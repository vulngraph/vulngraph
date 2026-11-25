package identity

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var censusNow = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func fresh() time.Time { return censusNow.Add(-2 * time.Hour) }
func stale() time.Time { return censusNow.Add(-60 * 24 * time.Hour) }

// principal builds one iam_user row the way the collector records it.
func principal(acct, name string, console bool) Principal {
	id := fmt.Sprintf("arn:aws:iam::%s:user/%s", acct, name)
	if name == "root" {
		id = fmt.Sprintf("arn:aws:iam::%s:root", acct)
	}
	return Principal{ID: id, Name: name, AccountID: acct, ConsoleAccess: console, ConsoleAccessKnown: true, LastSeen: fresh()}
}

func role(acct, name string, lastSeen time.Time) Role {
	return Role{
		ID:        fmt.Sprintf("arn:aws:iam::%s:role/%s", acct, name),
		Name:      name,
		AccountID: acct,
		LastSeen:  lastSeen,
	}
}

// This is the whole bug, reproduced at census scale: a population that the old
// "iam_user + human_identity" arithmetic would report as 8 humans is 3 people,
// 2 root principals and 3 programmatic credentials.
func TestBuildCensus_HumansDedupeAndExclude(t *testing.T) {
	in := censusInput{
		WorkloadRoleIDs: map[string]bool{},
		Principals: []Principal{
			// One human across four accounts, two spellings.
			principal("210000000001", "alex.example@example.com", true),
			principal("210000000004", "alex.example@example.com", true),
			principal("210000000023", "alex.example", true),
			principal("210000000024", "alex.example", true),
			// A second human, acquired-company domain.
			principal("444455556666", "sam.sample@example-corp.com", true),
			// A third human with no email at all.
			principal("123456789012", "Casey", true),
			// Root principals: privileged, not people.
			principal("123456789012", "root", true),
			principal("111122223333", "root", true),
			// Programmatic: no console access.
			principal("210000000002", "ci-runner", false),
			principal("444455556666", "bi-dashboard", false),
			principal("444455556666", "smtp-relay-user.20200101-000000", false),
			// The same CI credential replicated into a second account is one
			// service identity, not two.
			principal("210000000007", "ci-runner", false),
			// Login profile unreadable: neither a person nor key-only.
			principal("210000000008", "unread-user", false),
		},
	}
	// One programmatic row is flagged inactive by AWS.
	in.Principals[10].Inactive = true
	in.Principals[12].ConsoleAccessKnown = false

	c := buildCensus(in, censusNow)

	assert.Equal(t, 3, c.Humans.Distinct, "4+1+1 rows for 3 people")
	assert.Equal(t, 2, c.Humans.WithCorporateEmail)
	assert.Equal(t, 6, c.Humans.ConsolePrincipals, "the un-deduplicated rows stay visible")
	assert.Equal(t, 2, c.Humans.Excluded.RootPrincipals)
	assert.Equal(t, 4, c.Humans.Excluded.Programmatic)
	assert.Equal(t, 3, c.Humans.Excluded.ProgrammaticDistinct, "ci-runner in 2 accounts is 1 service identity")
	assert.Equal(t, 1, c.Humans.Excluded.ConsoleAccessUnknown)
	assert.Equal(t, 1, c.Humans.Excluded.InactivePrincipals)

	// The narrowing must reconcile: every raw row lands in exactly one class.
	assert.Equal(t,
		len(in.Principals),
		c.Humans.ConsolePrincipals+c.Humans.Excluded.RootPrincipals+c.Humans.Excluded.Programmatic+c.Humans.Excluded.ConsoleAccessUnknown,
		"root + programmatic + unknown + console must equal the raw iam_user count",
	)
}

// A federated human already holding IAM users must not be counted twice, and a
// federated human with no IAM user must not be missed — the exact failure that
// made the old tile exclude 100% of federated humans.
func TestBuildCensus_FederatedHumansUnionWithIAMUsers(t *testing.T) {
	in := censusInput{
		WorkloadRoleIDs: map[string]bool{},
		Principals: []Principal{
			principal("210000000001", "alex.example@example.com", true),
		},
		DirectoryIdentities: []directoryIdentity{
			// Same person, arriving from Identity Center.
			{ID: "sso_user:alex.example", Name: "alex.example", Provider: "aws", Email: "alex.example@example.com"},
			// Someone who only ever federates — invisible to the old tile.
			{ID: "sso_user:pat.sample", Name: "pat.sample", Provider: "aws", Email: "pat.sample@example.com"},
			// A directory identity from another source.
			{ID: "okta:jordan", Name: "jordan@example.com", Provider: "okta"},
		},
		SSOPermissionSets:   299,
		SSOGroups:           170,
		SSOGroupAssignments: 108,
	}

	c := buildCensus(in, censusNow)

	assert.Equal(t, 3, c.Humans.Distinct, "1 IAM/SSO overlap + 2 federated-only")
	assert.Equal(t, 3, c.Humans.Federation.DirectoryIdentities)
	assert.Equal(t, map[string]int{"aws": 2, "okta": 1}, c.Humans.Federation.DirectoryByProvider)
	assert.Equal(t, 299, c.Humans.Federation.SSOPermissionSets)
	assert.Equal(t, 170, c.Humans.Federation.SSOGroups)
	assert.Equal(t, 108, c.Humans.Federation.SSOGroupAssignments)
	assert.Zero(t, c.Humans.Federation.SSOUserAssignments,
		"an org that grants access only to groups has no user assignments to enumerate")
}

// Roles split by purpose, with the SSO roles landing on the human side and the
// stale account's roles flagged rather than silently counted as current.
func TestBuildCensus_RolesSplitByPurpose(t *testing.T) {
	lambdaRole := role("210000000021", "billing-webhook-prod", fresh())
	ecsRole := role("210000000021", "billing-task", stale())
	in := censusInput{
		WorkloadRoleIDs: map[string]bool{lambdaRole.ID: true, ecsRole.ID: true},
		Roles: []Role{
			lambdaRole,
			ecsRole,
			role("210000000021", "AWSReservedSSO_InfraEngineerAccess_c0ffee", fresh()),
			role("210000000021", "AWSReservedSSO_AdministratorAccess_dead", stale()),
			role("1", "cdk-hnb659fds-cfn-exec-role-1-eu-west-1", fresh()),
			{ID: "arn:aws:iam::1:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling", Name: "AWSServiceRoleForAutoScaling", AccountID: "1", LastSeen: fresh()},
			role("1", "legacy-migration-2019", stale()),
		},
	}

	c := buildCensus(in, censusNow)

	assert.Equal(t, 7, c.Roles.Total)
	assert.Equal(t, map[string]int{
		"workload":         2,
		"human_federation": 2,
		"platform":         2,
		"unattributed":     1,
	}, c.Roles.ByClass)
	assert.Equal(t, map[string]int{
		"workload":         1,
		"human_federation": 1,
		"unattributed":     1,
	}, c.Roles.StaleByClass, "platform roles here are all fresh")

	// The SSO roles are surfaced as human federation surface, not machine roles.
	assert.Equal(t, 2, c.Humans.Federation.SSOFederationRoles)

	// The classes partition the total — nothing is dropped or double-counted.
	sum := 0
	for _, n := range c.Roles.ByClass {
		sum += n
	}
	assert.Equal(t, c.Roles.Total, sum)
}

// The workload tile must span clouds, and the AWS side must come from the
// graph's workload evidence rather than from the whole role population.
func TestBuildCensus_WorkloadsAreCrossCloud(t *testing.T) {
	lambdaRole := role("210000000021", "billing-webhook-prod", fresh())
	in := censusInput{
		WorkloadRoleIDs: map[string]bool{lambdaRole.ID: true},
		Roles: []Role{
			lambdaRole,
			role("1", "legacy-migration-2019", fresh()),
		},
		NativeWorkloads: []nativeWorkloadGroup{
			{Provider: "gcp", Type: "gcp_service_account", Count: 2000},
			{Provider: "kubernetes", Type: "k8s_service_account", Count: 300},
			{Provider: "azure", Type: "azure_service_principal", Count: 20},
		},
		GCPDefaultServiceAccounts:   200,
		RolesReferencedNotCollected: 5,
		Principals: []Principal{
			principal("210000000002", "ci-runner", false),
		},
	}

	c := buildCensus(in, censusNow)

	assert.Equal(t, 2321, c.Workloads.Total, "1 AWS workload role + 2000 + 300 + 20")
	assert.Equal(t, map[string]int{"aws": 1, "gcp": 2000, "kubernetes": 300, "azure": 20}, c.Workloads.ByProvider)
	assert.Equal(t, map[string]int{
		"iam_role":                1,
		"gcp_service_account":     2000,
		"k8s_service_account":     300,
		"azure_service_principal": 20,
	}, c.Workloads.ByType)
	assert.Equal(t, 200, c.Workloads.GCPDefaultServiceAccounts, "Google-created defaults stay visible")
	assert.Equal(t, 5, c.Workloads.RolesReferencedNotCollected)

	// The narrowing rule: programmatic IAM users excluded from the human count
	// are workload identities and must be visible on this side.
	assert.Equal(t, 1, c.Workloads.ProgrammaticIAMUsers)

	byProvider, byType := 0, 0
	for _, n := range c.Workloads.ByProvider {
		byProvider += n
	}
	for _, n := range c.Workloads.ByType {
		byType += n
	}
	assert.Equal(t, c.Workloads.Total, byProvider)
	assert.Equal(t, c.Workloads.Total, byType)
}

// A long-stale account must be reported, ranked, and capped — the mechanism
// that stops a dead account inflating a "current" figure invisibly.
func TestBuildCensus_StalenessIsExposed(t *testing.T) {
	in := censusInput{
		WorkloadRoleIDs: map[string]bool{},
		Roles: []Role{
			role("210000000021", "a", stale()),
			role("210000000021", "b", stale()),
			role("999", "c", fresh()),
		},
		Principals:  []Principal{principal("999", "Casey", true)},
		StaleByType: map[string]int{"gcp_service_account": 0},
		TotalByType: map[string]int{"gcp_service_account": 2000},
		StaleAccounts: []StaleAccount{
			{AccountID: "small", Count: 3, LastSeen: stale(), AgeDays: 60},
			{AccountID: "210000000021", Count: 2500, LastSeen: stale(), AgeDays: 60},
		},
	}

	c := buildCensus(in, censusNow)

	assert.Equal(t, 30, c.Staleness.ThresholdDays)
	assert.Equal(t, 2, c.Staleness.StaleByType["iam_role"])
	assert.Equal(t, 3, c.Staleness.TotalByType["iam_role"])
	assert.Equal(t, 0, c.Staleness.StaleByType["iam_user"])
	assert.Equal(t, 1, c.Staleness.TotalByType["iam_user"])
	assert.Equal(t, 2000, c.Staleness.TotalByType["gcp_service_account"])
	require.Len(t, c.Staleness.StaleAccounts, 2)
	assert.Equal(t, "210000000021", c.Staleness.StaleAccounts[0].AccountID, "worst offender first")
	assert.Equal(t, 60, c.Staleness.StaleAccounts[0].AgeDays)
}

func TestBuildCensus_StaleAccountsCapped(t *testing.T) {
	in := censusInput{WorkloadRoleIDs: map[string]bool{}}
	for i := range maxStaleAccounts + 10 {
		in.StaleAccounts = append(in.StaleAccounts, StaleAccount{
			AccountID: fmt.Sprintf("acct-%02d", i), Count: i, LastSeen: stale(), AgeDays: 60,
		})
	}
	c := buildCensus(in, censusNow)
	assert.Len(t, c.Staleness.StaleAccounts, maxStaleAccounts)
	assert.Equal(t, maxStaleAccounts+9, c.Staleness.StaleAccounts[0].Count, "ranked by size")
}

// ── Service ──────────────────────────────────────────────────────────────────

type fakeRepo struct {
	in    censusInput
	err   error
	calls int
}

func (f *fakeRepo) censusInput(context.Context, time.Time) (censusInput, error) {
	f.calls++
	if f.err != nil {
		return censusInput{}, f.err
	}
	return f.in, nil
}

func TestService_CachesCensus(t *testing.T) {
	repo := &fakeRepo{in: censusInput{
		WorkloadRoleIDs: map[string]bool{},
		Principals:      []Principal{principal("1", "Casey", true)},
	}}
	svc := NewService(repo)
	now := censusNow
	svc.now = func() time.Time { return now }

	c, err := svc.Census(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, c.Humans.Distinct)
	assert.Equal(t, censusNow, c.GeneratedAt)

	_, err = svc.Census(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, repo.calls, "second call inside the TTL is served from cache")

	now = censusNow.Add(cacheTTL + time.Second)
	_, err = svc.Census(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, repo.calls, "the census is recomputed once the TTL lapses")
}

func TestService_PropagatesRepoError(t *testing.T) {
	svc := NewService(&fakeRepo{err: errors.New("clickhouse down")})
	_, err := svc.Census(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clickhouse down")
}
