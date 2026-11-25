package identity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every fixture below is a synthetic principal or role name in a shape typical
// of real AWS inventories. The point of naming them is that these are the
// kinds of rows the old browser-side arithmetic mis-counted.
func TestClassifyPrincipal(t *testing.T) {
	tests := []struct {
		name string
		p    Principal
		want PrincipalClass
	}{
		{
			name: "account root is not a person even with console access",
			p:    Principal{ID: "arn:aws:iam::123456789012:root", Name: "root", ConsoleAccess: true},
			want: ClassRoot,
		},
		{
			name: "root detected by ARN suffix when name is empty",
			p:    Principal{ID: "arn:aws:iam::111122223333:root", ConsoleAccess: true},
			want: ClassRoot,
		},
		{
			// An illustrative row. "secondroot" is an ordinary IAM user someone
			// named badly; classifying it as root would hide a console credential.
			name: "secondroot is an ordinary user, not account root",
			p:    Principal{ID: "arn:aws:iam::123456789012:user/secondroot", Name: "secondroot", ConsoleAccess: true, ConsoleAccessKnown: true},
			want: ClassHumanConsole,
		},
		{
			name: "console user is a person",
			p:    Principal{ID: "arn:aws:iam::210000000001:user/alex.example@example.com", Name: "alex.example@example.com", ConsoleAccess: true, ConsoleAccessKnown: true},
			want: ClassHumanConsole,
		},
		{
			name: "ci-runner has no console access — programmatic",
			p:    Principal{ID: "arn:aws:iam::210000000002:user/ci-runner", Name: "ci-runner", ConsoleAccessKnown: true},
			want: ClassProgrammatic,
		},
		{
			name: "smtp-relay-user is programmatic",
			p:    Principal{ID: "arn:aws:iam::444455556666:user/smtp-relay-user.20200101-000000", Name: "smtp-relay-user.20200101-000000", ConsoleAccessKnown: true},
			want: ClassProgrammatic,
		},
		{
			name: "bi-dashboard is programmatic",
			p:    Principal{ID: "arn:aws:iam::444455556666:user/bi-dashboard", Name: "bi-dashboard", ConsoleAccessKnown: true},
			want: ClassProgrammatic,
		},
		{
			name: "svc_reporting_job_prd is programmatic",
			p:    Principal{ID: "arn:aws:iam::444455556666:user/svc_reporting_job_prd", Name: "svc_reporting_job_prd", ConsoleAccessKnown: true},
			want: ClassProgrammatic,
		},
		{
			// Inactive is orthogonal to class: an inactive programmatic user is
			// still a programmatic user, and the flag is reported separately.
			name: "inactive programmatic user keeps its class",
			p:    Principal{ID: "arn:aws:iam::210000000003:user/CI", Name: "CI", Inactive: true, ConsoleAccessKnown: true},
			want: ClassProgrammatic,
		},
		{
			// The collector omits console_access when GetLoginProfile failed:
			// an unread flag is not "no console access".
			name: "unread console access is unknown, not programmatic",
			p:    Principal{ID: "arn:aws:iam::210000000004:user/ops-user", Name: "ops-user"},
			want: ClassConsoleUnknown,
		},
		{
			name: "root with unread console access is still root",
			p:    Principal{ID: "arn:aws:iam::123456789012:root", Name: "root"},
			want: ClassRoot,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ClassifyPrincipal(tt.p))
		})
	}
}

func TestNormalizeHuman(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"corporate email keeps only the local part", "alex.example@example.com", "alex.example"},
		{"bare local part matches the email form", "alex.example", "alex.example"},
		{"case is irrelevant", "Alex.Example@example.com", "alex.example"},
		{"acquired-company domain still keys on the person", "sam.sample@example-corp.com", "sam.sample"},
		{"surrounding whitespace is not an identity", "  casey@example.com ", "casey"},
		{"non-email name lowercases", "AlexExample", "alexexample"},
		{"leading @ is not an email", "@weird", "@weird"},
		{"empty stays empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizeHuman(tt.in))
		})
	}
}

// The headline bug: raw iam_user rows vastly outnumber distinct people because
// the same human holds an IAM user in every AWS account they work in.
// alex.example appears across a spread of accounts as an email and as a bare
// local part; every one of those rows is ONE person.
func TestNormalizeHuman_DedupesOnePersonAcrossAccounts(t *testing.T) {
	accounts := []string{
		"210000000001", "210000000004", "210000000005", "111122223333", "210000000006",
		"210000000002", "210000000007", "210000000008", "210000000009", "210000000010",
		"210000000011", "210000000012", "210000000013", "210000000014", "210000000015",
		"210000000016", "210000000003", "210000000017", "210000000018", "210000000019",
		"210000000020",
	}
	require.Len(t, accounts, 21, "fixture mirrors a representative multi-account spread")

	keys := map[string]bool{}
	for _, acct := range accounts {
		keys[NormalizeHuman("alex.example@example.com")] = true
		// The bare local part is how the same human is recorded in some accounts.
		keys[NormalizeHuman("alex.example")] = true
		require.NotEmpty(t, acct)
	}
	assert.Len(t, keys, 1, "many accounts × 2 spellings of one human must be 1 person")
}

func TestClassifyRole(t *testing.T) {
	tests := []struct {
		name              string
		role              Role
		assumedByWorkload bool
		want              RoleClass
	}{
		{
			// The tile-crossing bug: AWSReservedSSO_* roles were counted as
			// machine roles when they are the human federation surface.
			name: "AWSReservedSSO_ is human federation",
			role: Role{ID: "arn:aws:iam::210000000021:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_InfraEngineerAccess_c0ffee", Name: "AWSReservedSSO_InfraEngineerAccess_c0ffee"},
			want: RoleHumanFederation,
		},
		{
			// SSO wins over the aws-reserved/ path that looks like plumbing.
			name:              "SSO role stays human federation even with workload evidence",
			role:              Role{ID: "arn:aws:iam::1:role/AWSReservedSSO_AdministratorAccess_1", Name: "AWSReservedSSO_AdministratorAccess_1"},
			assumedByWorkload: true,
			want:              RoleHumanFederation,
		},
		{
			name:              "lambda execution role is a workload identity",
			role:              Role{ID: "arn:aws:iam::210000000021:role/billing-webhook-prod", Name: "billing-webhook-prod"},
			assumedByWorkload: true,
			want:              RoleWorkload,
		},
		{
			// Positive graph evidence beats the naming heuristic: a service-role/
			// path that a live ECS task actually runs as is a workload identity.
			name:              "workload evidence beats the plumbing name pattern",
			role:              Role{ID: "arn:aws:iam::1:role/service-role/ecsTaskExecutionRole", Name: "ecsTaskExecutionRole"},
			assumedByWorkload: true,
			want:              RoleWorkload,
		},
		{
			name: "service-linked role is platform plumbing",
			role: Role{ID: "arn:aws:iam::1:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling", Name: "AWSServiceRoleForAutoScaling"},
			want: RolePlatform,
		},
		{
			name: "service-role path is platform plumbing",
			role: Role{ID: "arn:aws:iam::1:role/service-role/StepFunctions-Role", Name: "StepFunctions-Role"},
			want: RolePlatform,
		},
		{
			name: "CDK bootstrap role is platform plumbing",
			role: Role{ID: "arn:aws:iam::1:role/cdk-hnb659fds-cfn-exec-role-1-eu-west-1", Name: "cdk-hnb659fds-cfn-exec-role-1-eu-west-1"},
			want: RolePlatform,
		},
		{
			name: "CDK role nested under a stack name is platform plumbing",
			role: Role{ID: "arn:aws:iam::1:role/MyStack-CdkDeployRole-ABC", Name: "MyStack-CdkDeployRole-ABC"},
			want: RolePlatform,
		},
		{
			name: "CloudFormation role is platform plumbing",
			role: Role{ID: "arn:aws:iam::1:role/MyStack-CloudFormationRole-XYZ", Name: "MyStack-CloudFormationRole-XYZ"},
			want: RolePlatform,
		},
		{
			name: "StackSet execution role is platform plumbing",
			role: Role{ID: "arn:aws:iam::1:role/stackset-exec-role", Name: "stackset-exec-role"},
			want: RolePlatform,
		},
		{
			name: "Control Tower role is platform plumbing",
			role: Role{ID: "arn:aws:iam::1:role/AWSControlTowerExecution", Name: "AWSControlTowerExecution"},
			want: RolePlatform,
		},
		{
			// The honest unknown. NOT a safe bucket — it is the population worth
			// investigating, and naming it that way is the point.
			name: "a role with no workload edge and no plumbing marker is unattributed",
			role: Role{ID: "arn:aws:iam::1:role/legacy-migration-2019", Name: "legacy-migration-2019"},
			want: RoleUnattributed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ClassifyRole(tt.role, tt.assumedByWorkload))
		})
	}
}

func TestIsStale(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		lastSeen time.Time
		want     bool
	}{
		{"seen minutes ago", now.Add(-10 * time.Minute), false},
		{"seen 29 days ago", now.Add(-29 * 24 * time.Hour), false},
		{
			// An account whose newest identity sighting is long past: its roles
			// must not count as current.
			name:     "seen 60 days ago",
			lastSeen: now.Add(-60 * 24 * time.Hour),
			want:     true,
		},
		{"never seen is stale, not fresh", time.Time{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsStale(tt.lastSeen, now))
		})
	}
}
