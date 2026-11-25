package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// Query strings are package consts named for what they fetch (CLAUDE.md).
//
// Every asset read uses FINAL rather than argMax GROUP BY: these are
// whole-table type scans, not id lookups, so no skip index applies and FINAL
// reads the already-merged data (the same reasoning as asset.assetSelect).
//
// The census classifies in Go rather than in SQL so the rules are table-tested
// against realistic principal shapes (see classify_test.go) instead of buried in a
// multiIf. The two row-level queries are bounded by the identity population
// (hundreds of IAM users, thousands of IAM roles), not by the far larger asset table.
const (
	// identityPrincipals reads every AWS IAM user row — one per (account, user),
	// which is exactly the duplication the census collapses. console_access and
	// inactive come from the collector's metadata JSON (metadata is a JSON
	// String column, so values are extracted, not indexed). The collector omits
	// console_access when it could not read the login profile, so the key's
	// presence is what makes its value an observation.
	identityPrincipals = `SELECT id, name, account_id,
		JSONExtractString(metadata, 'console_access') = 'true',
		JSONHas(metadata, 'console_access'),
		JSONExtractString(metadata, 'inactive') = 'true',
		last_seen
		FROM assets FINAL
		WHERE type = 'iam_user'`

	// identityRoles reads every AWS IAM role row. last_seen is what makes a
	// stale account's roles distinguishable from live ones.
	identityRoles = `SELECT id, name, account_id, last_seen
		FROM assets FINAL
		WHERE type = 'iam_role'`

	// identityDirectory reads collected human identities (Identity Center SSO
	// users, Okta, Google Workspace, GitHub members). domain carries the
	// resolved email for Identity Center users (see the AWS collector's
	// ssoGrantGraph), which is the key a person is deduplicated on.
	identityDirectory = `SELECT id, name, provider, domain
		FROM assets FINAL
		WHERE type = 'human_identity'`

	// identityNativeWorkloads counts the non-AWS workload identity types, with
	// their stale subset. These need no per-row classification — every row IS a
	// workload identity — so they are aggregated in ClickHouse rather than
	// shipped to Go. %d is the staleness threshold in days (never user input;
	// ClickHouse INTERVAL takes a literal, not a bind parameter).
	identityNativeWorkloads = `SELECT provider, type, count() AS n,
		countIf(last_seen < now() - INTERVAL %d DAY) AS stale
		FROM assets FINAL
		WHERE type IN ('gcp_service_account', 'k8s_service_account', 'azure_service_principal')
		GROUP BY provider, type`

	// identityGCPDefaults counts Google-created default service accounts by
	// their reserved email suffixes, filtered in ClickHouse rather than
	// fetching every service account name to filter in Go.
	identityGCPDefaults = `SELECT count()
		FROM assets FINAL
		WHERE type = 'gcp_service_account'
		  AND (name LIKE '%-compute@developer.gserviceaccount.com'
		    OR name LIKE '%@appspot.gserviceaccount.com'
		    OR name LIKE '%@cloudservices.gserviceaccount.com')`

	// identitySSOCounts counts Identity Center permission sets and groups, plus
	// how permission sets are actually granted. The assignee split is the
	// diagnostic for why an org with hundreds of permission sets can still yield zero
	// collected people: assignments made exclusively to groups produce no user
	// principals to enumerate.
	identitySSOCounts = `SELECT
		countIf(type = 'sso_permission_set') AS permission_sets,
		countIf(type = 'sso_group') AS groups,
		sum(countSubstrings(JSONExtractString(metadata, 'assignees'), 'group:')) AS group_assignments,
		sum(countSubstrings(JSONExtractString(metadata, 'assignees'), 'user:')) AS user_assignments
		FROM assets FINAL
		WHERE type IN ('sso_permission_set', 'sso_group')`

	// identityWorkloadRoles is the graph's own evidence of which IAM roles a
	// workload runs as: executes_as (Lambda / ECS task / Azure webapp) and
	// federated_access (IRSA service accounts, CI repos via OIDC).
	//
	// EdgeFreshnessCond is not optional here. Edges are never deleted, only left
	// un-restamped until TTL, so without it a deleted Lambda's role stays
	// "assumed by a workload" indefinitely, overstating how many roles still have a live workload.
	identityWorkloadRoles = `SELECT DISTINCT dst_id
		FROM graph_edges
		WHERE edge_type IN ('executes_as', 'federated_access')
		  AND dst_type = 'iam_role'
		  AND ` + graphschema.EdgeFreshnessCond

	// identityStaleAccounts finds accounts whose NEWEST identity sighting is
	// already past the staleness threshold: collection stopped, so every
	// identity they contribute is a historical claim rather than a current one.
	// The threshold is interpolated as a bare integer (never user input) because
	// ClickHouse's INTERVAL takes a literal, not a bind parameter.
	identityStaleAccounts = `SELECT account_id, any(provider), count(), max(last_seen)
		FROM assets FINAL
		WHERE type IN ('iam_user', 'iam_role', 'gcp_service_account',
		               'k8s_service_account', 'azure_service_principal', 'human_identity')
		  AND account_id != ''
		GROUP BY account_id
		HAVING max(last_seen) < now() - INTERVAL %d DAY`

	// identityRolesReferencedNotCollected counts roles a live workload edge
	// points at that have no inventory row: a workload running as an identity in
	// an account we are not collecting. A coverage hole, reported rather than
	// rounded away.
	identityRolesReferencedNotCollected = `SELECT count()
		FROM (
			SELECT DISTINCT dst_id
			FROM graph_edges
			WHERE edge_type IN ('executes_as', 'federated_access')
			  AND dst_type = 'iam_role'
			  AND ` + graphschema.EdgeFreshnessCond + `
		)
		WHERE dst_id NOT IN (SELECT id FROM assets FINAL WHERE type = 'iam_role')`
)

// censusQueryTimeout bounds the whole census. It is generous because the role
// scan is the slowest read (thousands of rows out of a FINAL type filter) and a
// half-computed census is useless — better a clean 500 than a partial number a
// security dashboard presents as fact.
const censusQueryTimeout = 30 * time.Second

// directoryIdentity is one collected human from a directory source.
type directoryIdentity struct {
	ID       string
	Name     string
	Provider string
	Email    string
}

// nativeWorkloadGroup is one (provider, type) count of a workload identity type
// that needs no classification.
type nativeWorkloadGroup struct {
	Provider string
	Type     string
	Count    int
}

// censusInput is everything buildCensus needs. Keeping it a plain struct is
// what lets the measurement be tested without ClickHouse.
type censusInput struct {
	Principals          []Principal
	Roles               []Role
	DirectoryIdentities []directoryIdentity
	NativeWorkloads     []nativeWorkloadGroup
	// WorkloadRoleIDs is the set of IAM role ids a live workload edge points at.
	WorkloadRoleIDs             map[string]bool
	GCPDefaultServiceAccounts   int
	SSOPermissionSets           int
	SSOGroups                   int
	SSOGroupAssignments         int
	SSOUserAssignments          int
	RolesReferencedNotCollected int
	StaleAccounts               []StaleAccount
	// StaleByType / TotalByType carry staleness for types buildCensus does not
	// hold rows for (GCP/K8s/Azure workload identities, directory identities).
	StaleByType map[string]int
	TotalByType map[string]int
}

// Repo loads the raw rows a census is computed from.
type Repo interface {
	censusInput(ctx context.Context, now time.Time) (censusInput, error)
}

// CHRepo reads the census from ClickHouse.
type CHRepo struct {
	ch *db.CH
}

func NewCHRepo(ch *db.CH) *CHRepo { return &CHRepo{ch: ch} }

// censusInput runs the census reads. They run sequentially rather than
// concurrently on purpose: db.CH holds a bounded query semaphore, so fanning
// eight FINAL scans at it would just queue behind itself while starving every
// other request.
func (r *CHRepo) censusInput(ctx context.Context, now time.Time) (censusInput, error) {
	qCtx, cancel := context.WithTimeout(ctx, censusQueryTimeout)
	defer cancel()

	in := censusInput{
		WorkloadRoleIDs: map[string]bool{},
		StaleByType:     map[string]int{},
		TotalByType:     map[string]int{},
	}

	if err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var p Principal
			if err := rows.Scan(&p.ID, &p.Name, &p.AccountID, &p.ConsoleAccess, &p.ConsoleAccessKnown, &p.Inactive, &p.LastSeen); err != nil {
				return fmt.Errorf("scan principal: %w", err)
			}
			in.Principals = append(in.Principals, p)
		}
		return nil
	}, identityPrincipals); err != nil {
		return censusInput{}, fmt.Errorf("censusInput: principals: %w", err)
	}

	if err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var role Role
			if err := rows.Scan(&role.ID, &role.Name, &role.AccountID, &role.LastSeen); err != nil {
				return fmt.Errorf("scan role: %w", err)
			}
			in.Roles = append(in.Roles, role)
		}
		return nil
	}, identityRoles); err != nil {
		return censusInput{}, fmt.Errorf("censusInput: roles: %w", err)
	}

	if err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var d directoryIdentity
			if err := rows.Scan(&d.ID, &d.Name, &d.Provider, &d.Email); err != nil {
				return fmt.Errorf("scan directory identity: %w", err)
			}
			in.DirectoryIdentities = append(in.DirectoryIdentities, d)
		}
		return nil
	}, identityDirectory); err != nil {
		return censusInput{}, fmt.Errorf("censusInput: directory: %w", err)
	}

	staleDays := int(StaleAfter / (24 * time.Hour))
	if err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				g         nativeWorkloadGroup
				n, staleN uint64
			)
			if err := rows.Scan(&g.Provider, &g.Type, &n, &staleN); err != nil {
				return fmt.Errorf("scan native workload: %w", err)
			}
			g.Count = int(n)
			in.NativeWorkloads = append(in.NativeWorkloads, g)
			in.TotalByType[g.Type] += g.Count
			in.StaleByType[g.Type] += int(staleN)
		}
		return nil
	}, fmt.Sprintf(identityNativeWorkloads, staleDays)); err != nil {
		return censusInput{}, fmt.Errorf("censusInput: native workloads: %w", err)
	}

	if err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var dst string
			if err := rows.Scan(&dst); err != nil {
				return fmt.Errorf("scan workload role: %w", err)
			}
			in.WorkloadRoleIDs[dst] = true
		}
		return nil
	}, identityWorkloadRoles); err != nil {
		return censusInput{}, fmt.Errorf("censusInput: workload roles: %w", err)
	}

	if err := r.scanCount(qCtx, identityGCPDefaults, &in.GCPDefaultServiceAccounts); err != nil {
		return censusInput{}, fmt.Errorf("censusInput: gcp defaults: %w", err)
	}
	if err := r.scanCount(qCtx, identityRolesReferencedNotCollected, &in.RolesReferencedNotCollected); err != nil {
		return censusInput{}, fmt.Errorf("censusInput: uncollected roles: %w", err)
	}

	if err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var ps, groups, groupAsg, userAsg uint64
			if err := rows.Scan(&ps, &groups, &groupAsg, &userAsg); err != nil {
				return fmt.Errorf("scan sso counts: %w", err)
			}
			in.SSOPermissionSets = int(ps)
			in.SSOGroups = int(groups)
			in.SSOGroupAssignments = int(groupAsg)
			in.SSOUserAssignments = int(userAsg)
		}
		return nil
	}, identitySSOCounts); err != nil {
		return censusInput{}, fmt.Errorf("censusInput: sso counts: %w", err)
	}

	if err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				sa       StaleAccount
				n        uint64
				lastSeen time.Time
			)
			if err := rows.Scan(&sa.AccountID, &sa.Provider, &n, &lastSeen); err != nil {
				return fmt.Errorf("scan stale account: %w", err)
			}
			sa.Count = int(n)
			sa.LastSeen = lastSeen
			sa.AgeDays = int(now.Sub(lastSeen).Hours() / 24)
			in.StaleAccounts = append(in.StaleAccounts, sa)
		}
		return nil
	}, fmt.Sprintf(identityStaleAccounts, staleDays)); err != nil {
		return censusInput{}, fmt.Errorf("censusInput: stale accounts: %w", err)
	}

	return in, nil
}

func (r *CHRepo) scanCount(ctx context.Context, query string, dst *int) error {
	return r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var n uint64
			if err := rows.Scan(&n); err != nil {
				return fmt.Errorf("scan count: %w", err)
			}
			*dst = int(n)
		}
		return nil
	}, query)
}
