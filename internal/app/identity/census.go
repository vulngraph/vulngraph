package identity

import (
	"sort"
	"strings"
	"time"
)

// Census is the identity surface's headline measure. Every headline number here
// is accompanied by the population it excludes and by its staleness, so no
// narrowing is silent and a long-stale account cannot inflate a figure the UI
// calls "current".
type Census struct {
	Humans    Humans    `json:"humans"`
	Workloads Workloads `json:"workloads"`
	Roles     Roles     `json:"roles"`
	Staleness Staleness `json:"staleness"`
	// GeneratedAt is when the census was computed, and the clock every staleness
	// comparison in it used.
	GeneratedAt time.Time `json:"generated_at"`
}

// Humans is the people census. Distinct is the honest headcount; every other
// field is either the raw population it was derived from or a population
// deliberately excluded from it.
type Humans struct {
	// Distinct is the number of PEOPLE: console-capable, non-root principals
	// deduplicated by NormalizeHuman across accounts and sources.
	Distinct int `json:"distinct"`
	// WithCorporateEmail is how many of Distinct were identified by an
	// email-shaped name — the subset we can tie to a directory account.
	WithCorporateEmail int `json:"with_corporate_email"`
	// ConsolePrincipals is the un-deduplicated row count behind Distinct: one
	// per (person, AWS account). The gap between the two is per-account
	// duplication, which must never be reported as headcount.
	ConsolePrincipals int `json:"console_principals"`
	// ByProvider splits Distinct by where the person was seen. Deduplication is
	// global, so a person present in both AWS IAM and a directory counts once in
	// Distinct and once under each provider here — the split shows coverage, and
	// its values therefore do not have to sum to Distinct.
	ByProvider map[string]int `json:"by_provider"`
	// Excluded is every principal population kept OUT of Distinct. Reported, not
	// dropped: on a security platform an excluded credential is still attack
	// surface.
	Excluded HumansExcluded `json:"excluded"`
	// Federation is the federated-access surface: SSO permission sets, the
	// groups holding them, and the directory identities collected.
	Federation Federation `json:"federation"`
}

// HumansExcluded accounts for every iam_user row that is not a person.
// RootPrincipals + Programmatic + ConsoleAccessUnknown + ConsolePrincipals
// equals the raw iam_user count, so the census reconciles against /api/assets/summary by construction.
type HumansExcluded struct {
	// RootPrincipals is the account root principals — one per AWS account, the
	// most privileged credential in it, and not a person.
	RootPrincipals int `json:"root_principals"`
	// Programmatic is IAM user rows with no console access: access-key-only
	// service accounts in the human namespace.
	Programmatic int `json:"programmatic"`
	// ProgrammaticDistinct deduplicates Programmatic the same way people are
	// deduplicated, so a CI user replicated across 20 accounts reads as one
	// service identity.
	ProgrammaticDistinct int `json:"programmatic_distinct"`
	// ConsoleAccessUnknown is IAM user rows whose console access was never
	// read: neither counted as people nor as key-only service accounts.
	ConsoleAccessUnknown int `json:"console_access_unknown"`
	// InactivePrincipals is rows AWS itself flags inactive (no credential use).
	// It overlaps the classes above rather than partitioning them.
	InactivePrincipals int `json:"inactive_principals"`
}

// Federation is the human federation surface. Zero DirectoryIdentities with
// nonzero SSOGroups means humans reach the cloud through a path the inventory
// cannot name — an understatement a bare "human identities" count has no way
// to express.
type Federation struct {
	// DirectoryIdentities is collected human_identity assets (Identity Center,
	// Okta, Google Workspace, GitHub members).
	DirectoryIdentities int `json:"directory_identities"`
	// DirectoryByProvider splits them by source directory.
	DirectoryByProvider map[string]int `json:"directory_by_provider"`
	// SSOPermissionSets is the Identity Center permission sets collected.
	SSOPermissionSets int `json:"sso_permission_sets"`
	// SSOGroups is the Identity Center groups collected.
	SSOGroups int `json:"sso_groups"`
	// SSOGroupAssignments / SSOUserAssignments are how permission sets are
	// actually granted. An org that assigns exclusively to groups has zero user
	// assignments, which is why enumerating assignments alone yields no people.
	SSOGroupAssignments int `json:"sso_group_assignments"`
	SSOUserAssignments  int `json:"sso_user_assignments"`
	// SSOFederationRoles is the AWSReservedSSO_* landing roles: the per-account
	// materialisation of those permission sets, counted here rather than in the
	// machine-role tile.
	SSOFederationRoles int `json:"sso_federation_roles"`
}

// Workloads is the cross-cloud non-human identity census, counted across every
// provider (not GCP alone).
type Workloads struct {
	// Total is distinct workload identities across every provider.
	Total int `json:"total"`
	// ByProvider and ByType decompose Total. Both sum to Total.
	ByProvider map[string]int `json:"by_provider"`
	ByType     map[string]int `json:"by_type"`
	// GCPDefaultServiceAccounts is the subset of gcp_service_account that Google
	// creates automatically in every project. Included in Total (they are real,
	// usable identities) but broken out, because nobody provisioned them.
	GCPDefaultServiceAccounts int `json:"gcp_default_service_accounts"`
	// ProgrammaticIAMUsers is the distinct access-key-only IAM users from
	// Humans.Excluded, surfaced here as well: excluded from the human headcount
	// but genuinely workload identities, so they are visible on this side rather
	// than lost between the two tiles.
	ProgrammaticIAMUsers int `json:"programmatic_iam_users"`
	// RolesReferencedNotCollected is roles a fresh executes_as/federated_access
	// edge points at that have no inventory row. Nonzero means a workload runs
	// as an identity in an account we are not collecting — a coverage hole, not
	// a rounding error.
	RolesReferencedNotCollected int `json:"roles_referenced_not_collected"`
}

// Roles is the AWS IAM role population split by what each role is FOR, so the
// tile does not imply a far larger number of machine identities.
type Roles struct {
	// Total is distinct iam_role assets.
	Total int `json:"total"`
	// ByClass partitions Total across RoleClass values (mutually exclusive,
	// exhaustive).
	ByClass map[string]int `json:"by_class"`
	// StaleByClass is the >30-day-stale subset of each class.
	StaleByClass map[string]int `json:"stale_by_class"`
}

// Staleness makes "current" falsifiable. Without it a single account that
// stopped being collected two months ago keeps contributing its whole role
// population to every headline.
type Staleness struct {
	// ThresholdDays is the age past which a row stops counting as evidence.
	ThresholdDays int `json:"threshold_days"`
	// StaleByType is stale rows per identity asset type.
	StaleByType map[string]int `json:"stale_by_type"`
	// TotalByType is all rows per identity asset type, so a ratio is derivable
	// without a second call.
	TotalByType map[string]int `json:"total_by_type"`
	// StaleAccounts are accounts whose NEWEST identity sighting is already past
	// the threshold — i.e. collection stopped, so every identity they contribute
	// is a historical claim.
	StaleAccounts []StaleAccount `json:"stale_accounts"`
}

// StaleAccount is one account that has stopped being collected.
type StaleAccount struct {
	AccountID string    `json:"account_id"`
	Provider  string    `json:"provider"`
	Count     int       `json:"count"`
	LastSeen  time.Time `json:"last_seen"`
	AgeDays   int       `json:"age_days"`
}

// maxStaleAccounts caps the stale-account list. It is a UI banner, not a
// report: the biggest offenders are what matter and an unbounded list would let
// one badly-collected org balloon the response.
const maxStaleAccounts = 20

// buildCensus is the whole measurement, expressed over already-fetched rows so
// it is testable without ClickHouse. now is the clock every staleness
// comparison uses, passed in rather than read, so a census is reproducible.
func buildCensus(in censusInput, now time.Time) Census {
	c := Census{GeneratedAt: now}

	// ── Humans ────────────────────────────────────────────────────────────────
	humanKeys := map[string]bool{}
	humanEmailKeys := map[string]bool{}
	progKeys := map[string]bool{}
	byProvider := map[string]int{}
	for _, p := range in.Principals {
		if p.Inactive {
			c.Humans.Excluded.InactivePrincipals++
		}
		switch ClassifyPrincipal(p) {
		case ClassRoot:
			c.Humans.Excluded.RootPrincipals++
		case ClassProgrammatic:
			c.Humans.Excluded.Programmatic++
			progKeys[NormalizeHuman(p.Name)] = true
		case ClassConsoleUnknown:
			c.Humans.Excluded.ConsoleAccessUnknown++
		case ClassHumanConsole:
			c.Humans.ConsolePrincipals++
			k := NormalizeHuman(p.Name)
			if !humanKeys[k] {
				byProvider["aws"]++
			}
			humanKeys[k] = true
			if isEmailShaped(p.Name) {
				humanEmailKeys[k] = true
			}
		}
	}
	// Directory identities are people too, and the same person may already be
	// present as an IAM console user — union on the same key rather than adding,
	// or every SSO user collected would double-count a human who also holds IAM
	// users.
	for _, d := range in.DirectoryIdentities {
		k := NormalizeHuman(firstNonEmpty(d.Email, d.Name))
		if k == "" {
			continue
		}
		byProvider[d.Provider]++
		humanKeys[k] = true
		if isEmailShaped(d.Email) || isEmailShaped(d.Name) {
			humanEmailKeys[k] = true
		}
	}
	c.Humans.Distinct = len(humanKeys)
	c.Humans.WithCorporateEmail = len(humanEmailKeys)
	c.Humans.ByProvider = byProvider
	c.Humans.Excluded.ProgrammaticDistinct = len(progKeys)

	// ── Roles ─────────────────────────────────────────────────────────────────
	byClass := map[string]int{}
	staleByClass := map[string]int{}
	for _, r := range in.Roles {
		cls := string(ClassifyRole(r, in.WorkloadRoleIDs[r.ID]))
		byClass[cls]++
		if IsStale(r.LastSeen, now) {
			staleByClass[cls]++
		}
	}
	c.Roles = Roles{Total: len(in.Roles), ByClass: byClass, StaleByClass: staleByClass}

	// ── Federation ────────────────────────────────────────────────────────────
	dirByProvider := map[string]int{}
	for _, d := range in.DirectoryIdentities {
		dirByProvider[d.Provider]++
	}
	c.Humans.Federation = Federation{
		DirectoryIdentities: len(in.DirectoryIdentities),
		DirectoryByProvider: dirByProvider,
		SSOPermissionSets:   in.SSOPermissionSets,
		SSOGroups:           in.SSOGroups,
		SSOGroupAssignments: in.SSOGroupAssignments,
		SSOUserAssignments:  in.SSOUserAssignments,
		SSOFederationRoles:  byClass[string(RoleHumanFederation)],
	}

	// ── Workloads ─────────────────────────────────────────────────────────────
	wlByType := map[string]int{"iam_role": byClass[string(RoleWorkload)]}
	wlByProvider := map[string]int{}
	if n := wlByType["iam_role"]; n > 0 {
		wlByProvider["aws"] = n
	}
	for _, g := range in.NativeWorkloads {
		wlByType[g.Type] += g.Count
		wlByProvider[g.Provider] += g.Count
	}
	total := 0
	for _, n := range wlByType {
		total += n
	}
	c.Workloads = Workloads{
		Total:                       total,
		ByProvider:                  wlByProvider,
		ByType:                      wlByType,
		GCPDefaultServiceAccounts:   in.GCPDefaultServiceAccounts,
		ProgrammaticIAMUsers:        c.Humans.Excluded.ProgrammaticDistinct,
		RolesReferencedNotCollected: in.RolesReferencedNotCollected,
	}

	// ── Staleness ─────────────────────────────────────────────────────────────
	staleByType := map[string]int{}
	totalByType := map[string]int{}
	for t, n := range in.StaleByType {
		staleByType[t] = n
	}
	for t, n := range in.TotalByType {
		totalByType[t] = n
	}
	// The role and principal rows are already in hand, so their staleness is
	// computed here against the same clock rather than trusting a second query.
	for _, r := range in.Roles {
		totalByType["iam_role"]++
		if IsStale(r.LastSeen, now) {
			staleByType["iam_role"]++
		}
	}
	for _, p := range in.Principals {
		totalByType["iam_user"]++
		if IsStale(p.LastSeen, now) {
			staleByType["iam_user"]++
		}
	}
	accounts := in.StaleAccounts
	sort.Slice(accounts, func(i, j int) bool {
		if accounts[i].Count != accounts[j].Count {
			return accounts[i].Count > accounts[j].Count
		}
		return accounts[i].AccountID < accounts[j].AccountID
	})
	if len(accounts) > maxStaleAccounts {
		accounts = accounts[:maxStaleAccounts]
	}
	c.Staleness = Staleness{
		ThresholdDays: int(StaleAfter / (24 * time.Hour)),
		StaleByType:   staleByType,
		TotalByType:   totalByType,
		StaleAccounts: accounts,
	}
	return c
}

// isEmailShaped reports whether a name is a usable email address (something
// before the @ and something after it) — the signal that a principal can be
// tied back to a directory account.
func isEmailShaped(s string) bool {
	at := strings.IndexByte(s, '@')
	return at > 0 && at < len(s)-1
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
