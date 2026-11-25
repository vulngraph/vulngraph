// Package identity computes the identity census the Identity surface shows:
// how many PEOPLE exist (not per-account principal rows), how many workload
// identities exist across clouds (not just GCP service accounts), and what an
// IAM role population is actually made of.
//
// The classification and dedup rules live here as pure functions, separate
// from the SQL that feeds them (repo.go) and the census assembly (service.go).
//
// Narrowing rule (security platform): every population this file EXCLUDES from
// a headline stays counted in an explicit sibling field — "Humans" excludes
// root and programmatic principals, so RootPrincipals and Programmatic are
// reported next to it. Under-counting identities hides attack surface;
// silently dropping a population is worse than a wrong label.
package identity

import (
	"strings"
	"time"
)

// PrincipalClass is what an AWS IAM user row actually is. The classes are
// mutually exclusive and cover every row, so the counts always reconcile to the
// raw iam_user total.
type PrincipalClass string

const (
	// ClassRoot is an account root principal (arn:aws:iam::<acct>:root). One per
	// AWS account, not a person, and never a member of the human headcount.
	ClassRoot PrincipalClass = "root"

	// ClassHumanConsole is an IAM user with console (password) access — the only
	// class that plausibly represents a person logging in.
	ClassHumanConsole PrincipalClass = "human_console"

	// ClassProgrammatic is an IAM user with no console access: an access-key-only
	// service account living in the IAM user namespace (a CI system, an SMTP
	// relay user, a BI tool's service account). It is a workload
	// credential wearing a human's clothes, so it is excluded from the human
	// headcount and reported as its own population.
	ClassProgrammatic PrincipalClass = "programmatic"

	// ClassConsoleUnknown is an IAM user whose console access was never read
	// (the login-profile lookup failed). It may be a person or a key-only
	// service account; calling it either would be a guess.
	ClassConsoleUnknown PrincipalClass = "console_access_unknown"
)

// Principal is one AWS IAM user row as stored in the asset inventory: one row
// per (account, user), which is exactly why row counts overstate headcount.
type Principal struct {
	ID            string
	Name          string
	AccountID     string
	ConsoleAccess bool
	// ConsoleAccessKnown is false when the collector could not read the
	// login profile; ConsoleAccess is then not an observation.
	ConsoleAccessKnown bool
	Inactive           bool
	LastSeen           time.Time
}

// ClassifyPrincipal sorts one IAM user row into its class. Root is checked
// first because a root principal can carry console access and would otherwise
// be counted as a person.
func ClassifyPrincipal(p Principal) PrincipalClass {
	if IsRootPrincipal(p.ID, p.Name) {
		return ClassRoot
	}
	if !p.ConsoleAccessKnown {
		return ClassConsoleUnknown
	}
	if p.ConsoleAccess {
		return ClassHumanConsole
	}
	return ClassProgrammatic
}

// IsRootPrincipal reports whether a principal is an account root. The ARN is
// authoritative (":root" suffix, no "user/" segment); the name is a fallback
// for rows whose id was recorded without the ARN. Deliberately does NOT match
// substrings — "secondroot" is an ordinary IAM user someone named badly, not
// account root, and treating it as root would hide a real credential.
func IsRootPrincipal(id, name string) bool {
	return strings.HasSuffix(id, ":root") || name == "root"
}

// NormalizeHuman is the dedup key that turns per-account principal rows into
// people: the lowercased local part of an email-shaped name, else the
// lowercased name.
//
// It deliberately stops there. Stripping separators too would also collapse
// distinct people whose names differ only by punctuation — on a security
// platform an over-merge silently deletes an identity from the census, so the
// conservative key is the right trade: residual duplicates inflate the count
// rather than hiding an account, and the un-deduped principal count is
// reported alongside it either way.
func NormalizeHuman(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if at := strings.Index(n, "@"); at > 0 {
		return n[:at]
	}
	return n
}

// RoleClass is what an AWS IAM role is FOR: the human federation surface,
// something a workload runs as, AWS/IaC plumbing, or unattributed.
type RoleClass string

const (
	// RoleHumanFederation is an AWSReservedSSO_* role: the landing role an
	// Identity Center permission set materialises in each account. These are how
	// humans actually get into AWS, so they are counted as human federation
	// surface, not as machine roles.
	RoleHumanFederation RoleClass = "human_federation"

	// RoleWorkload is a role the graph proves a workload runs as — an
	// executes_as or federated_access edge from a Lambda, ECS service, IRSA
	// service account, or CI repo.
	RoleWorkload RoleClass = "workload"

	// RolePlatform is AWS/IaC plumbing: service-linked roles, service-role/
	// roles, CDK bootstrap roles, CloudFormation/StackSet/Control Tower roles.
	// Real, but nobody's identity.
	RolePlatform RoleClass = "platform"

	// RoleUnattributed is everything else: a role with no workload edge and no
	// plumbing marker. This is NOT a "safe" bucket — it is the honest name for
	// "we do not know who assumes this", which on a security platform is the
	// bucket worth looking at.
	RoleUnattributed RoleClass = "unattributed"
)

// Role is one AWS IAM role row from the asset inventory.
type Role struct {
	ID        string
	Name      string
	AccountID string
	LastSeen  time.Time
}

// ClassifyRole sorts one role. assumedByWorkload comes from the graph
// (executes_as / federated_access edges), so the caller supplies it.
//
// Order is load-bearing: SSO first (an AWSReservedSSO_* role can also carry a
// service-role-looking path), then workload evidence (positive proof beats a
// naming heuristic), then plumbing patterns, then the honest unknown.
func ClassifyRole(r Role, assumedByWorkload bool) RoleClass {
	switch {
	case IsSSORole(r.Name):
		return RoleHumanFederation
	case assumedByWorkload:
		return RoleWorkload
	case IsPlatformRole(r.ID, r.Name):
		return RolePlatform
	default:
		return RoleUnattributed
	}
}

// IsSSORole reports whether a role name is an IAM Identity Center landing role.
// AWS reserves the AWSReservedSSO_ prefix, so the prefix is exact, not a
// substring match.
func IsSSORole(name string) bool {
	return strings.HasPrefix(name, "AWSReservedSSO_")
}

// platformNamePrefixes are IaC/AWS-managed role name prefixes. Matched
// case-insensitively on the name.
var platformNamePrefixes = []string{
	"stackset-",       // CloudFormation StackSet execution roles
	"stacksets-exec-", // StackSet admin/exec pair
	"awscontroltower", // Control Tower
}

// platformNameSubstrings are markers that appear anywhere in the name rather
// than as a prefix: CDK names both the bootstrap roles (cdk-hnb659fds-…) and
// per-stack roles (MyStack-cdkDeployRole-…), and CloudFormation-generated roles
// carry the service name mid-name.
var platformNameSubstrings = []string{
	"cdk",
	"cloudformation",
}

// platformPathSegments are ARN path segments AWS itself owns. A role under
// aws-service-role/ is a service-linked role that only its AWS service can
// assume; service-role/ is the console-created service role path.
var platformPathSegments = []string{
	":role/aws-service-role/",
	":role/service-role/",
}

// IsPlatformRole reports whether a role is AWS or IaC plumbing rather than
// anyone's identity. Checked on the ARN path first (authoritative) then on the
// name (heuristic).
func IsPlatformRole(id, name string) bool {
	for _, seg := range platformPathSegments {
		if strings.Contains(id, seg) {
			return true
		}
	}
	lower := strings.ToLower(name)
	for _, p := range platformNamePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	for _, s := range platformNameSubstrings {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// StaleAfter is the age at which an identity's inventory row stops being
// evidence of a CURRENT identity. It matches the collection-staleness threshold
// used elsewhere: a role last seen two months ago may have been deleted the day
// after, and counting it as live inflates every tile it lands in.
const StaleAfter = 30 * 24 * time.Hour

// IsStale reports whether a last_seen timestamp is older than StaleAfter
// relative to now. A zero last_seen is stale: an identity we have no sighting
// for is not evidence of a current identity.
func IsStale(lastSeen, now time.Time) bool {
	return lastSeen.IsZero() || now.Sub(lastSeen) > StaleAfter
}
