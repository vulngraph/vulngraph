package correlate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestDangerousActionsKeysAreLowercase locks the invariant that every key in the
// map is lowercase. dangerousActionsInPolicy lowercases each policy action before
// the lookup, so any key with an uppercase letter is dead — it can never match,
// silently blinding the correlator to that dangerous permission.
func TestDangerousActionsKeysAreLowercase(t *testing.T) {
	for k := range dangerousActions {
		require.Equalf(t, strings.ToLower(k), k,
			"dangerousActions key %q must be lowercase or it can never match", k)
	}
}

// TestDangerousActionsDetected spot-checks the two AWS actions whose keys were
// previously miscased (ec2:AuthorizeSecurityGroupIngress, rds:RestoreDBInstanceToPointInTime).
func TestDangerousActionsDetected(t *testing.T) {
	for _, action := range []string{
		"ec2:AuthorizeSecurityGroupIngress",
		"rds:RestoreDBInstanceToPointInTime",
		"sts:AssumeRoleWithWebIdentity",
	} {
		_, ok := dangerousActions[strings.ToLower(action)]
		require.Truef(t, ok, "expected %q to be a recognised dangerous action", action)
	}
}

// Deny-all detection is now handled by ciem.EffectivePermissionsForPolicies —
// see internal/awspolicy/denyall_test.go for the underlying parsing tests and
// TestIamPermissionEdges_* below for the end-to-end correlator behavior.

// TestIamPermissionEdges_DenyAllNeutralizesAdminWildcard is the exact reported
// bug's shape: a principal with an AdministratorAccess-equivalent Allow and a
// separate, sibling deny-all policy must not produce an admin-wildcard
// allows_action edge — a real AWS explicit deny wins globally, regardless of
// which attached policy document declares the Allow vs. the Deny.
func TestIamPermissionEdges_DenyAllNeutralizesAdminWildcard(t *testing.T) {
	policiesJSON := `[
		{"name":"AdministratorAccess","type":"identity","managed":true,"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"},
		{"name":"deny-all","type":"identity","managed":false,"document":"{\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}
	]`
	role := asset.Asset{
		ID:       "arn:aws:iam::111122223333:user/locked-down",
		Type:     "iam_user",
		Metadata: map[string]string{"policies": policiesJSON},
	}
	edges := iamPermissionEdges(role, nil)
	require.Empty(t, edges, "a principal with an explicit deny-all must produce zero allows_action edges, even alongside an admin-looking grant")
}

// TestIamPermissionEdges_ScopedDenyStillProducesAdminEdge guards against an
// overcorrection: a Deny that isn't truly global must not suppress a real
// admin-wildcard edge.
func TestIamPermissionEdges_ScopedDenyStillProducesAdminEdge(t *testing.T) {
	policiesJSON := `[
		{"name":"AdministratorAccess","type":"identity","managed":true,"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"},
		{"name":"deny-s3-only","type":"identity","managed":false,"document":"{\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"}
	]`
	role := asset.Asset{
		ID:       "arn:aws:iam::111122223333:user/still-admin",
		Type:     "iam_user",
		Metadata: map[string]string{"policies": policiesJSON},
	}
	edges := iamPermissionEdges(role, nil)
	require.NotEmpty(t, edges, "a scoped deny must not suppress a real admin-wildcard grant")
}

// TestIamPermissionEdges_ConditionalDenyStillProducesAdminEdge guards against
// treating a Condition-gated deny-all (e.g. "deny everything unless MFA
// present") as an unconditional one — it only blocks in the unmet-condition
// case, so it must not suppress the admin-wildcard edge.
func TestIamPermissionEdges_ConditionalDenyStillProducesAdminEdge(t *testing.T) {
	policiesJSON := `[
		{"name":"AdministratorAccess","type":"identity","managed":true,"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"},
		{"name":"deny-without-mfa","type":"identity","managed":false,"document":"{\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"BoolIfExists\":{\"aws:MultiFactorAuthPresent\":\"false\"}}}]}"}
	]`
	role := asset.Asset{
		ID:       "arn:aws:iam::111122223333:role/mfa-gated-admin",
		Type:     "iam_role",
		Metadata: map[string]string{"policies": policiesJSON},
	}
	edges := iamPermissionEdges(role, nil)
	require.NotEmpty(t, edges, "a conditional (MFA-gated) deny-all must not suppress a real admin-wildcard grant")
}

// TestIamPermissionEdges_BoundaryAllowAloneProducesNoEdge guards against
// treating a permission boundary's Allow statement as a real grant — a
// boundary only caps an identity policy's grant, it never creates one on its
// own. A common real pattern is a broad boundary Allow paired with narrowly
// scoped identity policies; scanning the boundary the same as an identity
// policy would falsely report the role as having a dangerous permission it
// was never actually granted.
func TestIamPermissionEdges_BoundaryAllowAloneProducesNoEdge(t *testing.T) {
	// s3:ListBucket is deliberately not in dangerousActions, so the identity
	// policy alone contributes zero edges — the only thing that could produce
	// an "admin-wildcard" edge here is the boundary's Action:"*", which must be
	// excluded.
	policiesJSON := `[
		{"name":"scoped-identity","type":"identity","managed":false,"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListBucket\",\"Resource\":\"*\"}]}"},
		{"name":"broad-boundary","type":"boundary","managed":false,"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}
	]`
	role := asset.Asset{
		ID:       "arn:aws:iam::111122223333:role/scoped-with-broad-boundary",
		Type:     "iam_role",
		Metadata: map[string]string{"policies": policiesJSON},
	}
	edges := iamPermissionEdges(role, nil)
	require.Empty(t, edges, "a permissive boundary alone must not be read as a dangerous-action grant — only identity policies grant")
}

// TestIamPermissionEdges_TrustPolicyDenyAllIgnored guards against a deny-all
// statement in the trust (assume-role) policy suppressing an unrelated
// identity-policy admin grant — trust governs who may assume the role, not
// what the assumed principal may do.
func TestIamPermissionEdges_TrustPolicyDenyAllIgnored(t *testing.T) {
	policiesJSON := `[
		{"name":"AdministratorAccess","type":"identity","managed":true,"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"},
		{"name":"role-trust","type":"trust","managed":false,"document":"{\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",\"Principal\":\"*\"}]}"}
	]`
	role := asset.Asset{
		ID:       "arn:aws:iam::111122223333:role/trust-deny-noise",
		Type:     "iam_role",
		Metadata: map[string]string{"policies": policiesJSON},
	}
	edges := iamPermissionEdges(role, nil)
	require.NotEmpty(t, edges, "a deny-all in the trust policy must not suppress the identity policy's real admin grant")
}

// TestNotActionWidenings pins what the full sweep logs as widened to Allow *:
// an AWS principal's own NotAction-only Allow and one in its account's SCPs,
// and nothing for a plain Allow or a non-AWS principal.
func TestNotActionWidenings(t *testing.T) {
	const notAction = `"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"NotAction\":\"iam:*\",\"Resource\":\"*\"}]}"`
	widened := asset.Asset{
		ID: "role-na", Type: "iam_role", AccountID: "111",
		Metadata: map[string]string{"policies": `[{"name":"na-policy","type":"identity",` + notAction + `}]`},
	}
	plain := asset.Asset{
		ID: "user-plain", Type: "iam_user", AccountID: "222",
		Metadata: map[string]string{"policies": adminPolicy("admin")},
	}
	capped := asset.Asset{
		ID: "user-scp", Type: "iam_user", AccountID: "333",
		Metadata: map[string]string{"policies": adminPolicy("admin")},
	}
	scp := scpSetAsset("333", `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`)
	gcp := asset.Asset{
		ID: "sa-1", Type: "gcp_service_account",
		Metadata: map[string]string{"policies": `[{"name":"gcp","type":"identity",` + notAction + `}]`},
	}

	got := notActionWidenings(NewGraph([]asset.Asset{widened, plain, capped, scp, gcp}))
	require.Equal(t, map[string][]string{
		"role-na":  {"na-policy"},
		"user-scp": {"scp"},
	}, got)
}
