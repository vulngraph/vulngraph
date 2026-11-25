package correlate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// githubTrustPolicy builds a role's "policies" metadata blob with a single
// trust statement granting GitHub Actions OIDC assume for subject sub.
func githubTrustPolicy(sub string) string {
	return `[{"name":"github-oidc","type":"trust","managed":false,` +
		`"document":"{\"Statement\":{\"Effect\":\"Allow\",` +
		`\"Principal\":{\"Federated\":\"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com\"},` +
		`\"Condition\":{\"StringLike\":{\"token.actions.githubusercontent.com:sub\":\"` + sub + `\"}}}}"}]`
}

// TestPartialCorrelate_IAMCanAssume_SkipsUnrelatedRole is IAMCanAssume's
// version of the IAMEffectivePermissions regression test — single-sided (every
// edge derives entirely from the role's own trust document), so an unrelated
// role must be skipped outright. Both roles carry a concrete-ARN trust
// document (a document IAMCanAssume DOES emit an edge from) specifically so
// this proves the unrelated role's edge is skipped, not merely absent because
// its document shape produces nothing regardless of scoping — removing the
// NeedsRecompute guard turns n from 1 to 2.
func TestPartialCorrelate_IAMCanAssume_SkipsUnrelatedRole(t *testing.T) {
	trustDoc := func(principalARN string) string {
		return `[{"name":"x","type":"trust","document":"{\"Statement\":{\"Effect\":\"Allow\",` +
			`\"Principal\":{\"AWS\":\"` + principalARN + `\"}}}"}]`
	}
	changedRole := asset.Asset{
		ID: "role-changed", Type: "iam_role",
		Metadata: map[string]string{"policies": trustDoc("arn:aws:iam::1:user/alice")},
	}
	unrelatedRole := asset.Asset{
		ID: "role-unrelated", Type: "iam_role",
		Metadata: map[string]string{"policies": trustDoc("arn:aws:iam::1:user/bob")},
	}
	loader := scopedLoader{
		changed: []asset.Asset{changedRole},
		view:    []asset.Asset{changedRole, unrelatedRole},
	}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{IAMCanAssume{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{"role-changed"})
	require.NoError(t, err)
	require.Equal(t, 1, n, "only the changed role's can_assume edge should be produced")
	require.Equal(t, "arn:aws:iam::1:user/alice", w.got[0].SrcID)
}

// TestPartialCorrelate_FederationTrust_SkipsUnrelatedRoleWhenRepoUnchanged
// pins the safe half of the two-sided scoping: a role unrelated to what
// changed is skipped when no github_repo changed this run either.
func TestPartialCorrelate_FederationTrust_SkipsUnrelatedRoleWhenRepoUnchanged(t *testing.T) {
	changedRole := asset.Asset{
		ID: "role-changed", Type: "iam_role",
		Metadata: map[string]string{"policies": githubTrustPolicy("repo:example/api:*")},
	}
	unrelatedRole := asset.Asset{
		ID: "role-unrelated", Type: "iam_role",
		Metadata: map[string]string{"policies": githubTrustPolicy("repo:example/web:*")},
	}
	repoAPI := asset.Asset{ID: "example/api", Type: "github_repo"}
	repoWeb := asset.Asset{ID: "example/web", Type: "github_repo"}
	loader := scopedLoader{
		changed: []asset.Asset{changedRole},
		view:    []asset.Asset{changedRole, unrelatedRole, repoAPI, repoWeb},
	}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{FederationTrust{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{"role-changed"})
	require.NoError(t, err)
	require.Equal(t, 1, n, "only the changed role's federated_access edge should be produced")
	require.Equal(t, "example/api", w.got[0].SrcID)
}

// TestPartialCorrelate_FederationTrust_RepoChangeStillMatchesUnchangedRole is
// the correctness guard: a partial run triggered by a NEW/changed repo (no
// role changed) must still match it against an existing, untouched role's
// trust policy — the exact case a naive "skip unchanged roles" filter would
// silently break.
func TestPartialCorrelate_FederationTrust_RepoChangeStillMatchesUnchangedRole(t *testing.T) {
	existingRole := asset.Asset{
		ID: "role-existing", Type: "iam_role",
		Metadata: map[string]string{"policies": githubTrustPolicy("repo:example/api:*")},
	}
	newRepo := asset.Asset{ID: "example/api", Type: "github_repo"}
	loader := scopedLoader{
		changed: []asset.Asset{newRepo},
		view:    []asset.Asset{existingRole, newRepo},
	}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{FederationTrust{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{"example/api"})
	require.NoError(t, err)
	require.Equal(t, 1, n, "a newly-changed repo must still match the pre-existing, untouched role's trust policy")
	require.Equal(t, "role-existing", w.got[0].DstID)
}

// TestPartialCorrelate_SecretAccess_SkipsUnrelatedRoleWhenSecretsUnchanged
// mirrors the FederationTrust safe-skip case for SecretAccess's two-sided
// (role × secret) scoping.
func TestPartialCorrelate_SecretAccess_SkipsUnrelatedRoleWhenSecretsUnchanged(t *testing.T) {
	changedRole := asset.Asset{
		ID: "role-changed", Type: "iam_role", AccountID: "111",
		Metadata: map[string]string{"policies": adminPolicy("changed-admin")},
	}
	unrelatedRole := asset.Asset{
		ID: "role-unrelated", Type: "iam_role", AccountID: "222",
		Metadata: map[string]string{"policies": adminPolicy("unrelated-admin")},
	}
	secret := asset.Asset{ID: "arn:aws:secretsmanager:x:1:secret:s", Type: "secretsmanager_secret"}
	loader := scopedLoader{
		changed: []asset.Asset{changedRole},
		view:    []asset.Asset{changedRole, unrelatedRole, secret},
	}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{SecretAccess{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{"role-changed"})
	require.NoError(t, err)
	require.Equal(t, 1, n, "only the changed role's secret-access edge should be produced")
	require.Equal(t, "role-changed", w.got[0].SrcID)
}

// TestPartialCorrelate_SecretAccess_SecretChangeStillMatchesUnchangedRole is
// the correctness guard for SecretAccess: a newly-added secret must still be
// matched against an existing, untouched role's wildcard grant.
func TestPartialCorrelate_SecretAccess_SecretChangeStillMatchesUnchangedRole(t *testing.T) {
	existingRole := asset.Asset{
		ID: "role-existing", Type: "iam_role", AccountID: "111",
		Metadata: map[string]string{"policies": adminPolicy("existing-admin")},
	}
	newSecret := asset.Asset{ID: "arn:aws:secretsmanager:x:1:secret:new", Type: "secretsmanager_secret"}
	loader := scopedLoader{
		changed: []asset.Asset{newSecret},
		view:    []asset.Asset{existingRole, newSecret},
	}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{SecretAccess{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{newSecret.ID})
	require.NoError(t, err)
	require.NotZero(t, n, "a newly-changed secret must still be matched against the pre-existing, untouched role's wildcard grant")
	require.Equal(t, "role-existing", w.got[0].SrcID)
}

// TestPartialCorrelate_SecretAccess_SCPChangeRecomputesWholeAccount is
// SecretAccess's version of the IAMEffectivePermissions SCP test: a changed
// aws_scp_set must still trigger a full recompute for every principal in that
// account, even when no secret changed this run (so OtherSideUnchanged would
// otherwise have let the scoping skip it).
func TestPartialCorrelate_SecretAccess_SCPChangeRecomputesWholeAccount(t *testing.T) {
	scp := asset.Asset{ID: "scp-111", Type: "aws_scp_set", AccountID: "111"}
	roleInAccount := asset.Asset{
		ID: "role-in-scp-account", Type: "iam_role", AccountID: "111",
		Metadata: map[string]string{"policies": adminPolicy("in-account-admin")},
	}
	secret := asset.Asset{ID: "arn:aws:secretsmanager:x:1:secret:s", Type: "secretsmanager_secret"}
	loader := scopedLoader{
		changed: []asset.Asset{scp},
		view:    []asset.Asset{scp, roleInAccount, secret},
	}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{SecretAccess{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{"scp-111"})
	require.NoError(t, err)
	require.NotZero(t, n, "the in-account role must be recomputed even though only the SCP asset changed, not any secret")
	require.Equal(t, "role-in-scp-account", w.got[0].SrcID)
}

// humanOIDCTrustPolicy builds a role's "policies" metadata blob with a single
// (array-form) trust statement whose OIDC sub condition value is email —
// extractOIDCSubs only understands the array Statement shape.
func humanOIDCTrustPolicy(email string) string {
	return `[{"name":"human-oidc","type":"trust","managed":false,` +
		`"document":"{\"Statement\":[{\"Condition\":{\"StringEquals\":` +
		`{\"accounts.google.com:sub\":\"` + email + `\"}}}]}"}]`
}

// TestPartialCorrelate_HumanIdentityFederation_HumanChangeStillMatchesUnchangedRole
// is the correctness guard for the fix applied to HumanIdentityFederation's
// role-matching loop: a newly-discovered human_identity must still match an
// existing, untouched role's OIDC trust sub.
func TestPartialCorrelate_HumanIdentityFederation_HumanChangeStillMatchesUnchangedRole(t *testing.T) {
	existingRole := asset.Asset{
		ID: "role-existing", Type: "iam_role",
		Metadata: map[string]string{"policies": humanOIDCTrustPolicy("person@example.com")},
	}
	newHuman := asset.Asset{ID: "human-1", Type: "human_identity", Domain: "person@example.com"}
	loader := scopedLoader{
		changed: []asset.Asset{newHuman},
		view:    []asset.Asset{existingRole, newHuman},
	}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{HumanIdentityFederation{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{"human-1"})
	require.NoError(t, err)
	require.Equal(t, 1, n, "a newly-changed human_identity must still match the pre-existing, untouched role's OIDC trust sub")
	require.Equal(t, "role-existing", w.got[0].DstID)
}
