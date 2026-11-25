package correlate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// scopedLoader lets a test distinguish the partial-correlate SEED set
// (LoadByIDs) from the background VIEW (LoadViewForTypes) — fakeLoader
// returns the same assets for both, which can't exercise scoping.
type scopedLoader struct {
	changed []asset.Asset
	view    []asset.Asset
}

func (l scopedLoader) LoadView(context.Context) ([]asset.Asset, bool, error) {
	return l.view, false, nil
}
func (l scopedLoader) LoadViewForTypes(context.Context, []string) ([]asset.Asset, bool, error) {
	return l.view, false, nil
}
func (l scopedLoader) LoadByIDs(_ context.Context, ids []string) ([]asset.Asset, error) {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	var out []asset.Asset
	for _, a := range l.changed {
		if want[a.ID] {
			out = append(out, a)
		}
	}
	return out, nil
}

func adminPolicy(name string) string {
	return `[{"name":"` + name + `","type":"identity","managed":true,` +
		`"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}]`
}

// TestPartialCorrelate_IAMEffectivePermissions_SkipsUnrelatedPrincipals is the
// regression test: a partial correlate on one changed role must NOT recompute
// effective permissions for every other principal merely present in the
// background view (LoadViewForTypes), which is what turned a small partial
// into a run proportional to every principal in the view.
func TestPartialCorrelate_IAMEffectivePermissions_SkipsUnrelatedPrincipals(t *testing.T) {
	changedRole := asset.Asset{
		ID: "role-changed", Type: "iam_role", AccountID: "111",
		Metadata: map[string]string{"policies": adminPolicy("changed-admin")},
	}
	unrelatedRole := asset.Asset{
		ID: "role-unrelated", Type: "iam_role", AccountID: "222",
		Metadata: map[string]string{"policies": adminPolicy("unrelated-admin")},
	}
	loader := scopedLoader{
		changed: []asset.Asset{changedRole},
		view:    []asset.Asset{changedRole, unrelatedRole},
	}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{IAMEffectivePermissions{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{"role-changed"})
	require.NoError(t, err)
	require.Equal(t, 1, n, "only the changed role's admin-wildcard edge should be produced")
	require.Len(t, w.got, 1)
	require.Equal(t, "role-changed", w.got[0].SrcID)
}

// TestPartialCorrelate_IAMEffectivePermissions_SCPChangeRecomputesWholeAccount
// guards the correctness side of the same scoping: an SCP caps every
// principal in its account, so a changed aws_scp_set must still trigger a
// full recompute for that account — the fix must not narrow scope so far that
// it silently drops a real permissions change.
func TestPartialCorrelate_IAMEffectivePermissions_SCPChangeRecomputesWholeAccount(t *testing.T) {
	scp := asset.Asset{ID: "scp-111", Type: "aws_scp_set", AccountID: "111"}
	roleInAccount := asset.Asset{
		ID: "role-in-scp-account", Type: "iam_role", AccountID: "111",
		Metadata: map[string]string{"policies": adminPolicy("in-account-admin")},
	}
	roleInOtherAccount := asset.Asset{
		ID: "role-other-account", Type: "iam_role", AccountID: "222",
		Metadata: map[string]string{"policies": adminPolicy("other-account-admin")},
	}
	loader := scopedLoader{
		changed: []asset.Asset{scp},
		view:    []asset.Asset{scp, roleInAccount, roleInOtherAccount},
	}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{IAMEffectivePermissions{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{"scp-111"})
	require.NoError(t, err)
	require.Equal(t, 1, n, "the in-account role must be recomputed even though only the SCP asset changed")
	require.Equal(t, "role-in-scp-account", w.got[0].SrcID)
}

// TestPartialCorrelate_BailsOutOnExpiredContext guards the other half of the
// fix: Correlate's per-rule loop takes no ctx at all, so nothing inside a rule
// can be preempted — but the loop between rules can at least stop starting
// NEW rules once the job's own context has already expired, instead of
// running every remaining rule regardless (otherwise a job can overrun its
// deadline with no way for River's Timeout to have any effect at all).
func TestPartialCorrelate_BailsOutOnExpiredContext(t *testing.T) {
	role := asset.Asset{ID: "role-1", Type: "iam_role", Metadata: map[string]string{"policies": adminPolicy("x")}}
	loader := scopedLoader{changed: []asset.Asset{role}, view: []asset.Asset{role}}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{IAMEffectivePermissions{}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already expired before PartialCorrelate ever runs a rule

	n, err := svc.PartialCorrelate(ctx, []string{"role-1"})
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, n)
	require.Empty(t, w.got, "no edges should be written once the job's own context has expired")
}

// TestPermissionPrincipals_IncludesGCPServiceAccount pins the fix for the
// InterestedIn/PermissionPrincipals mismatch: IAMEffectivePermissions declares
// gcp_service_account in InterestedIn (so a changed GCP SA activates the
// rule), but PermissionPrincipals used to only ever populate iam_role and
// iam_user — so the rule ran with nothing to iterate for the very asset that
// triggered it. Mirrors the AWS-side principal types' handling: a
// gcp_service_account is appended to permissionPrincipals exactly like
// iam_user is, no trust-policy-only IAMRoles slice involved.
func TestPermissionPrincipals_IncludesGCPServiceAccount(t *testing.T) {
	role := asset.Asset{ID: "arn:aws:iam::1:role/x", Type: "iam_role"}
	user := asset.Asset{ID: "arn:aws:iam::1:user/y", Type: "iam_user"}
	sa := asset.Asset{ID: "serviceAccount:deploy@p.iam.gserviceaccount.com", Type: "gcp_service_account"}

	g := NewGraph([]asset.Asset{role, user, sa})

	require.ElementsMatch(t, []asset.Asset{role, user, sa}, g.PermissionPrincipals(),
		"gcp_service_account must be iterated by PermissionPrincipals, same as iam_role and iam_user")
	require.Contains(t, g.PermissionPrincipals(), sa)
}
