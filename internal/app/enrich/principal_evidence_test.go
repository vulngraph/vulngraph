package enrich

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestEnrich_PrincipalReachEvidencePreservesPriority(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reach      ReachProvider
		want       uint8
		unmeasured bool
	}{
		{"no provider", nil, 80, false},
		{"unknown", fakeReach{ok: false}, 80, false},
		{"failure", fakeReach{err: errors.New("graph unavailable")}, 80, true},
		{"invalid negative result", fakeReach{hops: -2, ok: true}, 80, false},
		{"observed no modeled path", fakeReach{hops: reachNone, ok: true}, 55, false},
		{"observed two hop path", fakeReach{hops: 2, ok: true}, 90, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer := &fakeFindingWriter{}
			service := NewService(writer, &fakeSignalRepo{}, []Source{
				fakeSource{name: "observed-risk", factor: Factor{Source: "observed-risk", Points: 80}, applied: true},
				PrincipalClass{},
				InternetReach{Reach: tc.reach},
			})
			f := privescFinding("arn:aws:iam::111:role/github-actions-deploy", false)
			f.ID = "principal-reach"
			score, err := service.Enrich(t.Context(), f)
			require.NoError(t, err)
			require.Equal(t, tc.want, score.Value, "only observed reach may adjust priority; the role name cannot cap it")
			require.Len(t, writer.recorded, 1)
			require.Equal(t, tc.want, writer.recorded[0].Score)
			if tc.unmeasured {
				require.Contains(t, score.Unmeasured, sourceInternetReach)
			}
		})
	}
}

// Trust is an independent entry point even without a workload-to-role graph
// path. A familiar role name must not override the positive trust finding.
func TestEnrich_PublicTrustOnExpectedRoleRemainsActionable(t *testing.T) {
	for _, name := range []string{"github-actions-deploy", "OrganizationAccountAccessRole", "ordinary-role"} {
		t.Run(name, func(t *testing.T) {
			writer := &fakeFindingWriter{}
			service := NewService(writer, &fakeSignalRepo{}, []Source{
				fakeSource{name: "observed-risk", factor: Factor{Source: "observed-risk", Points: 80}, applied: true},
				IdentityHygiene{Assets: fakeAssetGetter{a: asset.Asset{Metadata: map[string]string{"public_trust": "true"}}}},
				PrincipalClass{},
				InternetReach{Reach: fakeReach{hops: reachNone, ok: true}},
			})
			f := privescFinding("arn:aws:iam::111:role/"+name, false)
			f.ResourceType = "iam_role"
			f.ID = name
			score, err := service.Enrich(t.Context(), f)
			require.NoError(t, err)
			require.Equal(t, uint8(70), score.Value, "80 observed risk + 15 public trust - 25 modeled no-path; no name-based cap")
			require.GreaterOrEqual(t, int(score.Value), ThresholdPipeline)
			require.Equal(t, uint8(70), writer.recorded[0].Score)
		})
	}
}
