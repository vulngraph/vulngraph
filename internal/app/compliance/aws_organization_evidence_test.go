package compliance

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/checks"
)

func TestEvidenceProjection_PreservesAWSOrganizationObservation(t *testing.T) {
	svc := NewService(fakeFindings{}, &fakeInventory{}, checks.Default(), &fakeConnectors{})
	spec := svc.evidenceSpec(allMappedIDs())
	var inputs []asset.Asset
	for _, observed := range []string{"", "false", "true"} {
		t.Run(observed, func(t *testing.T) {
			a := asset.Asset{Provider: asset.ProviderAWS, Type: "iam_role", Metadata: map[string]string{
				ciem.MetaPrivilegeTier: ciem.TierStandard, "policies": "[]",
			}}
			if observed != "" {
				a.Metadata[ciem.MetaAWSOrganizationComplete] = observed
			}
			inputs = append(inputs, a)
			want := observed == "true"
			require.Equal(t, want, ciem.Graded(a), "missing organization coverage must not prove a clean permission set")
			reduced := reduceEvidence(spec, a)
			require.Equal(t, want, ciem.Graded(reduced), "the compact inventory must preserve complete versus incomplete evidence")
			require.Equal(t, observed, reduced.Metadata[ciem.MetaAWSOrganizationComplete])
		})
	}
	require.Len(t, sampleByEvidence(spec, inputs), 3, "legacy, explicitly partial and complete observations must not be grouped together")
}

func TestEvidenceProjection_PreservesPartialAWSPrivilegeProbes(t *testing.T) {
	check, ok := checks.Default().ByID("aws-iam-admin-role-dormant")
	require.True(t, ok)
	svc := NewService(fakeFindings{}, &fakeInventory{}, checks.Default(), &fakeConnectors{})
	spec := svc.evidenceSpec([]string{check.ID})
	for _, complete := range []string{"", "false", "true"} {
		for _, lastUse := range []string{"1", "180"} {
			a := asset.Asset{Provider: asset.ProviderAWS, Type: "iam_role", Metadata: map[string]string{
				"path": "/", "admin": "false", "privilege_tier": ciem.TierStandard,
				ciem.MetaAWSOrganizationComplete: complete, "last_used_observed": "true", "last_used_days": lastUse, "created_days": "240",
			}}
			want := complete == "true" || lastUse == "1"
			require.Equal(t, want, check.Evaluable(a))
			require.Equal(t, want, check.Evaluable(reduceEvidence(spec, a)), "raw-present partial evidence is removed before probing, so the other predicate values must survive projection")
		}
	}
}
