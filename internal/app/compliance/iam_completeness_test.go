package compliance

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/checks"
)

func TestEvidenceProjection_PreservesConditionalGCPProbes(t *testing.T) {
	reg := checks.Default()
	svc := NewService(fakeFindings{}, &fakeInventory{}, reg, &fakeConnectors{})
	spec := svc.evidenceSpec(append(allMappedIDs(), "gcp-sa-unused"))
	check, ok := reg.ByID("gcp-sa-unused")
	require.True(t, ok)
	for _, complete := range []string{"", "false", "true"} {
		for _, disabled := range []string{"false", "true"} {
			for _, lastAuth := range []string{"3", "200"} {
				a := asset.Asset{Provider: asset.ProviderGCP, Type: "gcp_service_account", Metadata: map[string]string{
					"roles": "roles/viewer", "disabled": disabled, "sa_last_auth_days": lastAuth, "key_age_days": "400",
					"privilege_tier": ciem.TierStandard, "permissions": "storage.objects.get", "roles_complete": complete, "permissions_complete": complete,
				}}
				r := reduceEvidence(spec, a)
				require.Equal(t, ciem.Graded(a), ciem.Graded(r))
				require.Equal(t, check.Evaluable(a), check.Evaluable(r), "all raw keys exist but partial fields are removed before probes: %v -> %v", a.Metadata, r.Metadata)
				if disabled == "true" || lastAuth == "3" {
					require.True(t, check.Evaluable(r), "independent disabled/recent observations can prove no dormancy")
				}
			}
		}
	}
}

func TestEvidenceProjection_PreservesAzureGrantValidity(t *testing.T) {
	svc := NewService(fakeFindings{}, &fakeInventory{}, checks.Default(), &fakeConnectors{})
	spec := svc.evidenceSpec(allMappedIDs())
	for _, tc := range []struct {
		grants, permissions, complete string
		graded                        bool
	}{
		{`[{"scope":"/subscriptions/s","evidence_complete":true,"actions":["read"]}]`, "read", "true", true},
		{`[{"scope":"/subscriptions/s","evidence_complete":false,"actions":["read"]}]`, "read", "true", false},
		{`[{"scope":"unknown","evidence_complete":true,"actions":["read"]}]`, "read", "true", false},
		{`broken`, "read", "true", false},
		{`[]`, "", "true", true},
		{"", "", "true", true},
		{"", "read", "true", false},
		{`[]`, "", "false", false},
	} {
		a := asset.Asset{Provider: asset.ProviderAzure, Type: "azure_service_principal", Metadata: map[string]string{
			"privilege_tier": ciem.TierStandard, "role_grants": tc.grants, "permissions": tc.permissions, "role_grants_complete": tc.complete,
		}}
		require.Equal(t, tc.graded, ciem.Graded(a))
		require.Equal(t, tc.graded, ciem.Graded(reduceEvidence(spec, a)))
	}
}

func TestCompute_GCPCompletenessIsRequiredForPassing(t *testing.T) {
	for _, complete := range []string{"", "false", "true"} {
		t.Run(complete, func(t *testing.T) {
			a := asset.Asset{Provider: asset.ProviderGCP, Type: "gcp_service_account", Metadata: map[string]string{
				"privilege_tier": ciem.TierStandard, "permissions": "", "permissions_complete": complete,
			}}
			cov, err := NewService(fakeFindings{}, &fakeInventory{samples: []asset.Asset{a}}, checks.Default(), &fakeConnectors{}).Compute(context.Background())
			require.NoError(t, err)
			want := StateNotAssessed
			if complete == "true" {
				want = StatePassing
			}
			require.Equal(t, want, controlStateOf(t, cov, "SOC2-CC6.3-GCP"))
		})
	}
}

func TestEvidenceProjection_CollapsesPermissionPayloadsButKeepsEmpty(t *testing.T) {
	svc := NewService(fakeFindings{}, &fakeInventory{}, checks.Default(), &fakeConnectors{})
	spec := svc.evidenceSpec(allMappedIDs())
	var assets []asset.Asset
	for _, permissions := range []string{"", "read", "write", "another-long-permission-set"} {
		assets = append(assets, asset.Asset{Provider: asset.ProviderAzure, Type: "azure_service_principal", Metadata: map[string]string{
			"privilege_tier": ciem.TierStandard, "permissions": permissions, "role_grants_complete": "true",
		}})
	}
	require.Len(t, sampleByEvidence(spec, assets), 2)
}
