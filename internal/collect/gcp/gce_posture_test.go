package gcp

import (
	"testing"

	"github.com/stretchr/testify/require"
	compute "google.golang.org/api/compute/v1"
)

// The CIS 4.x instance settings already ride on the aggregated listing; this
// pins that they reach the asset and that the Shielded VM sub-object is
// evidence only when it came back.
func TestGCEPostureMetadata(t *testing.T) {
	full := toNeutral(&compute.Instance{
		Name: "vm", CanIpForward: true,
		ShieldedInstanceConfig:     &compute.ShieldedInstanceConfig{EnableSecureBoot: true, EnableVtpm: true},
		ConfidentialInstanceConfig: &compute.ConfidentialInstanceConfig{EnableConfidentialCompute: true},
		ServiceAccounts: []*compute.ServiceAccount{{
			Email:  "123-compute@developer.gserviceaccount.com",
			Scopes: []string{"https://www.googleapis.com/auth/devstorage.read_only", cloudPlatformScope},
		}},
	})
	md := gceMetadata(full, nil, true)
	require.Equal(t, "true", md["can_ip_forward"])
	require.Equal(t, "true", md["confidential_compute"])
	require.Equal(t, "true", md["shielded_secure_boot"])
	require.Equal(t, "true", md["shielded_vtpm"])
	require.Equal(t, "false", md["shielded_integrity_monitoring"])
	require.Equal(t, "true", md["sa_cloud_platform_scope"])

	bare := gceMetadata(toNeutral(&compute.Instance{
		Name:            "vm2",
		ServiceAccounts: []*compute.ServiceAccount{{Email: "app@p.iam.gserviceaccount.com", Scopes: []string{"https://www.googleapis.com/auth/logging.write"}}},
	}), nil, true)
	require.Equal(t, "false", bare["can_ip_forward"])
	require.Equal(t, "false", bare["confidential_compute"], "an omitted confidentialInstanceConfig is GCE's encoding of off")
	require.Equal(t, "false", bare["sa_cloud_platform_scope"])
	for _, k := range []string{"shielded_secure_boot", "shielded_vtpm", "shielded_integrity_monitoring"} {
		require.NotContains(t, bare, k, "no shieldedInstanceConfig returned is unknown, not off")
	}

	noSA := gceMetadata(toNeutral(&compute.Instance{Name: "vm3"}), nil, true)
	require.NotContains(t, noSA, "sa_cloud_platform_scope", "no service account, no scope to grade")
}
