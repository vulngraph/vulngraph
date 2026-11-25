package asset

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContentHash_StableAndSemantic(t *testing.T) {
	a := Asset{
		ID: "i-1", Name: "web-server", Type: "ec2_instance",
		Provider: ProviderAWS, Region: "eu-west-1", AccountID: "123",
		PublicIP: "1.2.3.4",
		Tags:     map[string]string{"env": "prod", "team": "payments"},
		Metadata: map[string]string{"prov_connector_id": "conn-abc"},
	}
	h1 := ContentHash(a)
	h2 := ContentHash(a)
	require.Equal(t, h1, h2, "same input → same hash")
	require.Len(t, h1, 16, "8 bytes → 16 hex chars")

	// Changing a semantic field changes the hash.
	changed := a
	changed.PublicIP = "5.6.7.8"
	require.NotEqual(t, h1, ContentHash(changed), "PublicIP change must change hash")

	// Changing map insertion order does NOT change the hash.
	reordered := a
	reordered.Tags = map[string]string{"team": "payments", "env": "prod"}
	require.Equal(t, h1, ContentHash(reordered), "map key order must not affect hash")
}

func TestConnectorFingerprint_ChangesOnAssetChange(t *testing.T) {
	assets := []Asset{
		{ID: "i-1", Name: "a", Type: "ec2_instance", Provider: ProviderAWS},
		{ID: "i-2", Name: "b", Type: "ec2_instance", Provider: ProviderAWS},
	}
	fp1 := ConnectorFingerprint(assets)
	fp2 := ConnectorFingerprint(assets)
	require.Equal(t, fp1, fp2, "same assets → same fingerprint")

	// Same assets in different order → same fingerprint (sorted).
	reversed := []Asset{assets[1], assets[0]}
	require.Equal(t, fp1, ConnectorFingerprint(reversed), "asset order must not affect fingerprint")

	// Changed asset → different fingerprint.
	modified := []Asset{
		{ID: "i-1", Name: "a-renamed", Type: "ec2_instance", Provider: ProviderAWS},
		assets[1],
	}
	require.NotEqual(t, fp1, ConnectorFingerprint(modified), "renamed asset must change fingerprint")

	// Empty slice → empty string (no short-circuit on empty collector output).
	require.Empty(t, ConnectorFingerprint(nil))
}
