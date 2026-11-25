package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apikeys "google.golang.org/api/apikeys/v2"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

type fakeKMS struct {
	rings    map[string][]string
	keys     map[string][]*cloudkms.CryptoKey
	grants   map[string][]string
	grantErr map[string]error
	ringsErr map[string]error
}

func (f fakeKMS) Locations(context.Context, string) ([]string, error) {
	return []string{"global", "europe-west4", "us-east1"}, nil
}
func (f fakeKMS) KeyRings(_ context.Context, _, loc string) ([]string, error) {
	return f.rings[loc], f.ringsErr[loc]
}
func (f fakeKMS) CryptoKeys(_ context.Context, ring string) ([]*cloudkms.CryptoKey, error) {
	return f.keys[ring], nil
}
func (f fakeKMS) PublicGrants(_ context.Context, res string) ([]string, error) {
	return f.grants[res], f.grantErr[res]
}

func TestCollectKMS(t *testing.T) {
	const ring = "projects/p/locations/europe-west4/keyRings/r"
	f := fakeKMS{
		rings: map[string][]string{"europe-west4": {ring}},
		keys: map[string][]*cloudkms.CryptoKey{ring: {
			{Name: ring + "/cryptoKeys/rotated", Purpose: "ENCRYPT_DECRYPT", RotationPeriod: "7776000s", NextRotationTime: "2026-12-01T00:00:00Z",
				Primary: &cloudkms.CryptoKeyVersion{State: "ENABLED"}},
			{Name: ring + "/cryptoKeys/yearly", Purpose: "ENCRYPT_DECRYPT", RotationPeriod: "31536000s", NextRotationTime: "2027-01-01T00:00:00Z"},
			{Name: ring + "/cryptoKeys/never", Purpose: "ENCRYPT_DECRYPT"},
			{Name: ring + "/cryptoKeys/unreadable", Purpose: "ASYMMETRIC_SIGN"},
		}},
		grants:   map[string][]string{ring + "/cryptoKeys/never": {"allUsers=roles/cloudkms.cryptoKeyEncrypterDecrypter"}},
		grantErr: map[string]error{ring + "/cryptoKeys/unreadable": errors.New("denied")},
		ringsErr: map[string]error{"us-east1": errors.New("unavailable")},
	}
	got, err := collectKMS(context.Background(), f, "p", time.Now())
	require.Error(t, err, "a location that failed to list makes the sweep partial")
	md := byID(got)
	require.Len(t, md, 4, "the keys that were read are kept")

	rotated := md[ring+"/cryptoKeys/rotated"]
	require.Equal(t, "90", rotated["rotation_period_days"])
	require.Equal(t, "true", rotated["rotation_within_90_days"])
	require.Equal(t, "true", rotated["next_rotation"])
	require.Equal(t, "", rotated["public_grants"])
	require.Equal(t, ring, rotated["key_ring"])
	require.Equal(t, "false", md[ring+"/cryptoKeys/yearly"]["rotation_within_90_days"])
	never := md[ring+"/cryptoKeys/never"]
	require.Equal(t, "", never["rotation_period_days"], "no rotation schedule is observed, not unknown")
	require.Equal(t, "false", never["next_rotation"])
	require.Equal(t, "allUsers=roles/cloudkms.cryptoKeyEncrypterDecrypter", never["public_grants"])
	require.NotContains(t, md[ring+"/cryptoKeys/unreadable"], "public_grants", "an unread policy is unknown")
}

// A public grant on the key ring is inherited by every key in it.
func TestCollectKMS_RingGrantInherited(t *testing.T) {
	const ring = "projects/p/locations/global/keyRings/r"
	f := fakeKMS{
		rings:  map[string][]string{"global": {ring}},
		keys:   map[string][]*cloudkms.CryptoKey{ring: {{Name: ring + "/cryptoKeys/k", Purpose: "ENCRYPT_DECRYPT"}}},
		grants: map[string][]string{ring: {"allAuthenticatedUsers=roles/cloudkms.viewer"}},
	}
	got, err := collectKMS(context.Background(), f, "p", time.Now())
	require.NoError(t, err)
	require.Equal(t, "allAuthenticatedUsers=roles/cloudkms.viewer", byID(got)[ring+"/cryptoKeys/k"]["public_grants"])
}

// A key ring whose IAM policy cannot be read leaves every key in it with
// public_grants absent — a public ring grant would be inherited, so the key's
// own clean policy proves nothing.
func TestCollectKMS_UnreadableRingPolicyIsUnknown(t *testing.T) {
	const ring = "projects/p/locations/global/keyRings/r"
	f := fakeKMS{
		rings:    map[string][]string{"global": {ring}},
		keys:     map[string][]*cloudkms.CryptoKey{ring: {{Name: ring + "/cryptoKeys/k", Purpose: "ENCRYPT_DECRYPT"}}},
		grantErr: map[string]error{ring: errors.New("denied")},
	}
	got, err := collectKMS(context.Background(), f, "p", time.Now())
	require.Error(t, err)
	require.NotContains(t, byID(got)[ring+"/cryptoKeys/k"], "public_grants")
}

type fakeAPIKeys struct{ keys []*apikeys.V2Key }

func (f fakeAPIKeys) ListKeys(context.Context, string) ([]*apikeys.V2Key, error) { return f.keys, nil }

func TestCollectAPIKeys(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	keys := []*apikeys.V2Key{
		{Name: "projects/1/locations/global/keys/open", CreateTime: "2026-01-01T00:00:00Z"},
		{Name: "projects/1/locations/global/keys/browser", DisplayName: "web", CreateTime: "2026-09-20T00:00:00Z",
			Restrictions: &apikeys.V2Restrictions{
				BrowserKeyRestrictions: &apikeys.V2BrowserKeyRestrictions{AllowedReferrers: []string{"https://app.example.com/*"}},
				ApiTargets:             []*apikeys.V2ApiTarget{{Service: "maps-backend.googleapis.com"}},
			}},
		{Name: "projects/1/locations/global/keys/wild", Restrictions: &apikeys.V2Restrictions{
			BrowserKeyRestrictions: &apikeys.V2BrowserKeyRestrictions{AllowedReferrers: []string{"*.com/*"}},
			ApiTargets:             []*apikeys.V2ApiTarget{{Service: "cloudapis.googleapis.com"}},
		}},
		{Name: "projects/1/locations/global/keys/server-any", Restrictions: &apikeys.V2Restrictions{
			ServerKeyRestrictions: &apikeys.V2ServerKeyRestrictions{AllowedIps: []string{"0.0.0.0/0"}}}},
		{Name: "projects/1/locations/global/keys/deleted", DeleteTime: "2026-09-01T00:00:00Z"},
	}
	got, err := collectAPIKeys(context.Background(), fakeAPIKeys{keys: keys}, "p", now)
	require.NoError(t, err)
	md := byID(got)
	require.Len(t, md, 4, "a key pending deletion is not live")
	require.Equal(t, map[string]string{"app_restriction": "", "api_restricted": "false", "age_days": "273"}, md["projects/1/locations/global/keys/open"])
	require.Equal(t, map[string]string{"app_restriction": "browser", "api_restricted": "true", "age_days": "11"}, md["projects/1/locations/global/keys/browser"])
	wild := md["projects/1/locations/global/keys/wild"]
	require.Equal(t, "", wild["app_restriction"], "a wildcard referrer restricts nothing")
	require.Equal(t, "false", wild["api_restricted"], "cloudapis.googleapis.com admits every API")
	require.NotContains(t, wild, "age_days", "an unparsable createTime is unknown")
	require.Equal(t, "", md["projects/1/locations/global/keys/server-any"]["app_restriction"])
}
