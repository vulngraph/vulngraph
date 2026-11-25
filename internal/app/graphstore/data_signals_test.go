package graphstore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/explore"
)

func TestAssetPublicTier(t *testing.T) {
	tests := []struct {
		name string
		meta map[string]string
		want int32
	}{
		{"not public", map[string]string{"public": "false"}, publicTierNone},
		{"no metadata", map[string]string{}, publicTierNone},
		{"s3 confirmed", map[string]string{"public": "true", "public_access": "confirmed"}, publicTierConfirmed},
		{"s3 possible (no PAB)", map[string]string{"public": "true", "public_access": "possible"}, publicTierPossible},
		{"rds publicly_accessible is network-only → possible", map[string]string{"publicly_accessible": "true"}, publicTierPossible},
		{"cloudsql public with possible tier", map[string]string{"public": "true", "public_access": "possible"}, publicTierPossible},
		{"lambda wildcard policy is confirmed", map[string]string{"public": "true", "public_access": "confirmed"}, publicTierConfirmed},
		// The default case does not promote to confirmed. This shape —
		// public=true with no tier key — is a stale-metadata artifact from a
		// collector that predates tier grading, not an observed open bucket.
		{"legacy public without tier is unproven, not confirmed", map[string]string{"public": "true"}, publicTierPossible},
		{"unrecognised tier value is unproven", map[string]string{"public": "true", "public_access": "banana"}, publicTierPossible},
		{"observed-not-public", map[string]string{"public": "false", "public_access": asset.PublicAccessNone}, publicTierNone},
		// A collector that could not read the exposure config at all reports
		// unknown. That is a coverage gap, not an exposure — it must not be public
		// and must not be graded possible (which would badge AccessDenied S3
		// buckets as PUBLIC? in the UI).
		{"unreadable exposure config is unknown", map[string]string{"public": "false", "public_access": PublicAccessUnknown}, publicTierUnknown},
		{"unknown wins over a stale public=true", map[string]string{"public": "true", "public_access": PublicAccessUnknown}, publicTierUnknown},
		// GCS bucket, image or snapshot whose IAM policy read failed: the
		// collector omits "public" entirely and writes only the unknown tier.
		{"unread IAM policy without a public key is unknown", map[string]string{"public_access": PublicAccessUnknown}, publicTierUnknown},
		// public_access without public=true never happens, but the tier must
		// follow the public signal, not the tier key alone.
		{"tier key without public", map[string]string{"public_access": "possible"}, publicTierNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, assetPublicTier(tt.meta))
		})
	}
}

// TestAssetPublicNeverPublicOnUnknown pins the pairing: whatever the tier says,
// an unobserved exposure config must not set the `public` column, because every
// "public sensitive data" query filters on it.
func TestAssetPublicNeverPublicOnUnknown(t *testing.T) {
	require.Equal(t, int32(0), assetPublic(map[string]string{
		"public": "true", "public_access": PublicAccessUnknown,
	}), "an unreadable bucket must not be reported as public")
	require.Equal(t, int32(1), assetPublic(map[string]string{
		"public": "true", "public_access": asset.PublicAccessConfirmed,
	}))
}

// TestPublicAccessUnknownLiteral pins the wire value shared with the collectors.
// graphstore cannot import internal/collect, so the string is duplicated there;
// this test is the contract. If it changes, change collect/aws/s3.go,
// collect/gcp/cloudsql.go and collect/azure/helpers.go (publicAccessUnknown)
// in the same commit.
func TestPublicAccessUnknownLiteral(t *testing.T) {
	require.Equal(t, "unknown", PublicAccessUnknown)
	require.NotEqual(t, asset.PublicAccessNone, PublicAccessUnknown,
		"unknown (not observed) and none (observed, nothing public) must stay distinct")
}

func TestAssetEncrypted(t *testing.T) {
	tests := []struct {
		name string
		meta map[string]string
		want int32
	}{
		// Observed negatives — the only shapes allowed to raise an alarm.
		{"s3 no default encryption", map[string]string{"encryption": ""}, encryptionUnencrypted},
		{"rds storage_encrypted=false", map[string]string{"storage_encrypted": "false"}, encryptionUnencrypted},
		// Observed positives.
		{"s3 SSE algorithm present", map[string]string{"encryption": "AES256"}, encryptionEncrypted},
		{"s3 KMS", map[string]string{"encryption": "aws:kms"}, encryptionEncrypted},
		{"rds storage_encrypted=true", map[string]string{"storage_encrypted": "true"}, encryptionEncrypted},
		// The floor. Graded encrypted, these would make the unencrypted count
		// cover only the two store types whose key is read.
		{"no metadata at all", map[string]string{}, encryptionUnknown},
		{"gcs bucket (key never collected)", map[string]string{"public": "false"}, encryptionUnknown},
		{"s3 bucket whose GetBucketEncryption failed", map[string]string{"public": "false", "website": ""}, encryptionUnknown},
		{"rds instance with no storage_encrypted key", map[string]string{"publicly_accessible": "true"}, encryptionUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, assetEncrypted(tt.meta))
		})
	}
}

// TestAssetEncryptedUnknownIsNotAnAlarm is the regression guard for both
// directions of the error: an unobserved store must not be counted as
// unencrypted (a false alarm on every unobserved store) and must not be counted as
// encrypted (which would make the tile a floor over 2 of 9 store types).
func TestAssetEncryptedUnknownIsNotAnAlarm(t *testing.T) {
	got := assetEncrypted(map[string]string{})
	require.NotEqual(t, encryptionUnencrypted, got, "unknown must not read as unencrypted")
	require.NotEqual(t, encryptionEncrypted, got, "unknown must not read as encrypted")
}

// TestReadSignalsEncryptionTriState guards the wire form of Asset.encrypted:
// readSignals used to fold it into a bool with `!= 0`, so every unknown (2) store
// was served as encrypted on /api/graph/cypher, /api/dspm/stores and MCP.
func TestReadSignalsEncryptionTriState(t *testing.T) {
	tests := []struct {
		name  string
		props map[string]any
		want  string
	}{
		{"0 is observed unencrypted", map[string]any{"encrypted": int64(0)}, explore.EncryptionUnencrypted},
		{"1 is observed encrypted", map[string]any{"encrypted": int64(1)}, explore.EncryptionEncrypted},
		{"2 is unknown", map[string]any{"encrypted": int64(2)}, explore.EncryptionUnknown},
		{"int32 0 is observed unencrypted", map[string]any{"encrypted": int32(0)}, explore.EncryptionUnencrypted},
		{"int32 1 is observed encrypted", map[string]any{"encrypted": int32(1)}, explore.EncryptionEncrypted},
		{"int32 2 is unknown", map[string]any{"encrypted": int32(2)}, explore.EncryptionUnknown},
		{"NULL is unknown, not the unencrypted alarm", map[string]any{"encrypted": nil}, explore.EncryptionUnknown},
		{"out-of-domain value is unknown", map[string]any{"encrypted": int64(7)}, explore.EncryptionUnknown},
		{"label without the column carries no state", map[string]any{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var n explore.Node
			readSignals(&n, tt.props)
			require.Equal(t, tt.want, n.Encryption)
		})
	}
}
