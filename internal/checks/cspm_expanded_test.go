package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestDataExfilChecks(t *testing.T) {
	tests := []struct {
		name  string
		check Check
		typ   string
		md    map[string]string
		want  bool
	}{
		{"public snapshot flagged", awsEBSSnapshotPublic, "ebs_snapshot", map[string]string{"public": "true"}, true},
		{"private snapshot ok", awsEBSSnapshotPublic, "ebs_snapshot", map[string]string{"public": "false"}, false},
		{"public ami flagged", awsAMIPublic, "ami", map[string]string{"public": "true"}, true},
		{"private ami ok", awsAMIPublic, "ami", map[string]string{"public": "false"}, false},
		{"public gcp image flagged", gcpImagePublic, "gcp_image", map[string]string{"public": "true"}, true},
		{"private gcp image ok", gcpImagePublic, "gcp_image", map[string]string{"public": "false"}, false},
		{"public gcp snapshot flagged", gcpSnapshotPublic, "gcp_disk_snapshot", map[string]string{"public": "true"}, true},
		{"private gcp snapshot ok", gcpSnapshotPublic, "gcp_disk_snapshot", map[string]string{"public": "false"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.check.Violates(asset.Asset{
				Provider: asset.ProviderAWS, Type: tt.typ, Metadata: tt.md,
			}))
		})
	}
}

// Public snapshots are Critical — the breach-grade exfil vector — on both clouds.
func TestPublicSnapshotIsCritical(t *testing.T) {
	require.Equal(t, finding.SeverityCritical, awsEBSSnapshotPublic.Severity)
	require.Equal(t, finding.SeverityHigh, awsAMIPublic.Severity)
	require.Equal(t, finding.SeverityCritical, gcpSnapshotPublic.Severity)
	require.Equal(t, finding.SeverityHigh, gcpImagePublic.Severity)
}

func TestDataExfilChecksRegistered(t *testing.T) {
	got := map[string]bool{}
	for _, c := range Default().checks {
		got[c.ID] = true
	}
	for _, id := range []string{"aws-ebs-snapshot-public", "aws-ami-public", "gcp-image-public", "gcp-snapshot-public"} {
		require.True(t, got[id], "check %q not registered", id)
	}
}

// The never-used sentinel "9999" is not a day count: a never-used role is
// stale once the role itself is older than 90 days, and unknown age stays silent.
func TestRoleUnusedTreatsNeverUsedByAge(t *testing.T) {
	tests := []struct {
		name string
		md   map[string]string
		want bool
	}{
		{"used 91 days ago", map[string]string{"last_used_observed": "true", "last_used_days": "91"}, true},
		{"used 30 days ago", map[string]string{"last_used_observed": "true", "last_used_days": "30"}, false},
		{"never used, role two years old", map[string]string{"last_used_observed": "true", "last_used_days": "9999", "created_days": "730"}, true},
		{"never used, role a month old", map[string]string{"last_used_observed": "true", "last_used_days": "9999", "created_days": "30"}, false},
		{"never used, role age unknown", map[string]string{"last_used_observed": "true", "last_used_days": "9999"}, false},
		{"last use unknown", map[string]string{"created_days": "730"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := asset.Asset{ID: "r", Type: "iam_role", Provider: asset.ProviderAWS, Metadata: tt.md}
			require.Equal(t, tt.want, awsIAMRoleUnused.Violates(a))
		})
	}
}

// Only a key that can rotate automatically is graded; an unread key spec or
// origin could be that kind, so it leaves the check unknown rather than clean.
func TestKMSRotationGradesOnlyRotatableAWSKeys(t *testing.T) {
	rotatable := func(over map[string]string) map[string]string {
		md := map[string]string{
			"key_state": "Enabled", "key_spec": "SYMMETRIC_DEFAULT", "key_origin": "AWS_KMS",
			"custom_key_store_id": "", "multi_region_key_type": "", "rotation_enabled": "false",
		}
		for k, v := range over {
			if v == "<absent>" {
				delete(md, k)
				continue
			}
			md[k] = v
		}
		return md
	}
	tests := []struct {
		name      string
		md        map[string]string
		fires     bool
		evaluable bool
	}{
		{"symmetric KMS-generated key without rotation", rotatable(nil), true, true},
		{"rotation on", rotatable(map[string]string{"rotation_enabled": "true"}), false, true},
		{"asymmetric", rotatable(map[string]string{"key_spec": "RSA_2048"}), false, true},
		{"HMAC", rotatable(map[string]string{"key_spec": "HMAC_256"}), false, true},
		{"imported key material", rotatable(map[string]string{"key_origin": "EXTERNAL"}), false, true},
		{"CloudHSM key store", rotatable(map[string]string{"key_origin": "AWS_CLOUDHSM", "custom_key_store_id": "cks-1"}), false, true},
		{"external key store", rotatable(map[string]string{"key_origin": "EXTERNAL_KEY_STORE", "custom_key_store_id": "cks-2"}), false, true},
		{"custom key store id alone", rotatable(map[string]string{"custom_key_store_id": "cks-3"}), false, true},
		{"key spec unread", rotatable(map[string]string{"key_spec": "<absent>"}), false, false},
		{"origin unread", rotatable(map[string]string{"key_origin": "<absent>"}), false, false},
		{"custom key store unread", rotatable(map[string]string{"custom_key_store_id": "<absent>"}), false, false},
		{"multi-Region primary without rotation", rotatable(map[string]string{"multi_region_key_type": "PRIMARY"}), true, true},
		{"multi-Region replica", rotatable(map[string]string{"multi_region_key_type": "REPLICA"}), false, true},
		{"multi-Region role unread", rotatable(map[string]string{"multi_region_key_type": "<absent>"}), false, false},
		{"rotation unread", rotatable(map[string]string{"rotation_enabled": "<absent>"}), false, false},
		{"asymmetric, rotation unread", rotatable(map[string]string{"key_spec": "ECC_NIST_P256", "rotation_enabled": "<absent>"}), false, true},
	}
	c := registered(t, awsKMSRotationDisabled.ID)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := asset.Asset{ID: "arn:aws:kms:eu-west-1:1:key/k", Type: "kms_key", Provider: asset.ProviderAWS, Metadata: tt.md}
			require.Equal(t, tt.fires, c.Violates(a))
			require.Equal(t, tt.evaluable, c.Evaluable(a))
		})
	}
}
