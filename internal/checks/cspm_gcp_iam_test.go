package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestGCPSACredentialHygieneChecks(t *testing.T) {
	tests := []struct {
		name  string
		check Check
		md    map[string]string
		want  bool
	}{
		{"exposed key flagged", gcpSAKeyExposed, map[string]string{"key_exposed": "true"}, true},
		{"no exposure ok", gcpSAKeyExposed, map[string]string{"key_exposed": "false"}, false},
		{"missing exposure metadata ok", gcpSAKeyExposed, map[string]string{}, false},

		{"user-managed key flagged", gcpSAUserManagedKey, map[string]string{"key_count": "1"}, true},
		{"keyless sa ok", gcpSAUserManagedKey, map[string]string{"key_count": "0"}, false},
		{"keys lookup failed stays silent", gcpSAUserManagedKey, map[string]string{}, false},
		{"stale flag but no active key ok", gcpSAUserManagedKey, map[string]string{"key_count": "0", "key_stale": "true"}, false},

		{"dormant sa with roles flagged", gcpSAUnused, map[string]string{"roles": "roles/editor", "disabled": "false", "sa_last_auth_days": "-1"}, true},
		{"idle past threshold flagged", gcpSAUnused, map[string]string{"roles": "roles/viewer", "disabled": "false", "sa_last_auth_days": "120"}, true},
		{"idle admin-equivalent steps aside for gcp-sa-admin-dormant", gcpSAUnused, map[string]string{"roles": "roles/editor", "disabled": "false", "sa_last_auth_days": "120"}, false},
		{"recently active ok", gcpSAUnused, map[string]string{"roles": "roles/editor", "disabled": "false", "sa_last_auth_days": "3"}, false},
		{"no role bindings ok (inert)", gcpSAUnused, map[string]string{"roles": "", "disabled": "false", "sa_last_auth_days": "-1"}, false},
		{"already disabled ok", gcpSAUnused, map[string]string{"roles": "roles/editor", "disabled": "true", "sa_last_auth_days": "-1"}, false},
		{"analyzer unavailable stays silent", gcpSAUnused, map[string]string{"roles": "roles/editor", "disabled": "false"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.check.ID+"/"+tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.check.Violates(asset.Asset{
				Provider: asset.ProviderGCP, Type: "gcp_service_account", Metadata: tt.md,
			}))
		})
	}
}

// The surviving three checks are wired into the default registry, and the two
// collapsed into gcp-sa-user-managed-key must never be re-registered: they were
// strictly nested inside it (full containment across user-managed, old, and
// unused), so one service account with one old idle key
// produced three findings — one Low and two High — describing one key.
func TestGCPSACredentialHygieneChecksRegistered(t *testing.T) {
	got := map[string]bool{}
	for _, c := range Default().checks {
		got[c.ID] = true
	}
	for _, id := range []string{"gcp-sa-key-exposed", "gcp-sa-user-managed-key", "gcp-sa-unused"} {
		require.True(t, got[id], "check %q not registered in Default()", id)
	}
	for _, id := range []string{"gcp-sa-key-old", "gcp-sa-key-unused"} {
		require.False(t, got[id], "check %q was collapsed into gcp-sa-user-managed-key — re-registering it triple-counts one key", id)
	}
}

// The collapsed ladder must reproduce what the three checks reported between
// them: the worst observed state of the key, and nothing invented from absent
// data (key_stale is omitted entirely when Policy Analyzer is unavailable).
func TestGCPSAUserManagedKeySeverityLadder(t *testing.T) {
	tests := []struct {
		name string
		md   map[string]string
		want finding.Severity
	}{
		{"idle key is High", map[string]string{"key_count": "1", "key_stale": "true", "key_age_days": "400"}, finding.SeverityHigh},
		{"idle young key is still High", map[string]string{"key_count": "1", "key_stale": "true", "key_age_days": "10"}, finding.SeverityHigh},
		{"old but used key is Medium", map[string]string{"key_count": "1", "key_stale": "false", "key_age_days": "120"}, finding.SeverityMedium},
		{"exactly at the rotation threshold is Low", map[string]string{"key_count": "1", "key_stale": "false", "key_age_days": "90"}, finding.SeverityLow},
		{"young used key is Low", map[string]string{"key_count": "1", "key_stale": "false", "key_age_days": "10"}, finding.SeverityLow},
		{"analyzer unavailable falls through to the age ladder", map[string]string{"key_count": "1", "key_age_days": "120"}, finding.SeverityMedium},
		{"no age and no analyzer data grades Low, never High", map[string]string{"key_count": "1"}, finding.SeverityLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := asset.Asset{Provider: asset.ProviderGCP, Type: "gcp_service_account", Metadata: tt.md}
			require.True(t, gcpSAUserManagedKey.Violates(a))
			require.Equal(t, tt.want, gcpSAUserManagedKey.SeverityFor(a))
		})
	}
}

// Losing gcp-sa-key-old and gcp-sa-key-unused as separate check IDs is only
// defensible because the surviving check preserves their detail as evidence —
// that is the stated justification for the collapse, and nothing asserted it.
// A responder who can no longer filter by check ID must still be able to read
// the key's age and idleness off the finding.
func TestGCPSAUserManagedKeyEvidence(t *testing.T) {
	tests := []struct {
		name string
		md   map[string]string
		want map[string]string
	}{
		{
			name: "old and idle carries both collapsed check IDs' detail",
			md:   map[string]string{"key_count": "2", "key_age_days": "400", "key_stale": "true"},
			want: map[string]string{"key_count": "2", "key_age_days": "400", "key_rotation_overdue": "true", "key_unused_90d": "true"},
		},
		{
			// key_stale=false is an OBSERVATION (Policy Analyzer answered), and must
			// be reported as such — it is the evidence that the key is in use and
			// therefore graded on age alone.
			name: "old but actively used records the negative observation",
			md:   map[string]string{"key_count": "1", "key_age_days": "120", "key_stale": "false"},
			want: map[string]string{"key_count": "1", "key_age_days": "120", "key_rotation_overdue": "true", "key_unused_90d": "false"},
		},
		{
			// Omitted, not "false": Policy Analyzer was unavailable, so idleness is
			// unknown. Emitting "false" would state the opposite of what is known.
			name: "analyzer unavailable omits the idleness key entirely",
			md:   map[string]string{"key_count": "1", "key_age_days": "120"},
			want: map[string]string{"key_count": "1", "key_age_days": "120", "key_rotation_overdue": "true"},
		},
		{
			name: "age unknown omits the age key entirely",
			md:   map[string]string{"key_count": "1", "key_stale": "true"},
			want: map[string]string{"key_count": "1", "key_unused_90d": "true"},
		},
		{
			name: "neither observed still names the key count",
			md:   map[string]string{"key_count": "3"},
			want: map[string]string{"key_count": "3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := asset.Asset{Provider: asset.ProviderGCP, Type: "gcp_service_account", Metadata: tt.md}
			require.True(t, gcpSAUserManagedKey.Violates(a), "the evidence only matters on a firing check")
			require.Equal(t, tt.want, gcpSAUserManagedKey.EvidenceFor(a))
		})
	}
}

// End-to-end through the registry: the evidence must survive onto the emitted
// finding, not merely exist on the Check value.
func TestGCPSAUserManagedKeyEvidenceReachesTheFinding(t *testing.T) {
	r := Default()
	assets := []asset.Asset{{
		ID: "sa-1", Name: "sa-1", Type: "gcp_service_account", Provider: asset.ProviderGCP,
		Metadata: map[string]string{"key_count": "1", "key_age_days": "400", "key_stale": "true"},
	}}
	var got finding.Finding
	for _, f := range r.Run(assets, fixedTime) {
		if f.CheckID == "gcp-sa-user-managed-key" {
			got = f
		}
	}
	require.Equal(t, "gcp-sa-user-managed-key", got.CheckID, "check did not fire through the registry")
	require.Equal(t, finding.SeverityHigh, got.Severity)
	require.Equal(t, "400", got.Metadata["key_age_days"])
	require.Equal(t, "true", got.Metadata["key_unused_90d"])
	require.Equal(t, "1", got.Metadata["key_count"])
}
