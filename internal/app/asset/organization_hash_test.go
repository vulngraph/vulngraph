package asset

import (
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrganizationObservationHash_PreservesSemanticsAndStoredTime(t *testing.T) {
	for _, key := range []string{"organization_policies", "organization_membership"} {
		t.Run(key, func(t *testing.T) {
			raw := `{"observed_at":"2026-11-25T10:00:00Z","account_id":"123","management_account_id":"456","complete":true,"levels":[{"target_id":"123","policies":[{"Document":"Allow iam:*"}]}]}`
			a := Asset{Metadata: map[string]string{key: raw, "privilege_tier": "high", "organization_policy_complete": "true"}}
			fresh := a
			fresh.Metadata = maps.Clone(a.Metadata)
			fresh.Metadata[key] = strings.Replace(raw, "10:00:00", "11:00:00", 1)
			require.Equal(t, ContentHash(a), ContentHash(fresh), "a refreshed timestamp alone must not force full ingestion and checking")
			require.Equal(t, ConnectorFingerprint([]Asset{a}), ConnectorFingerprint([]Asset{fresh}))
			require.Equal(t, raw, a.Metadata[key], "hashing must not rewrite the persisted witness")
			for _, changed := range []string{
				strings.Replace(raw, `"456"`, `"789"`, 1),
				strings.Replace(raw, `"complete":true`, `"complete":false`, 1),
				strings.Replace(raw, "Allow iam:*", "Deny iam:*", 1),
				strings.Replace(raw, `"2026-11-25T10:00:00Z"`, `"unread"`, 1),
				strings.Replace(raw, `"observed_at":"2026-11-25T10:00:00Z",`, "", 1),
				strings.Replace(raw, `"2026-11-25T10:00:00Z"`, `"0001-01-01T00:00:00Z"`, 1),
			} {
				fresh.Metadata[key] = changed
				require.NotEqual(t, ContentHash(a), ContentHash(fresh), "membership, policy, coverage and unknown observation changes must invalidate")
			}
			fresh.Metadata = maps.Clone(a.Metadata)
			fresh.Metadata["organization_policy_complete"] = "false"
			require.NotEqual(t, ContentHash(a), ContentHash(fresh), "a freshness-driven coverage change still invalidates")
		})
	}
}

func TestOrganizationObservationHash_DoesNotIgnoreOtherTimestamps(t *testing.T) {
	old := `{"observed_at":"2026-11-25T10:00:00Z"}`
	fresh := `{"observed_at":"2026-11-25T11:00:00Z"}`
	require.NotEqual(t, ContentHash(Asset{Tags: map[string]string{"organization_policies": old}}), ContentHash(Asset{Tags: map[string]string{"organization_policies": fresh}}))
	require.NotEqual(t, ContentHash(Asset{Metadata: map[string]string{"other": old}}), ContentHash(Asset{Metadata: map[string]string{"other": fresh}}))
}
