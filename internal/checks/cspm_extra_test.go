package checks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Malformed security-group rule JSON is not a clean "no world-open rule"
// reading: every check decoding it must report itself unevaluable, so the
// lifecycle reconcile does not close an open finding as fixed on garbage.
func TestSGChecks_MalformedRuleJSONIsUnevaluable(t *testing.T) {
	r := Default()
	sg := func(md map[string]string) asset.Asset {
		return asset.Asset{ID: "sg-1", Provider: asset.ProviderAWS, Type: "security_group", Metadata: md}
	}
	tests := []struct {
		checkID string
		key     string
	}{
		{checkID: "aws-sg-open-database-ports", key: "ingress"},
		{checkID: "aws-sg-open-all-ports", key: "ingress"},
		{checkID: "aws-security-group-world-open-admin-port", key: "ingress"},
		{checkID: "aws-security-group-unrestricted-egress", key: "egress"},
	}
	for _, tc := range tests {
		t.Run(tc.checkID, func(t *testing.T) {
			c, ok := r.ByID(tc.checkID)
			require.True(t, ok)

			bad := sg(map[string]string{"ingress": "[]", "egress": "[]"})
			bad.Metadata[tc.key] = `{"not":"a rule list"`
			assert.False(t, c.Violates(bad), "unreadable rules do not fire")
			assert.False(t, c.Evaluable(bad), "…and the silence is unknown, not clean")

			clean := sg(map[string]string{"ingress": "[]", "egress": "[]"})
			assert.True(t, c.Evaluable(clean), "an observed empty rule list is a clean reading")
		})
	}
}

// Another provider's "ingress" key has its own shape; the AWS decoder must not
// judge it.
func TestStructuredMetadataUnreadable_AWSSecurityGroupsOnly(t *testing.T) {
	nsg := asset.Asset{Provider: asset.ProviderAzure, Type: "network_security_group",
		Metadata: map[string]string{"ingress": "not json"}}
	assert.False(t, structuredMetadataUnreadable(nsg, []string{"ingress"}))
}
