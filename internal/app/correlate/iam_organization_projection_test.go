package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// scanAssets intentionally does not load Provider. The AWS principal's type and
// reserved ARN remain available, so its service-linked exemption must survive
// the real correlation projection rather than depending on that omitted field.
func TestOrganizationSelection_ServiceLinkedProjectedProvider(t *testing.T) {
	const reserved = "arn:aws:iam::111:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
	for _, tc := range []struct {
		name, id, path string
		provider       asset.Provider
		exempt         bool
	}{
		{"projected provider", reserved, "", "", true},
		{"explicit AWS provider", reserved, "", asset.ProviderAWS, true},
		{"conflicting provider", reserved, "", asset.ProviderAzure, false},
		{"cross account", "arn:aws:iam::222:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling", "", "", false},
		{"generic service role", "arn:aws:iam::111:role/service-role/AWSServiceRoleForAutoScaling", "", "", false},
		{"malformed resource", reserved + "/*", "", "", false},
		{"conflicting path", reserved, "/service-role/", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			role := principalWithPolicy(tc.id, "iam_role", "111", `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`)
			role.Provider = tc.provider
			role.Metadata["path"] = tc.path
			role.Metadata["permission_boundary_complete"] = "true"
			scp := scpSetAsset("111", `{"Statement":[{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}]}`)
			edges := IAMEffectivePermissions{}.Correlate(NewGraph([]asset.Asset{role, scp}))
			require.Equal(t, tc.exempt, len(edges) > 0, "SQL projection must preserve only a proven service-linked exemption")
		})
	}
}
