package correlate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

func TestOrganizationSelectionConsistentForPermissionsAndSecrets(t *testing.T) {
	deny := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":["iam:PassRole","secretsmanager:GetSecretValue"],"Resource":"*"}]}`
	const secret = "arn:aws:secretsmanager:eu-west-1:111:secret:db"
	const grant = `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","secretsmanager:GetSecretValue"],"Resource":"*"}]}`
	for _, tc := range []struct {
		name, id, mode string
		retained       bool
	}{
		{"ordinary member", "arn:aws:iam::111:role/app", "member", false},
		{"service linked", "arn:aws:iam::111:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling", "member", true},
		{"ordinary service role", "arn:aws:iam::111:role/service-role/AWSServiceRoleForAutoScaling", "member", false},
		{"management exempt", "arn:aws:iam::111:role/app", "management", true},
		{"legacy hierarchy unknown", "arn:aws:iam::111:role/app", "legacy", true},
		{"expired hierarchy unknown", "arn:aws:iam::111:role/app", "expired", true},
		{"moved to different org", "arn:aws:iam::111:role/app", "moved", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			role := principalWithPolicy(tc.id, "iam_role", "111", grant)
			role.Metadata["permission_boundary_complete"] = "true"
			scp := scpSetAsset("111", deny)
			var evidence ciem.AWSOrganizationEvidence
			require.NoError(t, json.Unmarshal([]byte(scp.Metadata[ciem.MetaAWSOrganization]), &evidence))
			switch tc.mode {
			case "management":
				evidence.Applicability = "exempt"
				evidence.Reason = "management"
				evidence.ManagementAccountID = "111"
			case "expired":
				evidence.ObservedAt = time.Now().Add(-48 * time.Hour)
			case "moved":
				raw, err := json.Marshal(ciem.AWSOrganizationEvidence{AccountID: "111", ManagementAccountID: "different-org", ObservedAt: time.Now()})
				require.NoError(t, err)
				role.Metadata[ciem.MetaAWSOrganizationMembership] = string(raw)
			}
			raw, err := json.Marshal(evidence)
			require.NoError(t, err)
			scp.Metadata[ciem.MetaAWSOrganization] = string(raw)
			if tc.mode == "legacy" {
				scp.Metadata = map[string]string{"policies": `[{"type":"scp","document":"{\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}]`, "policies_complete": "true"}
			}
			graph := NewGraph([]asset.Asset{role, scp, {ID: secret, Type: "secretsmanager_secret", Provider: asset.ProviderAWS, AccountID: "111"}})
			require.Equal(t, tc.retained, len(IAMEffectivePermissions{}.Correlate(graph)) > 0)
			require.Equal(t, tc.retained, len(SecretAccess{}.Correlate(graph)) > 0)
		})
	}
}
