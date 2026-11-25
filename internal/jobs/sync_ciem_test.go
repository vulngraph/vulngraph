package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/checks"
)

// The tier CIEM computes must reach the posture checks: analyzeIAM stamps it on
// the swept assets in place, before they are hashed, ingested and checked. A
// service account with an allow-only IAM escalation candidate carries a high
// tier, without claiming proven admin. Unread permissions remain unknown.
func TestAnalyzeIAM_TierReachesChecks(t *testing.T) {
	sa := func(id, roles string, meta map[string]string) asset.Asset {
		md := map[string]string{"roles": roles, "roles_complete": "true", "disabled": "false", "sa_last_auth_days": "200"}
		if _, observed := meta["permissions"]; observed {
			md["permissions_complete"] = "true"
		}
		for k, v := range meta {
			md[k] = v
		}
		return asset.Asset{ID: id, Name: id, Type: "gcp_service_account", Provider: asset.ProviderGCP, AccountID: "proj", Metadata: md}
	}
	swept := []asset.Asset{
		sa("writer", "projects/proj/roles/custom", map[string]string{"permissions": "resourcemanager.projects.setIamPolicy"}),
		sa("unread", "roles/iam.serviceAccountTokenCreator", nil),
		sa("owner", "roles/owner", map[string]string{"permissions": "resourcemanager.projects.setIamPolicy", "sa_last_auth_days": "1"}),
	}
	before := asset.ContentHash(swept[0])

	// GCP only: fetchSCPAssets has no AWS account to read, so no store is needed.
	_, res, partial, err := analyzeIAM(context.Background(), nil, swept)
	require.NoError(t, err)
	require.False(t, partial)
	require.NotEmpty(t, res.Tiers)

	assert.Equal(t, "high", swept[0].Metadata["privilege_tier"])
	assert.Equal(t, "ciem:gcp-privesc-01", swept[0].Metadata["privilege_tier_source"])
	assert.Equal(t, "unknown", swept[1].Metadata["privilege_tier"])
	assert.Equal(t, "high", swept[2].Metadata["privilege_tier"])
	assert.NotEqual(t, before, asset.ContentHash(swept[0]), "the tier is part of the content hash, so a tier change re-checks the principal")

	byResource := map[string][]string{}
	for _, f := range checks.Default().Run(swept, time.Now()) {
		byResource[f.ResourceID] = append(byResource[f.ResourceID], f.CheckID)
	}
	assert.NotContains(t, byResource["writer"], "gcp-sa-admin-dormant")
	assert.Contains(t, byResource["writer"], "gcp-sa-unused", "ordinary dormancy remains visible without unsupported admin proof")
	assert.NotContains(t, byResource["unread"], "gcp-sa-admin-dormant", "an unknown tier never proves privilege")
}

// scpStore serves aws_scp_set assets and stored principals, failing either read
// on demand.
type scpStore struct {
	scps     []asset.Asset
	prior    []asset.Asset
	scpErr   error
	priorErr error
}

func (s scpStore) ByIDs(_ context.Context, ids []string) ([]asset.Asset, error) {
	if len(ids) > 0 && strings.HasPrefix(ids[0], "aws_scp:") {
		return s.scps, s.scpErr
	}
	if s.priorErr != nil {
		return nil, s.priorErr
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []asset.Asset
	for _, a := range s.prior {
		if want[a.ID] {
			out = append(out, a)
		}
	}
	return out, nil
}

const adminPolicy = `[{"name":"admin","type":"identity","document":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}]`

func awsRole(id string) asset.Asset {
	return asset.Asset{ID: id, Name: id, Type: "iam_role", Provider: asset.ProviderAWS, AccountID: "111",
		Metadata: map[string]string{"policies": adminPolicy, "permission_boundary_complete": "true"}}
}

func organizationAsset(t *testing.T, evidence ciem.AWSOrganizationEvidence) asset.Asset {
	evidence.ObservedAt = time.Now()
	t.Helper()
	raw, err := json.Marshal(evidence)
	require.NoError(t, err)
	return asset.Asset{ID: "aws_scp:" + evidence.AccountID, Type: "aws_scp_set", Provider: asset.ProviderAWS, AccountID: evidence.AccountID,
		Metadata: map[string]string{ciem.MetaAWSOrganization: string(raw)}}
}

func memberSCPAsset(t *testing.T, document string) asset.Asset {
	t.Helper()
	return organizationAsset(t, ciem.AWSOrganizationEvidence{
		AccountID: "111", ManagementAccountID: "999", RootID: "r-root", RootSCPStatus: "enabled", Applicability: "member", Complete: true,
		Levels: []ciem.SCPLevel{
			{TargetID: "111", ParentID: "r-root", Complete: true, Policies: []ciem.SCPPolicyDocument{{Document: document}}},
			{TargetID: "r-root", Complete: true, Policies: []ciem.SCPPolicyDocument{{Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}}},
		},
	})
}

func readOnlySCP(t *testing.T) asset.Asset {
	t.Helper()
	return memberSCPAsset(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
}

// Failed org reads retain candidates, but do not turn missing restrictions into
// admin proof or a clean finding lifecycle. Holding a prior low tier would also
// conceal a newly granted escalation permission during the failed read.
func TestAnalyzeIAM_SCPReadErrorRetainsCandidatesWithUnknownCoverage(t *testing.T) {
	ctx := context.Background()
	capped := []asset.Asset{awsRole("arn:role/known")}
	_, _, partial, err := analyzeIAM(ctx, scpStore{scps: []asset.Asset{readOnlySCP(t)}}, capped)
	require.NoError(t, err)
	require.False(t, partial)
	require.Equal(t, ciem.TierStandard, capped[0].Metadata[ciem.MetaPrivilegeTier])
	require.True(t, ciem.Graded(capped[0]))

	for _, tc := range []struct {
		name    string
		store   scpStore
		partial bool
	}{
		{"successful lookup without a row", scpStore{}, false},
		{"SCP store read failed", scpStore{scpErr: errors.New("ch timeout"), prior: capped}, true},
		{"both reads failed", scpStore{scpErr: errors.New("ch down"), priorErr: errors.New("ch down")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swept := []asset.Asset{awsRole("arn:role/known"), awsRole("arn:role/new")}
			_, res, partial, err := analyzeIAM(ctx, tc.store, swept)
			require.NoError(t, err)
			require.Equal(t, tc.partial, partial)
			for _, a := range swept {
				require.Equal(t, ciem.TierUnknown, a.Metadata[ciem.MetaPrivilegeTier])
				require.Equal(t, "false", a.Metadata[ciem.MetaAWSOrganizationComplete])
				require.False(t, ciem.Graded(a))
			}
			require.NotEmpty(t, res.Findings)
			require.NotEmpty(t, res.Paths)
			foundLambda := false
			for _, f := range res.Findings {
				if f.RuleID == "aws-privesc-17" {
					foundLambda = true
					require.Equal(t, "high", string(f.Severity))
				}
			}
			require.True(t, foundLambda, "unknown SCPs retain Lambda candidate without admin demotion")
		})
	}
}

func TestAnalyzeIAM_ObservedOrganizationAndServiceLinkedControls(t *testing.T) {
	full := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	deny := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}]}`
	for _, tc := range []struct {
		name     string
		roleID   string
		scp      asset.Asset
		passRole bool
		admin    bool
	}{
		{"member cap", "arn:aws:iam::111:role/app", memberSCPAsset(t, deny), false, false},
		{"member unrestricted", "arn:aws:iam::111:role/app", memberSCPAsset(t, full), true, true},
		{"management", "arn:aws:iam::111:role/app", organizationAsset(t, ciem.AWSOrganizationEvidence{AccountID: "111", ManagementAccountID: "111", Applicability: "exempt", Reason: "management", Complete: true}), true, true},
		{"standalone", "arn:aws:iam::111:role/app", organizationAsset(t, ciem.AWSOrganizationEvidence{AccountID: "111", Applicability: "exempt", Reason: "standalone", Complete: true}), true, true},
		{"service linked", "arn:aws:iam::111:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling", memberSCPAsset(t, deny), true, true},
		{"ordinary service role", "arn:aws:iam::111:role/service-role/AWSServiceRoleForAutoScaling", memberSCPAsset(t, deny), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swept := []asset.Asset{awsRole(tc.roleID)}
			_, result, partial, err := analyzeIAM(context.Background(), scpStore{scps: []asset.Asset{tc.scp}}, swept)
			require.NoError(t, err)
			require.False(t, partial)
			require.True(t, ciem.Graded(swept[0]))
			require.Equal(t, tc.admin, swept[0].Metadata[ciem.MetaPrivilegeTier] == ciem.TierAdmin)
			found := false
			for _, path := range result.Paths {
				if path.Rule.ID == "aws-privesc-11" {
					found = true
				}
			}
			require.Equal(t, tc.passRole, found, "PassRole + EC2 respects principal-specific SCP applicability")
		})
	}
}

// The management connector's sweep carries its own SCP sets, so a store read
// is neither needed nor able to make those accounts partial.
func TestFetchSCPAssets_SkipsAccountsCarryingTheirOwn(t *testing.T) {
	_, remote, err := fetchSCPAssets(context.Background(), scpStore{scpErr: errors.New("unused")},
		[]asset.Asset{awsRole("arn:role/a"), readOnlySCP(t)})
	require.NoError(t, err)
	require.Empty(t, remote)
}
