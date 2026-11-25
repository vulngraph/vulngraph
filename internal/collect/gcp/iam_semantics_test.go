package gcp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const hardeningSA = "serviceAccount:worker@p.iam.gserviceaccount.com"

func TestGCPHardening_LiveCompoundCondition(t *testing.T) {
	for _, expr := range []string{
		`request.time < timestamp("2020-01-01T00:00:00Z") || request.time > timestamp("2021-01-01T00:00:00Z")`,
		`!(request.time < timestamp("2020-01-01T00:00:00Z"))`,
	} {
		t.Run(expr, func(t *testing.T) {
			f := hardeningIAM([]iamBinding{{Role: roleSATokenCreator, Members: []string{hardeningSA}, Resource: "projects/p", Condition: expr}})
			assets, err := withFakeIAMProject(f, "p").collect(context.Background(), nil, at("2026-11-25T12:00:00Z"))
			require.NoError(t, err)
			assert.Contains(t, assets[0].Metadata["permissions"], "iam.serviceAccounts.getAccessToken", "a true compound condition must retain its grant")
			result := ciem.AnalyzeIAMAssets(context.Background(), assets)
			assert.NotEmpty(t, result.Findings)
			t.Logf("condition=%s metadata=%v tier=%v findings=%v", expr, assets[0].Metadata, result.Tiers[hardeningSA], result.Findings)
		})
	}
}

func TestGCPHardening_LimitedIAMAdminCannotDemoteLiveTokenPath(t *testing.T) {
	f := hardeningIAM([]iamBinding{
		{Role: roleSATokenCreator, Members: []string{hardeningSA}, Resource: "projects/p"},
		{Role: "roles/resourcemanager.projectIamAdmin", Members: []string{hardeningSA}, Resource: "projects/p", Condition: `api.getAttribute('iam.googleapis.com/modifiedGrantsByRole', []).hasOnly(['roles/logging.viewer'])`},
	})
	assets, err := withFakeIAMProject(f, "p").collect(context.Background(), nil, at("2026-11-25T12:00:00Z"))
	require.NoError(t, err)
	result := ciem.AnalyzeIAMAssets(context.Background(), assets)
	require.Equal(t, ciem.TierHigh, result.Tiers[hardeningSA].Tier, "limited IAM changes cannot prove escalation to admin")
	for _, f := range result.Findings {
		if f.RuleID == "gcp-privesc-03" {
			t.Logf("conditional roles=%s token-path severity=%s tier=%v", assets[0].Metadata["conditional_roles"], f.Severity, result.Tiers[hardeningSA])
			require.Equal(t, ciem.SeverityCritical, f.Severity)
			return
		}
	}
	t.Fatal("live token path disappeared")
}

func TestGCPHardening_UnreadAncestorCannotProveClean(t *testing.T) {
	f := hardeningIAM(nil)
	f.ancestors = []string{"folders/42"}
	f.policyErr = map[string]error{"folders/42": errors.New("permission denied")}
	assets, err := withFakeIAMProject(f, "p").collect(context.Background(), nil, at("2026-11-25T12:00:00Z"))
	require.NoError(t, err)
	result := ciem.AnalyzeIAMAssets(context.Background(), assets)
	ciem.StampTiers(assets, result.Tiers)
	assert.Equal(t, "false", assets[0].Metadata["permissions_complete"])
	assert.Equal(t, ciem.TierUnknown, result.Tiers[hardeningSA].Tier)
	assert.False(t, ciem.Graded(assets[0]))
	for _, id := range []string{"gcp-iam-sa-separation-of-duties", "gcp-iam-kms-separation-of-duties", "gcp-sa-admin-privileges"} {
		check, ok := checks.Default().ByID(id)
		require.True(t, ok)
		a := assets[1]
		if check.AssetType == "gcp_service_account" {
			a = assets[0]
		}
		assert.False(t, check.Evaluable(a), "%s cannot conclude clean after unread ancestor", id)
	}
	t.Logf("service account=%v project=%v tier=%v", assets[0].Metadata, assets[1].Metadata, result.Tiers[hardeningSA])
}

func TestGCPHardening_RoleReadErrorIsNotEmptyGrant(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"denied", `{"error":{"code":403,"message":"denied"}}`, http.StatusForbidden},
		{"empty success", `{}`, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := safenet.NewInternal(time.Second)
			client.Transport = gcsPreventionTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				body, status := tc.body, tc.status
				if calls > 1 {
					body, status = `{"name":"projects/p/roles/custom","includedPermissions":["iam.serviceAccounts.getAccessToken"]}`, http.StatusOK
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			svc, err := iam.NewService(context.Background(), option.WithHTTPClient(client))
			require.NoError(t, err)
			r := &realIAM{iamSvc: svc, cache: map[string][]string{}}
			_, err = r.RolePermissions(context.Background(), "projects/p/roles/custom")
			require.Error(t, err)
			require.Empty(t, r.cache)
			perms, err := r.RolePermissions(context.Background(), "projects/p/roles/custom")
			require.NoError(t, err)
			require.Equal(t, []string{"iam.serviceAccounts.getAccessToken"}, perms, "an unread role must be retryable")
			require.Equal(t, 2, calls)
		})
	}
}

type failedRoleIAM struct {
	iamAPI
	role string
}

func (f failedRoleIAM) RolePermissions(ctx context.Context, role string) ([]string, error) {
	if role == f.role {
		return nil, errors.New("permission denied")
	}
	return f.iamAPI.RolePermissions(ctx, role)
}

func TestGCPHardening_PartialRoleReadRetainsKnownCandidate(t *testing.T) {
	f := hardeningIAM([]iamBinding{
		{Role: roleSATokenCreator, Members: []string{hardeningSA}, Resource: "projects/p"},
		{Role: "projects/p/roles/unread", Members: []string{hardeningSA}, Resource: "projects/p"},
	})
	assets, err := withFakeIAMProject(failedRoleIAM{iamAPI: f, role: "projects/p/roles/unread"}, "p").collect(context.Background(), nil, at("2026-11-25T12:00:00Z"))
	require.NoError(t, err)
	require.Equal(t, "true", assets[0].Metadata["roles_complete"])
	require.Equal(t, "false", assets[0].Metadata["permissions_complete"])
	result := ciem.AnalyzeIAMAssets(context.Background(), assets)
	require.Equal(t, ciem.TierUnknown, result.Tiers[hardeningSA].Tier)
	require.Len(t, result.Findings, 1)
	require.Equal(t, "gcp-privesc-03", result.Findings[0].RuleID)
	require.Equal(t, ciem.SeverityCritical, result.Findings[0].Severity)
}

func TestGCPHardening_PartialPolicyRetainsPositiveEvidence(t *testing.T) {
	bindings := []iamBinding{
		{Role: roleSAAdmin, Members: []string{"user:admin@gmail.com"}, Resource: "projects/p"},
		{Role: roleSAUser, Members: []string{"user:admin@gmail.com"}, Resource: "projects/p"},
	}
	a := projectAsset("p", effectiveIAM{bindings: bindings, ancestorsComplete: false}, at("2026-11-25T12:00:00Z"))
	require.Equal(t, "user:admin@gmail.com", a.Metadata["consumer_account_members"])
	require.Equal(t, "user:admin@gmail.com", a.Metadata["sa_admin_user_members"])
	require.NotContains(t, a.Metadata, "kms_admin_crypto_members")
	check, ok := checks.Default().ByID("gcp-iam-sa-separation-of-duties")
	require.True(t, ok)
	require.True(t, check.Violates(a))
}

func TestGCPHardening_TimeBoundProofIsExact(t *testing.T) {
	now := at("2026-11-25T12:00:00Z")
	for _, tc := range []struct {
		expr    string
		expired bool
	}{
		{`request.time < timestamp("2026-11-25T12:00:00Z")`, true},
		{`request.time <= timestamp("2026-11-25T12:00:00Z")`, false},
		{`request.time > timestamp("2026-11-25T12:00:00Z")`, true},
		{`request.time >= timestamp("2026-11-25T12:00:00Z")`, false},
		{`request.time < timestamp('2020-01-01T00:00:00Z')`, true},
		{`request.time < timestamp("2020-01-01T00:00:00Z") && resource.name == "x"`, false},
		{`resource.name == 'request.time < timestamp("2020-01-01T00:00:00Z")'`, false},
	} {
		require.Equal(t, tc.expired, conditionExpired(tc.expr, now), tc.expr)
	}
}

func TestGCPHardening_CompleteEmptyPolicyRemainsEvaluable(t *testing.T) {
	assets, err := withFakeIAMProject(hardeningIAM(nil), "p").collect(context.Background(), nil, at("2026-11-25T12:00:00Z"))
	require.NoError(t, err)
	result := ciem.AnalyzeIAMAssets(context.Background(), assets)
	ciem.StampTiers(assets, result.Tiers)
	require.Equal(t, ciem.TierStandard, result.Tiers[hardeningSA].Tier)
	require.True(t, ciem.Graded(assets[0]))
	for _, a := range assets {
		id := "gcp-sa-admin-privileges"
		if a.Type == "cloud_account" {
			id = "gcp-iam-sa-separation-of-duties"
		}
		check, ok := checks.Default().ByID(id)
		require.True(t, ok)
		require.True(t, check.Evaluable(a))
	}
}

func TestGCPHardening_PartialRolesDoNotDisableIndependentChecks(t *testing.T) {
	a := asset.Asset{Type: "gcp_service_account", Provider: asset.ProviderGCP, Metadata: map[string]string{
		"roles_complete": "false", "permissions_complete": "false", "key_exposed": "false",
	}}
	check, ok := checks.Default().ByID("gcp-sa-key-exposed")
	require.True(t, ok)
	require.True(t, check.Evaluable(a), "an observed independent key fact remains usable")
}

func TestGCPHardening_AncestryRequiresCompleteShape(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		want           []string
		wantErr        bool
	}{
		{"empty response", `{}`, nil, true},
		{"missing ancestor id", `{"ancestor":[{"resourceId":{"type":"project","id":"1"}},{"resourceId":{"type":"organization"}}]}`, nil, true},
		{"unrecognized ancestor", `{"ancestor":[{"resourceId":{"type":"project","id":"1"}},{"resourceId":{"type":"unexpected","id":"2"}}]}`, nil, true},
		{"folder without root", `{"ancestor":[{"resourceId":{"type":"project","id":"1"}},{"resourceId":{"type":"folder","id":"2"}}]}`, nil, true},
		{"standalone project", `{"ancestor":[{"resourceId":{"type":"project","id":"1"}}]}`, nil, false},
		{"complete hierarchy", `{"ancestor":[{"resourceId":{"type":"project","id":"1"}},{"resourceId":{"type":"folder","id":"2"}},{"resourceId":{"type":"organization","id":"3"}}]}`, []string{"folders/2", "organizations/3"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := safenet.NewInternal(time.Second)
			client.Transport = gcsPreventionTransport(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(tc.response))}, nil
			})
			svc, err := cloudresourcemanager.NewService(context.Background(), option.WithHTTPClient(client))
			require.NoError(t, err)
			r := &realIAM{rmSvc: svc}
			parents, err := r.Ancestry(context.Background(), "p")
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, parents)
			}
		})
	}
}

func hardeningIAM(bindings []iamBinding) *fakeIAM {
	return &fakeIAM{
		accounts: []gcpServiceAccount{{Email: strings.TrimPrefix(hardeningSA, "serviceAccount:")}},
		policies: map[string][]iamBinding{"projects/p": bindings},
		rolePerms: map[string][]string{
			roleSATokenCreator:                      {"iam.serviceAccounts.getAccessToken"},
			"roles/resourcemanager.projectIamAdmin": {"resourcemanager.projects.getIamPolicy", "resourcemanager.projects.setIamPolicy"},
		},
	}
}
