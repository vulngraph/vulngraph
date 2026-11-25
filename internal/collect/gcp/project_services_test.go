package gcp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	accessapproval "google.golang.org/api/accessapproval/v1"
	accesscontextmanager "google.golang.org/api/accesscontextmanager/v1"
	binaryauthorization "google.golang.org/api/binaryauthorization/v1"
	"google.golang.org/api/googleapi"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeProjectServices struct {
	categories     []string
	contactsErr    error
	orgCategories  []string
	orgContactsErr error
	approval       *accessapproval.AccessApprovalSettings
	approvalErr    error
	orgApproval    *accessapproval.AccessApprovalSettings
	orgApprovalErr error
	assetState     string
	stateErr       error
	perimeters     []*accesscontextmanager.ServicePerimeter
	perimeterErr   error
	ancestors      []string
	policy         *binaryauthorization.Policy
	policyCalls    *int
}

func (f fakeProjectServices) ContactCategories(context.Context, string) ([]string, error) {
	return f.categories, f.contactsErr
}
func (f fakeProjectServices) OrgContactCategories(context.Context, string) ([]string, error) {
	return f.orgCategories, f.orgContactsErr
}
func (f fakeProjectServices) AccessApproval(context.Context, string) (*accessapproval.AccessApprovalSettings, error) {
	return f.approval, f.approvalErr
}
func (f fakeProjectServices) OrgAccessApproval(context.Context, string) (*accessapproval.AccessApprovalSettings, error) {
	return f.orgApproval, f.orgApprovalErr
}
func (f fakeProjectServices) ServiceState(context.Context, string, string) (string, error) {
	return f.assetState, f.stateErr
}
func (f fakeProjectServices) Perimeters(context.Context, string) ([]*accesscontextmanager.ServicePerimeter, error) {
	return f.perimeters, f.perimeterErr
}
func (f fakeProjectServices) ProjectNumber(context.Context, string) (string, error) {
	return "123", nil
}
func (f fakeProjectServices) Ancestry(context.Context, string) ([]string, error) {
	return f.ancestors, nil
}
func (f fakeProjectServices) BinAuthzPolicy(context.Context, string) (*binaryauthorization.Policy, error) {
	if f.policyCalls != nil {
		*f.policyCalls++
	}
	return f.policy, nil
}

var (
	serviceDisabled = &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "SERVICE_DISABLED"}}}
	permDenied      = &googleapi.Error{Code: 403, Message: "The caller does not have permission"}
)

// With the organization readable, its contacts and Access Approval land on
// the organization asset; the project records only that it is covered.
func TestCollectProjectServices_OrgReadable(t *testing.T) {
	f := fakeProjectServices{
		categories:    []string{"SECURITY", "TECHNICAL"},
		orgCategories: []string{"SECURITY", "TECHNICAL"},
		approval:      &accessapproval.AccessApprovalSettings{},
		orgApproval:   nil,
		assetState:    "DISABLED",
		ancestors:     []string{"folders/1", "organizations/9"},
		perimeters: []*accesscontextmanager.ServicePerimeter{
			{Name: "accessPolicies/1/servicePerimeters/bridge", PerimeterType: "PERIMETER_TYPE_BRIDGE",
				Status: &accesscontextmanager.ServicePerimeterConfig{Resources: []string{"projects/123"}, RestrictedServices: []string{"storage.googleapis.com"}}},
			{Name: "accessPolicies/1/servicePerimeters/empty", Status: &accesscontextmanager.ServicePerimeterConfig{Resources: []string{"projects/123"}}},
			{Name: "accessPolicies/1/servicePerimeters/prod", Status: &accesscontextmanager.ServicePerimeterConfig{
				Resources: []string{"projects/123"}, RestrictedServices: []string{"bigquery.googleapis.com"}}},
		},
	}
	md, org, err := collectProjectServices(context.Background(), f, "p")
	require.NoError(t, err)
	require.Equal(t, "organizations/9", org.org)
	require.Equal(t, "LEGAL,SUSPENSION,TECHNICAL_INCIDENTS", org.md["essential_contacts_missing"])
	require.Equal(t, "false", org.md["access_approval_enrolled"], "no organization settings is not enrolled")
	require.NotContains(t, md, "essential_contacts_missing", "the organization's gap is reported once, there")
	require.NotContains(t, md, "access_approval_enrolled")
	require.Equal(t, "false", md["cloud_asset_api_enabled"])
	require.Equal(t, "prod", md["vpc_sc_perimeter"], "bridges and perimeters restricting nothing do not protect")

	f.categories = []string{"ALL"}
	f.approval = &accessapproval.AccessApprovalSettings{EnrolledServices: []*accessapproval.EnrolledService{{CloudProduct: "all"}}}
	md, _, err = collectProjectServices(context.Background(), f, "p")
	require.NoError(t, err)
	require.Equal(t, "", md["essential_contacts_missing"], "a project that covers itself says so")
	require.Equal(t, "true", md["access_approval_enrolled"])
}

// Organization reads denied (a project-scoped deployment): the project's
// effective settings are graded on the project, and nothing is partial.
func TestCollectProjectServices_OrgDeniedIsNotPartial(t *testing.T) {
	f := fakeProjectServices{
		categories: []string{"SECURITY"}, orgContactsErr: permDenied,
		approval: &accessapproval.AccessApprovalSettings{EnrolledAncestor: true}, orgApprovalErr: permDenied,
		assetState: "ENABLED", ancestors: []string{"organizations/9"}, perimeterErr: permDenied,
	}
	md, org, err := collectProjectServices(context.Background(), f, "p")
	require.NoError(t, err, "missing organization grants must not flag the sweep partial")
	require.Empty(t, org.md)
	require.Equal(t, "LEGAL,SUSPENSION,TECHNICAL,TECHNICAL_INCIDENTS", md["essential_contacts_missing"])
	require.Equal(t, "true", md["access_approval_enrolled"], "enrolment inherited from an ancestor counts")
	require.NotContains(t, md, "vpc_sc_perimeter", "perimeters unreadable: unknown")

	f.perimeterErr = errors.New("connection reset")
	_, _, err = collectProjectServices(context.Background(), f, "p")
	require.Error(t, err, "a real failure still flags the sweep")
}

func TestCollectProjectServices_DisabledAPIs(t *testing.T) {
	md, _, err := collectProjectServices(context.Background(), fakeProjectServices{
		contactsErr: serviceDisabled, approvalErr: serviceDisabled, assetState: "ENABLED"}, "p")
	require.NoError(t, err, "no organization and disabled APIs are stable facts, not partial reads")
	require.NotContains(t, md, "essential_contacts_missing", "org contacts are unreadable with the API disabled")
	require.NotContains(t, md, "vpc_sc_perimeter", "VPC-SC is an organization feature")
	require.Equal(t, "false", md["access_approval_enrolled"], "Access Approval API disabled is an explicit off")

	_, _, err = collectProjectServices(context.Background(), fakeProjectServices{stateErr: errors.New("boom")}, "p")
	require.Error(t, err)
}

func TestAnnotateBinAuthz(t *testing.T) {
	calls := 0
	policy := &binaryauthorization.Policy{
		DefaultAdmissionRule: &binaryauthorization.AdmissionRule{EvaluationMode: "ALWAYS_ALLOW", EnforcementMode: "ENFORCED_BLOCK_AND_AUDIT_LOG"},
		ClusterAdmissionRules: map[string]binaryauthorization.AdmissionRule{
			"europe-west4.strict": {EvaluationMode: "REQUIRE_ATTESTATION", EnforcementMode: "ENFORCED_BLOCK_AND_AUDIT_LOG"},
			"europe-west4.dryrun": {EvaluationMode: "REQUIRE_ATTESTATION", EnforcementMode: "DRYRUN_AUDIT_LOG_ONLY"},
		},
	}
	cluster := func(name, mode string) asset.Asset {
		return asset.Asset{Type: "gke_cluster", Name: name, Region: "europe-west4", Metadata: map[string]string{"binary_authorization": mode}}
	}
	assets := []asset.Asset{cluster("strict", "PROJECT_SINGLETON_POLICY_ENFORCE"), cluster("dryrun", "PROJECT_SINGLETON_POLICY_ENFORCE"),
		cluster("default", "PROJECT_SINGLETON_POLICY_ENFORCE"), cluster("off", "DISABLED")}
	require.NoError(t, annotateBinAuthz(context.Background(), fakeProjectServices{policy: policy, policyCalls: &calls}, "p", assets))
	require.Equal(t, "false", assets[0].Metadata["binauthz_policy_allows_all"])
	require.Equal(t, "true", assets[1].Metadata["binauthz_policy_allows_all"], "a dry-run rule only logs")
	require.Equal(t, "true", assets[2].Metadata["binauthz_policy_allows_all"])
	require.NotContains(t, assets[3].Metadata, "binauthz_policy_allows_all", "4.5.1 covers a cluster not enforcing")

	calls = 0
	require.NoError(t, annotateBinAuthz(context.Background(), fakeProjectServices{policyCalls: &calls}, "p", []asset.Asset{cluster("off", "DISABLED")}))
	require.Zero(t, calls, "no enforcing cluster, no policy read")
}
