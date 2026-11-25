package aws

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

var errWideThrottled = errors.New("throttling: rate exceeded")

const (
	wideAdminDoc      = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	wideKMSAllDoc     = `{"Statement":[{"Effect":"Allow","Action":["kms:Decrypt"],"Resource":"*"}]}`
	wideReadOnlyDoc   = `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`
	wideCloudShellARN = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
)

// fakeIAMWide pages GetAccountAuthorizationDetails over pages and answers the
// other account-wide reads from its fields.
type fakeIAMWide struct {
	pages      []*iam.GetAccountAuthorizationDetailsOutput
	pageErr    int // page index that fails (-1 none)
	members    map[string]int
	groupErr   map[string]bool
	certs      []iamtypes.ServerCertificateMetadata
	certErr    error
	supportErr error
	support    int
	awsDocs    map[string]string
}

func (f *fakeIAMWide) GetAccountAuthorizationDetails(_ context.Context, in *iam.GetAccountAuthorizationDetailsInput, _ ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	i := 0
	if in.Marker != nil {
		i = int(awssdk.ToString(in.Marker)[0] - '0')
	}
	if i == f.pageErr {
		return nil, errWideThrottled
	}
	out := *f.pages[i]
	if i+1 < len(f.pages) {
		out.IsTruncated, out.Marker = true, awssdk.String(string(rune('0'+i+1)))
	}
	return &out, nil
}

func (f *fakeIAMWide) GetGroup(_ context.Context, in *iam.GetGroupInput, _ ...func(*iam.Options)) (*iam.GetGroupOutput, error) {
	if f.groupErr[awssdk.ToString(in.GroupName)] {
		return nil, errWideThrottled
	}
	return &iam.GetGroupOutput{Users: make([]iamtypes.User, f.members[awssdk.ToString(in.GroupName)])}, nil
}

func (f *fakeIAMWide) ListServerCertificates(context.Context, *iam.ListServerCertificatesInput, ...func(*iam.Options)) (*iam.ListServerCertificatesOutput, error) {
	if f.certErr != nil {
		return nil, f.certErr
	}
	return &iam.ListServerCertificatesOutput{ServerCertificateMetadataList: f.certs}, nil
}

func (f *fakeIAMWide) ListEntitiesForPolicy(_ context.Context, in *iam.ListEntitiesForPolicyInput, _ ...func(*iam.Options)) (*iam.ListEntitiesForPolicyOutput, error) {
	if f.supportErr != nil {
		return nil, f.supportErr
	}
	if in.EntityFilter != iamtypes.EntityTypeRole || awssdk.ToString(in.PolicyArn) != "arn:aws:iam::aws:policy/AWSSupportAccess" {
		return nil, errors.New("unexpected ListEntitiesForPolicy input")
	}
	return &iam.ListEntitiesForPolicyOutput{PolicyRoles: make([]iamtypes.PolicyRole, f.support)}, nil
}

func (f *fakeIAMWide) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	if _, ok := f.awsDocs[awssdk.ToString(in.PolicyArn)]; !ok {
		return nil, errWideThrottled
	}
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{DefaultVersionId: awssdk.String("v1")}}, nil
}

func (f *fakeIAMWide) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
		Document: awssdk.String(url.QueryEscape(f.awsDocs[awssdk.ToString(in.PolicyArn)])),
	}}, nil
}

func wideCustomerPolicy(name, doc string, attached, boundary int32) iamtypes.ManagedPolicyDetail {
	return iamtypes.ManagedPolicyDetail{
		PolicyName: awssdk.String(name), Arn: awssdk.String("arn:aws:iam::1:policy/" + name),
		AttachmentCount: awssdk.Int32(attached), PermissionsBoundaryUsageCount: awssdk.Int32(boundary),
		DefaultVersionId: awssdk.String("v2"),
		PolicyVersionList: []iamtypes.PolicyVersion{
			{VersionId: awssdk.String("v1"), Document: awssdk.String(url.QueryEscape(wideReadOnlyDoc))},
			{VersionId: awssdk.String("v2"), IsDefaultVersion: true, Document: awssdk.String(url.QueryEscape(doc))},
		},
	}
}

func wideGroup(name string, managed []string, inline map[string]string) iamtypes.GroupDetail {
	g := iamtypes.GroupDetail{GroupName: awssdk.String(name), Arn: awssdk.String("arn:aws:iam::1:group/" + name), Path: awssdk.String("/")}
	for _, arn := range managed {
		g.AttachedManagedPolicies = append(g.AttachedManagedPolicies, iamtypes.AttachedPolicy{PolicyArn: awssdk.String(arn), PolicyName: awssdk.String(policyNameFromARN(arn))})
	}
	for n, d := range inline {
		g.GroupPolicyList = append(g.GroupPolicyList, iamtypes.PolicyDetail{PolicyName: awssdk.String(n), PolicyDocument: awssdk.String(url.QueryEscape(d))})
	}
	return g
}

func wideByID(assets []asset.Asset) map[string]asset.Asset {
	out := map[string]asset.Asset{}
	for _, a := range assets {
		out[a.ID] = a
	}
	return out
}

func TestReadIAMAccountWide(t *testing.T) {
	exp := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	f := &fakeIAMWide{
		pageErr: -1,
		pages: []*iam.GetAccountAuthorizationDetailsOutput{
			{
				Policies: []iamtypes.ManagedPolicyDetail{wideCustomerPolicy("home-admin", wideAdminDoc, 0, 0)},
				GroupDetailList: []iamtypes.GroupDetail{
					wideGroup("admins", []string{"arn:aws:iam::1:policy/home-admin"}, nil),
					wideGroup("ops", []string{"arn:aws:iam::aws:policy/AdministratorAccess", wideCloudShellARN}, nil),
				},
			},
			{
				Policies: []iamtypes.ManagedPolicyDetail{wideCustomerPolicy("cap", wideAdminDoc, 0, 3)},
				GroupDetailList: []iamtypes.GroupDetail{
					wideGroup("readers", nil, map[string]string{"kms": wideKMSAllDoc}),
					wideGroup("unread", []string{"arn:aws:iam::aws:policy/Missing"}, nil),
				},
			},
		},
		members:  map[string]int{"admins": 2, "ops": 0, "readers": 1},
		groupErr: map[string]bool{"unread": true},
		certs:    []iamtypes.ServerCertificateMetadata{{Arn: awssdk.String("arn:aws:iam::1:server-certificate/old"), ServerCertificateName: awssdk.String("old"), Expiration: &exp}},
		support:  1,
		awsDocs:  map[string]string{"arn:aws:iam::aws:policy/AdministratorAccess": wideAdminDoc, wideCloudShellARN: wideReadOnlyDoc},
	}
	got := readIAMAccountWide(context.Background(), f, "aws", "1", time.Now())
	require.NoError(t, got.err)
	require.Equal(t, map[string]string{"support_role_count": "1"}, got.settings)
	a := wideByID(got.assets)

	pol := a["arn:aws:iam::1:policy/home-admin"].Metadata
	require.Equal(t, "true", pol["full_admin"], "the DEFAULT version is graded, not the first")
	require.Equal(t, "0", pol["attachment_count"])
	require.Equal(t, "3", a["arn:aws:iam::1:policy/cap"].Metadata["boundary_usage_count"], "the second page is read")

	admins := a["arn:aws:iam::1:group/admins"].Metadata
	require.Equal(t, "true", admins["admin"])
	require.Equal(t, "true", admins["full_admin_customer_policy_only"], "admin only through a customer policy steps aside for the policy finding")
	require.Equal(t, "2", admins["member_count"])

	ops := a["arn:aws:iam::1:group/ops"].Metadata
	require.Equal(t, "true", ops["admin"])
	require.Equal(t, "false", ops["full_admin_customer_policy_only"])
	require.Equal(t, "true", ops["cloudshell_full_access"])
	require.Equal(t, "0", ops["member_count"])

	readers := a["arn:aws:iam::1:group/readers"].Metadata
	require.Equal(t, "false", readers["admin"])
	require.Equal(t, "true", readers["inline_kms_decrypt_all"])
	require.NotContains(t, readers, "full_admin_customer_policy_only")

	unread := a["arn:aws:iam::1:group/unread"].Metadata
	for _, k := range []string{"admin", "policies", "inline_kms_decrypt_all", "cloudshell_full_access", "member_count"} {
		require.NotContains(t, unread, k, "an unread policy document or member list leaves %s unknown", k)
	}

	cert := a["arn:aws:iam::1:server-certificate/old"]
	require.Equal(t, "iam_server_certificate", cert.Type)
	require.Equal(t, "2025-01-01T00:00:00Z", cert.Metadata["expiration"])
}

func TestReadIAMAccountWideFailures(t *testing.T) {
	f := &fakeIAMWide{
		pageErr: 1,
		pages: []*iam.GetAccountAuthorizationDetailsOutput{
			{GroupDetailList: []iamtypes.GroupDetail{wideGroup("g", nil, nil)}},
			{},
		},
		certs:      []iamtypes.ServerCertificateMetadata{{Arn: awssdk.String("c")}},
		supportErr: errWideThrottled,
	}
	got := readIAMAccountWide(context.Background(), f, "aws", "1", time.Now())
	require.Error(t, got.err)
	require.Nil(t, got.settings, "an unread Support-role listing is not 'no support role'")
	a := wideByID(got.assets)
	require.NotContains(t, a, "arn:aws:iam::1:group/g", "a failed later page drops the whole group listing, never a short one")
	require.Contains(t, a, "c", "the server certificates that did read are kept")
	require.NotContains(t, a["c"].Metadata, "expiration")
}
