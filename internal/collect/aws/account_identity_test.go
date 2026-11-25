package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	s3ctypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func trail(multi, logging string) asset.Asset {
	md := map[string]string{"multi_region": multi}
	if logging != "" {
		md["is_logging"] = logging
	}
	return asset.Asset{Type: "aws_cloudtrail", Metadata: md}
}

// The account-level rollup reports what per-trail grading could not: no
// trail at all, and a single-region trail with no multi-region one beside it.
func TestTrailRollupSettings(t *testing.T) {
	tests := []struct {
		name   string
		trails []asset.Asset
		want   string // "" = unknown (key absent)
	}{
		{"no trail", nil, "false"},
		{"single-region only", []asset.Asset{trail("false", "true")}, "false"},
		{"multi-region logging beside a single-region one", []asset.Asset{trail("false", "true"), trail("true", "true")}, "true"},
		{"multi-region stopped", []asset.Asset{trail("true", "false")}, "false"},
		{"multi-region status unread", []asset.Asset{trail("true", "")}, ""},
		{"unread one settled by a logging one", []asset.Asset{trail("true", ""), trail("true", "true")}, "true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trailRollupSettings(tt.trails)
			v, ok := got["cloudtrail_multi_region_logging"]
			require.Equal(t, tt.want != "", ok)
			require.Equal(t, tt.want, v)
		})
	}
}

func TestAccountBPASettings(t *testing.T) {
	require.Nil(t, accountBPASettings(accountBPA{}), "an unread account block writes nothing")
	require.Equal(t, "false", accountBPASettings(accountBPA{observed: true})["s3_bpa_all_enabled"], "no block is all four off")
	two := &s3types.PublicAccessBlockConfiguration{IgnorePublicAcls: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true)}
	got := accountBPASettings(accountBPA{observed: true, cfg: two})
	require.Equal(t, "false", got["s3_bpa_all_enabled"], "the two neutralizing flags are not all four")
	require.Equal(t, "true", got["s3_bpa_ignore_public_acls"])
	t4 := awssdk.Bool(true)
	all := &s3types.PublicAccessBlockConfiguration{BlockPublicAcls: t4, IgnorePublicAcls: t4, BlockPublicPolicy: t4, RestrictPublicBuckets: t4}
	require.Equal(t, "true", accountBPASettings(accountBPA{observed: true, cfg: all})["s3_bpa_all_enabled"])
}

type fakePasswordPolicy struct {
	out *iam.GetAccountPasswordPolicyOutput
	err error
}

func (f fakePasswordPolicy) GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	return f.out, f.err
}

type fakeAlternateContact struct {
	out *account.GetAlternateContactOutput
	err error
}

func (f fakeAlternateContact) GetAlternateContact(context.Context, *account.GetAlternateContactInput, ...func(*account.Options)) (*account.GetAlternateContactOutput, error) {
	return f.out, f.err
}

func TestReadPasswordPolicy(t *testing.T) {
	ctx := context.Background()

	s := newAccountSettings()
	require.NoError(t, readPasswordPolicy(ctx, fakePasswordPolicy{err: apiErr{code: "NoSuchEntity"}}, s))
	require.Equal(t, "absent", s.meta["password_policy"], "no policy is an observation")

	s = newAccountSettings()
	require.NoError(t, readPasswordPolicy(ctx, fakePasswordPolicy{out: &iam.GetAccountPasswordPolicyOutput{PasswordPolicy: &iamtypes.PasswordPolicy{
		MinimumPasswordLength: awssdk.Int32(8), RequireSymbols: true,
	}}}, s))
	require.Equal(t, "present", s.meta["password_policy"])
	require.Equal(t, "8", s.meta["password_min_length"])
	require.Equal(t, "0", s.meta["password_reuse_prevention"], "an unset reuse prevention is an observed 0")
	require.Equal(t, "true", s.meta["password_require_symbols"])
	require.Equal(t, "false", s.meta["password_require_numbers"])

	s = newAccountSettings()
	require.Error(t, readPasswordPolicy(ctx, fakePasswordPolicy{err: apiErr{code: "AccessDenied"}}, s))
	require.Empty(t, s.meta, "a denied read writes nothing")
}

func TestReadSecurityContact(t *testing.T) {
	ctx := context.Background()

	s := newAccountSettings()
	require.NoError(t, readSecurityContact(ctx, fakeAlternateContact{err: apiErr{code: "ResourceNotFoundException"}}, s))
	require.Equal(t, "false", s.meta["security_contact"])

	s = newAccountSettings()
	require.NoError(t, readSecurityContact(ctx, fakeAlternateContact{out: &account.GetAlternateContactOutput{
		AlternateContact: &accounttypes.AlternateContact{EmailAddress: awssdk.String("sec@example.com")},
	}}, s))
	require.Equal(t, "true", s.meta["security_contact"])

	s = newAccountSettings()
	require.Error(t, readSecurityContact(ctx, fakeAlternateContact{err: apiErr{code: "AccessDeniedException"}}, s))
	_, present := s.meta["security_contact"]
	require.False(t, present, "a denied read is unknown, not 'no contact'")
}

// The asset is emitted even with no keys, so an open account-wide finding is
// held open (unevaluable) instead of closed because its resource vanished.
func TestAccountSettingsAssetAlwaysEmitted(t *testing.T) {
	a := newAccountSettings().asset("111", time.Now())
	require.Equal(t, "aws:111:account-settings", a.ID)
	require.Equal(t, accountSettingsType, a.Type)
	require.Empty(t, a.Metadata)
}

type fakeRegionSettings struct {
	ebs     *bool
	snap    ec2types.SnapshotBlockPublicAccessState
	vpcMode ec2types.InternetGatewayBlockMode
	err     error
}

func (f fakeRegionSettings) GetEbsEncryptionByDefault(context.Context, *ec2.GetEbsEncryptionByDefaultInput, ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
	if f.ebs == nil {
		return nil, f.err
	}
	return &ec2.GetEbsEncryptionByDefaultOutput{EbsEncryptionByDefault: f.ebs}, nil
}

func (f fakeRegionSettings) GetSnapshotBlockPublicAccessState(context.Context, *ec2.GetSnapshotBlockPublicAccessStateInput, ...func(*ec2.Options)) (*ec2.GetSnapshotBlockPublicAccessStateOutput, error) {
	if f.snap == "" {
		return nil, f.err
	}
	return &ec2.GetSnapshotBlockPublicAccessStateOutput{State: f.snap}, nil
}

func (f fakeRegionSettings) DescribeVpcBlockPublicAccessOptions(context.Context, *ec2.DescribeVpcBlockPublicAccessOptionsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcBlockPublicAccessOptionsOutput, error) {
	if f.vpcMode == "" {
		return nil, f.err
	}
	return &ec2.DescribeVpcBlockPublicAccessOptionsOutput{VpcBlockPublicAccessOptions: &ec2types.VpcBlockPublicAccessOptions{InternetGatewayBlockMode: f.vpcMode}}, nil
}

func TestReadRegionSettings(t *testing.T) {
	ctx := context.Background()
	denied := apiErr{code: "UnauthorizedOperation"}

	got, err := readRegionSettings(ctx, fakeRegionSettings{ebs: awssdk.Bool(false), snap: "unblocked", vpcMode: "off"}, "eu-west-1", "111", time.Now(), ssmServiceSettingsReader(fakeSSMSettings{err: denied}))
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "aws:111:eu-west-1:region-settings", got[0].ID)
	require.Equal(t, "eu-west-1", got[0].Region)
	require.Equal(t, map[string]string{"ebs_encryption_by_default": "false", "snapshot_block_public_access": "unblocked", "vpc_block_public_access": "off"}, got[0].Metadata)

	got, err = readRegionSettings(ctx, fakeRegionSettings{ebs: awssdk.Bool(true), err: denied}, "eu-west-1", "111", time.Now(), ssmServiceSettingsReader(fakeSSMSettings{err: denied}))
	require.NoError(t, err, "one successful read is an asset")
	require.Equal(t, map[string]string{"ebs_encryption_by_default": "true"}, got[0].Metadata, "failed reads leave their keys absent")

	_, err = readRegionSettings(ctx, fakeRegionSettings{err: denied}, "eu-west-1", "111", time.Now(), ssmServiceSettingsReader(fakeSSMSettings{err: denied}))
	require.Error(t, err, "every read denied is a skipped collector, so a region-deny SCP is still recognised")
}

type fakeRootDetails struct {
	devices  []iamtypes.VirtualMFADevice
	mfaErr   error
	report   string
	state    iamtypes.ReportStateType
	genCalls int
}

func (f *fakeRootDetails) ListVirtualMFADevices(context.Context, *iam.ListVirtualMFADevicesInput, ...func(*iam.Options)) (*iam.ListVirtualMFADevicesOutput, error) {
	if f.mfaErr != nil {
		return nil, f.mfaErr
	}
	return &iam.ListVirtualMFADevicesOutput{VirtualMFADevices: f.devices}, nil
}

func (f *fakeRootDetails) GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	f.genCalls++
	return &iam.GenerateCredentialReportOutput{State: f.state}, nil
}

func (f *fakeRootDetails) GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	return &iam.GetCredentialReportOutput{Content: []byte(f.report)}, nil
}

const credReportHeader = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n"

func TestRootDetails(t *testing.T) {
	ctx := context.Background()
	f := &fakeRootDetails{
		devices: []iamtypes.VirtualMFADevice{
			{SerialNumber: awssdk.String("arn:aws:iam::111:mfa/alice"), User: &iamtypes.User{Arn: awssdk.String("arn:aws:iam::111:user/alice")}},
			{SerialNumber: awssdk.String("arn:aws:iam::111:mfa/root-account-mfa-device")},
		},
		state: iamtypes.ReportStateTypeComplete,
		report: credReportHeader +
			"<root_account>,arn:aws:iam::111:root,2019-01-01T00:00:00+00:00,true,2026-09-01T10:00:00+00:00,not_supported,not_supported,true,false,N/A,2026-10-01T08:00:00+00:00,false,N/A,N/A\n" +
			"alice,arn:aws:iam::111:user/alice,2020-01-01T00:00:00+00:00,true,2026-10-08T00:00:00+00:00,N/A,N/A,true,false,N/A,N/A,false,N/A,N/A\n",
	}
	md := map[string]string{}
	rootDetails(ctx, f, "aws", "111", md)
	require.Equal(t, "true", md["root_virtual_mfa"])
	require.Equal(t, "2026-10-01T08:00:00Z", md["root_last_used"], "latest of password and key use, from the root row only")
	require.Equal(t, "true", md["console_access"], "root has a password")
	require.NoError(t, rootDetailError(md))

	never := &fakeRootDetails{state: iamtypes.ReportStateTypeComplete,
		report: credReportHeader + "<root_account>,arn:aws:iam::111:root,2019-01-01T00:00:00+00:00,not_supported,no_information,not_supported,not_supported,true,false,N/A,N/A,false,N/A,N/A\n"}
	md = map[string]string{}
	rootDetails(ctx, never, "aws", "111", md)
	require.Equal(t, "false", md["root_virtual_mfa"], "no virtual device for root: hardware or none")
	require.Equal(t, "", md["root_last_used"], "observed never-used")
	require.NotContains(t, md, "console_access", "not_supported says nothing about the root password")
	require.Error(t, rootDetailError(md), "an unread password is logged")

	denied := &fakeRootDetails{mfaErr: apiErr{code: "AccessDenied"}, state: iamtypes.ReportStateTypeComplete, report: "garbage"}
	md = map[string]string{}
	rootDetails(ctx, denied, "aws", "111", md)
	require.Empty(t, md, "unreadable details write nothing")
	require.Error(t, rootDetailError(md))
}

// rootCredentialReport is a credential report whose root row carries the given
// password_enabled and mfa_active values.
func rootCredentialReport(password, mfa string) string {
	return credReportHeader + "<root_account>,arn:aws:iam::111:root,2019-01-01T00:00:00+00:00," + password +
		",N/A,N/A,not_supported," + mfa + ",false,N/A,N/A,false,N/A,N/A\n"
}

func TestRootDetailsPasswordEnabled(t *testing.T) {
	tests := []struct {
		name    string
		report  string
		state   iamtypes.ReportStateType
		want    string
		present bool
	}{
		{"root password", rootCredentialReport("true", "false"), iamtypes.ReportStateTypeComplete, "true", true},
		{"uppercase as documented", rootCredentialReport("TRUE", "true"), iamtypes.ReportStateTypeComplete, "true", true},
		{"root credentials removed", rootCredentialReport("false", "false"), iamtypes.ReportStateTypeComplete, "false", true},
		{"not_supported is not an observation", rootCredentialReport("not_supported", "false"), iamtypes.ReportStateTypeComplete, "", false},
		{"no root row", credReportHeader + "alice,arn:aws:iam::111:user/alice,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,false,false,N/A,N/A,false,N/A,N/A\n", iamtypes.ReportStateTypeComplete, "", false},
		{"no password column", "user,arn\n<root_account>,arn:aws:iam::111:root\n", iamtypes.ReportStateTypeComplete, "", false},
		{"report never completes", rootCredentialReport("true", "false"), iamtypes.ReportStateTypeInprogress, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if tt.state != iamtypes.ReportStateTypeComplete {
				cancel()
			}
			defer cancel()
			md := map[string]string{}
			rootDetails(ctx, &fakeRootDetails{state: tt.state, report: tt.report}, "aws", "111", md)
			got, ok := md["console_access"]
			require.Equal(t, tt.present, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCredentialReportStopsOnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fakeRootDetails{state: iamtypes.ReportStateTypeInprogress}
	_, ok := credentialReport(ctx, f)
	require.False(t, ok)
	require.Equal(t, 1, f.genCalls, "a cancelled sweep does not keep polling")
}

func TestIdentityGrantFacts(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want grantFacts
		ok   bool
	}{
		{"full admin", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, grantFacts{fullAdmin: true, kmsDecryptAll: true}, true},
		{"*:* is full admin", `{"Statement":[{"Effect":"Allow","Action":"*:*","Resource":"*"}]}`, grantFacts{fullAdmin: true, kmsDecryptAll: true}, true},
		{"admin scoped to a resource is not full admin", `{"Statement":{"Effect":"Allow","Action":["*"],"Resource":"arn:aws:s3:::b"}}`, grantFacts{}, true},
		{"service wildcards", `{"Statement":[{"Effect":"Allow","Action":["S3:*","ec2:Describe*","iam:*","s3:*"],"Resource":"arn:aws:s3:::b"}]}`, grantFacts{serviceWildcards: []string{"iam:*", "s3:*"}}, true},
		{"kms decrypt on all keys", `{"Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":["*"]}]}`, grantFacts{kmsDecryptAll: true}, true},
		{"kms wildcard covers decrypt", `{"Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*"}]}`, grantFacts{kmsDecryptAll: true, serviceWildcards: []string{"kms:*"}}, true},
		{"kms decrypt on one key", `{"Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"arn:aws:kms:us-east-1:111:key/k"}]}`, grantFacts{}, true},
		{"deny is not a grant", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`, grantFacts{}, true},
		{"NotAction is not read as *", `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`, grantFacts{}, true},
		{"unparseable", `{`, grantFacts{}, false},
		{"empty", ``, grantFacts{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := identityGrantFacts(tt.doc)
			require.Equal(t, tt.ok, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestPrincipalGrantMetadata(t *testing.T) {
	require.Nil(t, (&principalPolicies{complete: false}).grantMetadata(), "an incomplete set supports nothing")
	require.Equal(t, map[string]string{"cloudshell_full_access": "true"},
		(&principalPolicies{complete: false, cloudShell: true}).grantMetadata(), "a listed attachment is still an observation")

	got := (&principalPolicies{complete: true, customerFullAdmin: true}).grantMetadata()
	require.Equal(t, "true", got["full_admin_customer_policy_only"])
	require.Equal(t, "false", got["inline_kms_decrypt_all"])
	require.Equal(t, "false", got["cloudshell_full_access"])

	got = (&principalPolicies{complete: true, customerFullAdmin: true, otherFullAdmin: true}).grantMetadata()
	require.Equal(t, "false", got["full_admin_customer_policy_only"], "an AWS-managed or inline admin grant is the principal's own finding")

	_, present := (&principalPolicies{complete: true}).grantMetadata()["full_admin_customer_policy_only"]
	require.False(t, present)
}

// AdministratorAccess is AWS-managed: the role's admin is its own finding, and
// the policy asset carries the document facts.
func TestRolePoliciesStampPolicyFacts(t *testing.T) {
	pp := rolePolicies(context.Background(), fakeIAM{}, newManagedPolicyCache(fakeIAM{}), "admin-role", "arn:aws:iam::1:role/admin-role", "1", time.Now())
	require.True(t, pp.complete)
	require.Len(t, pp.assets, 1)
	md := pp.assets[0].Metadata
	require.Equal(t, "aws", md["managed_by"])
	require.Equal(t, "true", md["full_admin"])
	require.Equal(t, "false", pp.grantMetadata()["full_admin_customer_policy_only"])
}

func TestDedupePolicyAssetsKeepsRichest(t *testing.T) {
	thin := asset.Asset{ID: "arn:p", Type: "iam_policy", Metadata: map[string]string{"policy_arn": "arn:p"}}
	rich := asset.Asset{ID: "arn:p", Type: "iam_policy", Metadata: map[string]string{"policy_arn": "arn:p", "full_admin": "true"}}
	role := asset.Asset{ID: "arn:r", Type: "iam_role"}
	got := dedupePolicyAssets([]asset.Asset{thin, role, rich})
	require.Len(t, got, 2)
	require.Equal(t, "true", got[0].Metadata["full_admin"], "the copy whose document was read wins")
	require.Equal(t, "iam_role", got[1].Type)
}

func TestS3PolicyGrades(t *testing.T) {
	const tlsDeny = `{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::b","arn:aws:s3:::b/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}`
	tests := []struct {
		name       string
		doc        string
		tls, cross bool
	}{
		{"no policy", ``, false, false},
		{"tls deny", `{"Statement":[` + tlsDeny + `]}`, true, false},
		{"tls deny as bool literal", `{"Statement":{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"*","Resource":"*","Condition":{"BoolIfExists":{"aws:securetransport":false}}}}`, true, false},
		{"deny on GetObject only", `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, false, false},
		{"deny on objects but not the bucket", `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, false, false},
		{"deny on another bucket", `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::other","arn:aws:s3:::other/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, false, false},
		{"deny narrowed by another condition", `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"},"StringEquals":{"aws:SourceVpce":"vpce-1"}}}]}`, false, false},
		{"deny on secure transport true is not enforcement", `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`, false, false},
		{"string condition is not the bool operator", `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:SecureTransport":"false"}}}]}`, false, false},
		{"deny for one principal only", `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::111:root"},"Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, false, false},
		{"other account may rewrite the policy", `{"Statement":[` + tlsDeny + `,{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"s3:PutBucketPolicy","Resource":"arn:aws:s3:::b"}]}`, true, true},
		{"other account by bare id with wildcard", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["222222222222"]},"Action":"s3:Put*","Resource":"arn:aws:s3:::b/*"}]}`, false, true},
		{"other account read-only", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`, false, false},
		{"own account may", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/r"},"Action":"s3:*","Resource":"*"}]}`, false, false},
		{"anyone, org-conditioned", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:PutObjectAcl","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}]}`, false, false},
		{"anyone, unconditioned", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:PutObjectAcl","Resource":"*"}]}`, false, true},
		{"anyone over TLS", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:PutObjectAcl","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`, false, true},
		{"everyone but one role", `{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::111111111111:role/r"},"Action":"s3:PutBucketPolicy","Resource":"arn:aws:s3:::b"}]}`, false, true},
		{"anyone, every action but reads", `{"Statement":[{"Effect":"Allow","Principal":"*","NotAction":"s3:Get*","Resource":"*"}]}`, false, true},
		{"anyone, outside the org", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:PutObjectAcl","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"o-1"}}}]}`, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tls, cross := s3PolicyGrades(tt.doc, "b", "111111111111")
			require.Equal(t, tt.tls, tls, "tls")
			require.Equal(t, tt.cross, cross, "cross")
		})
	}
}

func bucketMeta(t *testing.T, f *fakeS3, acct accountBPA) map[string]map[string]string {
	t.Helper()
	got, _, _, err := collectS3Buckets(context.Background(), f, acct, "111111111111", time.Now())
	require.NoError(t, err)
	out := map[string]map[string]string{}
	for _, a := range got {
		out[a.Name] = a.Metadata
	}
	return out
}

func TestCollectS3Buckets_PolicyFacts(t *testing.T) {
	f := &fakeS3{
		buckets: []s3types.Bucket{{Name: awssdk.String("enforced")}, {Name: awssdk.String("none")}},
		policy:  map[string]string{"enforced": `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::enforced","arn:aws:s3:::enforced/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`},
	}
	md := bucketMeta(t, f, accountBPA{})
	require.Equal(t, "true", md["enforced"]["policy_tls_enforced"])
	require.Equal(t, "false", md["none"]["policy_tls_enforced"], "NoSuchBucketPolicy is an observed none")

	f.policyErr = apiErr{code: "AccessDenied"}
	md = bucketMeta(t, f, accountBPA{})
	_, present := md["none"]["policy_tls_enforced"]
	require.False(t, present, "a denied policy read is unknown")
}

// The four-flag verdict: two neutralizing flags make a bucket non-public but
// leave Block Public Access incomplete, which the old grading read as safe.
func TestCollectS3Buckets_BPAAllEnabled(t *testing.T) {
	buckets := []s3types.Bucket{{Name: awssdk.String("own-block")}, {Name: awssdk.String("no-block")}, {Name: awssdk.String("denied")}}
	f := &fakeS3{buckets: buckets, blocked: map[string]bool{"own-block": true}, pubDenied: map[string]bool{"denied": true}}

	neutralizing := fetchAccountBPA(context.Background(), &fakeS3Control{cfg: &s3ctypes.PublicAccessBlockConfiguration{
		IgnorePublicAcls: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true),
	}}, "111111111111")
	md := bucketMeta(t, f, neutralizing)
	require.Equal(t, "true", md["own-block"]["bpa_all_enabled"])
	require.Equal(t, "false", md["no-block"]["bpa_all_enabled"], "neutralized but two flags off")
	require.Equal(t, "false", md["no-block"]["public"], "still not public")
	_, present := md["denied"]["bpa_all_enabled"]
	require.False(t, present, "the bucket's own block was unread")

	full := fetchAccountBPA(context.Background(), &fakeS3Control{cfg: allOn()}, "111111111111")
	md = bucketMeta(t, f, full)
	for name, m := range md {
		require.Equal(t, "true", m["bpa_all_enabled"], "%s: a full account block covers every bucket", name)
	}

	md = bucketMeta(t, f, accountBPA{})
	require.Equal(t, "true", md["own-block"]["bpa_all_enabled"], "the bucket's own full block settles it")
	_, present = md["no-block"]["bpa_all_enabled"]
	require.False(t, present, "an unread account block may still be full")
}

func TestCloudTrailEncryptionAndLogGroupObserved(t *testing.T) {
	const arn = "arn:aws:cloudtrail:us-east-1:111:trail/t"
	f := &fakeCloudTrail{
		trails:        []cttypes.Trail{{TrailARN: awssdk.String(arn), Name: awssdk.String("t"), HomeRegion: awssdk.String("us-east-1")}},
		statusRegions: map[string]string{},
	}
	got, err := collectCloudTrailTrails(context.Background(), f, "global", "111", time.Now())
	require.NoError(t, err)
	md := got[0].Metadata
	v, ok := md["kms_key_id"]
	require.True(t, ok)
	require.Empty(t, v, "no KmsKeyId is an observed none")
	v, ok = md["cloudwatch_log_group"]
	require.True(t, ok)
	require.Empty(t, v)
}

func TestRotationIntervalDays(t *testing.T) {
	tests := []struct {
		name  string
		rules *smtypes.RotationRulesType
		want  int
		ok    bool
	}{
		{"nil", nil, 0, false},
		{"after days", &smtypes.RotationRulesType{AutomaticallyAfterDays: awssdk.Int64(30)}, 30, true},
		{"rate days", &smtypes.RotationRulesType{ScheduleExpression: awssdk.String("rate(10 days)")}, 10, true},
		{"rate hours", &smtypes.RotationRulesType{ScheduleExpression: awssdk.String("rate(4 hours)")}, 0, false},
		{"cron", &smtypes.RotationRulesType{ScheduleExpression: awssdk.String("cron(0 16 1,15 * ? *)")}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := rotationIntervalDays(tt.rules)
			require.Equal(t, tt.ok, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestOrEmpty(t *testing.T) {
	require.ErrorIs(t, orEmpty(nil), errEmptyResponse)
	e := errors.New("x")
	require.Equal(t, e, orEmpty(e))
}
