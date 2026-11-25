package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeSSMDocuments struct {
	docs     []ssmtypes.DocumentIdentifier
	gotOwner []string
	perms    map[string][][]string // name → pages of AccountIds
	permErr  map[string]error
}

func (f *fakeSSMDocuments) ListDocuments(_ context.Context, in *ssm.ListDocumentsInput, _ ...func(*ssm.Options)) (*ssm.ListDocumentsOutput, error) {
	for _, flt := range in.Filters {
		if awssdk.ToString(flt.Key) == "Owner" {
			f.gotOwner = flt.Values
		}
	}
	return &ssm.ListDocumentsOutput{DocumentIdentifiers: f.docs}, nil
}

func (f *fakeSSMDocuments) DescribeDocumentPermission(_ context.Context, in *ssm.DescribeDocumentPermissionInput, _ ...func(*ssm.Options)) (*ssm.DescribeDocumentPermissionOutput, error) {
	name := awssdk.ToString(in.Name)
	if err := f.permErr[name]; err != nil {
		return nil, err
	}
	pages := f.perms[name]
	if len(pages) == 0 {
		return &ssm.DescribeDocumentPermissionOutput{}, nil
	}
	page := 0
	if in.NextToken != nil {
		page = 1
	}
	out := &ssm.DescribeDocumentPermissionOutput{AccountIds: pages[page]}
	if page+1 < len(pages) {
		out.NextToken = awssdk.String("n")
	}
	return out, nil
}

func TestReadSSMDocuments(t *testing.T) {
	f := &fakeSSMDocuments{
		docs: []ssmtypes.DocumentIdentifier{
			{Name: awssdk.String("private"), DocumentType: ssmtypes.DocumentTypeCommand},
			{Name: awssdk.String("public-late"), DocumentType: ssmtypes.DocumentTypeAutomation},
			{Name: awssdk.String("denied")},
			{Name: awssdk.String("public-upper")},
		},
		// "all" on the SECOND permission page: a reader that stopped at one page would miss it.
		perms:   map[string][][]string{"public-late": {{"222222222222"}, {"all"}}, "public-upper": {{"All"}}},
		permErr: map[string]error{"denied": errors.New("AccessDeniedException")},
	}
	got, err := readSSMDocuments(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Equal(t, []string{"Self"}, f.gotOwner, "only account-owned documents can be shared by it")
	m := byID(got)

	priv := m["arn:aws:ssm:eu-west-1:111:document/private"]
	require.Equal(t, ssmDocumentType, priv.Type)
	require.Equal(t, map[string]string{"document_type": "Command", "publicly_shared": "false", "shared_account_count": "0"}, priv.Metadata)

	pub := m["arn:aws:ssm:eu-west-1:111:document/public-late"].Metadata
	require.Equal(t, "true", pub["publicly_shared"])
	require.Equal(t, "2", pub["shared_account_count"])
	require.Equal(t, asset.PublicAccessConfirmed, pub["public_access"])

	require.Equal(t, "true", m["arn:aws:ssm:eu-west-1:111:document/public-upper"].Metadata["publicly_shared"], "the public group is matched case-insensitively")
	require.NotContains(t, m["arn:aws:ssm:eu-west-1:111:document/denied"].Metadata, "publicly_shared",
		"an unread permission is unknown, never private")
}

type fakeSSMSettings struct {
	values map[string]string
	err    error
}

func (f fakeSSMSettings) GetServiceSetting(_ context.Context, in *ssm.GetServiceSettingInput, _ ...func(*ssm.Options)) (*ssm.GetServiceSettingOutput, error) {
	v, ok := f.values[awssdk.ToString(in.SettingId)]
	if !ok {
		return nil, f.err
	}
	return &ssm.GetServiceSettingOutput{ServiceSetting: &ssmtypes.ServiceSetting{SettingValue: awssdk.String(v)}}, nil
}

func TestReadRegionSettingsIncludesSSMServiceSettings(t *testing.T) {
	ctx := context.Background()
	denied := apiErr{code: "AccessDeniedException"}
	notFound := apiErr{code: "ServiceSettingNotFound"}

	got, err := readRegionSettings(ctx, fakeRegionSettings{err: denied}, "eu-west-1", "111", time.Now(), ssmServiceSettingsReader(fakeSSMSettings{
		values: map[string]string{ssmSettingPublicSharing: "Enable", ssmSettingAutomationLogTo: ""},
	}))
	require.NoError(t, err, "the SSM reads alone are enough for an asset")
	require.Equal(t, map[string]string{"ssm_document_public_sharing": "Enable", "ssm_automation_log_destination": ""}, got[0].Metadata,
		"an empty log destination is an observed value: Automation logs nowhere")

	got, err = readRegionSettings(ctx, fakeRegionSettings{ebs: awssdk.Bool(true), err: denied}, "eu-west-1", "111", time.Now(), ssmServiceSettingsReader(fakeSSMSettings{err: notFound}))
	require.NoError(t, err)
	require.Equal(t, map[string]string{"ebs_encryption_by_default": "true"}, got[0].Metadata,
		"a setting AWS reports as not provisioned is unknown, not a default")

	_, err = readRegionSettings(ctx, fakeRegionSettings{err: denied}, "eu-west-1", "111", time.Now(), ssmServiceSettingsReader(fakeSSMSettings{err: denied}))
	require.Error(t, err, "every read denied is still a skipped collector")
}

func (f *fakeSSM) ListResourceComplianceSummaries(_ context.Context, in *ssm.ListResourceComplianceSummariesInput, _ ...func(*ssm.Options)) (*ssm.ListResourceComplianceSummariesOutput, error) {
	var ctype string
	for _, flt := range in.Filters {
		if awssdk.ToString(flt.Key) == "ComplianceType" {
			ctype = flt.Values[0]
		}
	}
	if err := f.complianceErr[ctype]; err != nil {
		return nil, err
	}
	items := f.compliance[ctype]
	// Serve one item per page so pagination is exercised.
	start := 0
	if in.NextToken != nil {
		start = 1
	}
	if start >= len(items) {
		return &ssm.ListResourceComplianceSummariesOutput{}, nil
	}
	out := &ssm.ListResourceComplianceSummariesOutput{ResourceComplianceSummaryItems: items[start : start+1]}
	if start+1 < len(items) {
		out.NextToken = awssdk.String("n")
	}
	return out, nil
}

func TestSSMComplianceStampedOnInstances(t *testing.T) {
	fake := &fakeSSM{
		compliance: map[string][]ssmtypes.ResourceComplianceSummaryItem{
			"Patch": {
				{ResourceId: awssdk.String("i-a"), Status: ssmtypes.ComplianceStatusNonCompliant},
				{ResourceId: awssdk.String("i-b"), Status: ssmtypes.ComplianceStatusCompliant},
			},
		},
		complianceErr: map[string]error{"Association": errors.New("throttled")},
	}
	r := &regionInventory{done: make(chan struct{}), err: errors.New("inventory down"), compliance: readSSMCompliance(context.Background(), fake)}
	close(r.done)
	inst := func(id string) asset.Asset {
		return asset.Asset{ID: id, Type: "ec2_instance", Metadata: map[string]string{}}
	}
	instances := []asset.Asset{inst("i-a"), inst("i-b"), inst("i-none")}
	r.apply(context.Background(), instances, map[string]bool{}, time.Now())

	require.Equal(t, "NON_COMPLIANT", instances[0].Metadata["ssm_patch_compliance"])
	require.Equal(t, "COMPLIANT", instances[1].Metadata["ssm_patch_compliance"], "the second page is read")
	require.NotContains(t, instances[2].Metadata, "ssm_patch_compliance", "no Patch Manager record is ungraded, not compliant")
	for _, i := range instances {
		require.NotContains(t, i.Metadata, "ssm_association_compliance", "a failed listing stamps nothing")
	}
}

func TestSSMCompliancePageCapIsAFailedRead(t *testing.T) {
	endless := &endlessCompliance{}
	_, err := listComplianceSummaries(context.Background(), endless, "Patch")
	require.ErrorIs(t, err, errSSMCompliancePageCap)
	require.Equal(t, ssmComplianceMaxPages, endless.calls)
}

type endlessCompliance struct{ calls int }

func (e *endlessCompliance) ListResourceComplianceSummaries(context.Context, *ssm.ListResourceComplianceSummariesInput, ...func(*ssm.Options)) (*ssm.ListResourceComplianceSummariesOutput, error) {
	e.calls++
	return &ssm.ListResourceComplianceSummariesOutput{NextToken: awssdk.String("more")}, nil
}
