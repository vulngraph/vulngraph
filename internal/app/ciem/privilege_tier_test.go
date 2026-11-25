package ciem

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func identityPolicy(statements string) string {
	return `[{"name":"p","type":"identity","document":"{\"Statement\":[` + statements + `]}"}]`
}

func TestAnalyze_PrivilegeTiers(t *testing.T) {
	const acct = "111111111111"
	admin := roleAsset("arn:aws:iam::111111111111:role/admin", nil,
		identityPolicy(`{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}`))
	admin.Metadata["permission_boundary_complete"] = "true" // observed no boundary
	collectorAdmin := roleAsset("arn:aws:iam::111111111111:role/partial-admin", map[string]string{"admin": "true"}, "")
	delete(collectorAdmin.Metadata, "policies") // a collector hint cannot prove authority from an unread set
	selfGrant := roleAsset("arn:aws:iam::111111111111:role/putter", nil,
		identityPolicy(`{\"Effect\":\"Allow\",\"Action\":\"iam:PutRolePolicy\",\"Resource\":\"*\"}`))
	assumesAdmin := roleAsset("arn:aws:iam::111111111111:role/hopper", nil,
		identityPolicy(`{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Resource\":\"arn:aws:iam::111111111111:role/admin\"}`))
	assumesPlain := roleAsset("arn:aws:iam::111111111111:role/hopper-plain", nil,
		identityPolicy(`{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Resource\":\"arn:aws:iam::111111111111:role/reader\"}`))
	reader := roleAsset("arn:aws:iam::111111111111:role/reader", nil,
		identityPolicy(`{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}`))
	empty := roleAsset("arn:aws:iam::111111111111:role/empty", nil, "[]")
	unread := roleAsset("arn:aws:iam::111111111111:role/unread", nil, "")
	delete(unread.Metadata, "policies")
	// Present but unparseable: not an empty grant set, so never standard.
	garbled := roleAsset("arn:aws:iam::111111111111:role/garbled", nil, `{not json`)
	bucket := asset.Asset{ID: "b-1", Type: "s3_bucket", Provider: asset.ProviderAWS}

	in := []asset.Asset{admin, collectorAdmin, selfGrant, assumesAdmin, assumesPlain, reader, empty, unread, garbled, bucket}
	for i := range in {
		in[i].AccountID = acct
		if in[i].Type == "iam_role" {
			in[i].Metadata["permission_boundary_complete"] = "true"
		}
	}
	in = append(in, orgAsset(t, AWSOrganizationEvidence{AccountID: acct, Applicability: "exempt", Reason: "standalone", Complete: true}))
	res := AnalyzeIAMAssets(context.Background(), in)

	want := map[string]TierVerdict{
		admin.ID:          {TierAdmin, TierSourceCIEM},
		collectorAdmin.ID: {TierUnknown, TierSourceNoPermData},
		selfGrant.ID:      {TierCanEscalateToAdmin, "ciem:aws-privesc-06"},
		assumesAdmin.ID:   {TierCanEscalateToAdmin, "ciem:aws-privesc-15"},
		assumesPlain.ID:   {TierHigh, "ciem:aws-privesc-15"},
		reader.ID:         {TierStandard, TierSourceCIEM},
		empty.ID:          {TierStandard, TierSourceCIEM},
		unread.ID:         {TierUnknown, TierSourceNoPermData},
		garbled.ID:        {TierUnknown, TierSourceNoPermData},
	}
	assert.Equal(t, want, res.Tiers, "every identity gets a tier; a non-identity gets none")

	for _, s := range res.ScoredAssets {
		assert.Equal(t, want[s.ID].Tier, s.Metadata[MetaPrivilegeTier], "re-ingested scored copies must carry the tier")
	}
}

func TestAnalyze_GCPOwnerLabelDoesNotProveAdminTarget(t *testing.T) {
	gcpSA := func(id, roles, perms string) asset.Asset {
		return asset.Asset{ID: id, Type: "gcp_service_account", Provider: asset.ProviderGCP, AccountID: "proj",
			Metadata: map[string]string{"roles": roles, "permissions": perms, "permissions_complete": "true"}}
	}
	tokenMinter := gcpSA("minter", "roles/iam.serviceAccountTokenCreator", "iam.serviceAccounts.getAccessToken")
	owner := gcpSA("owner", "roles/owner", "resourcemanager.projects.setIamPolicy")

	alone := AnalyzeIAMAssets(context.Background(), []asset.Asset{tokenMinter})
	assert.Equal(t, TierHigh, alone.Tiers["minter"].Tier, "no admin in scope: the unbounded path is not proven admin")

	withOwner := AnalyzeIAMAssets(context.Background(), []asset.Asset{tokenMinter, owner})
	assert.Equal(t, TierHigh, withOwner.Tiers["owner"].Tier, "the allow remains an escalation candidate, not proof of admin")
	assert.Equal(t, TierHigh, withOwner.Tiers["minter"].Tier, "uncollected denies and target scope prevent proof that it reaches admin")
	assert.Equal(t, "ciem:gcp-privesc-03", withOwner.Tiers["minter"].Source)

	noPerms := asset.Asset{ID: "bare", Type: "gcp_service_account", Provider: asset.ProviderGCP,
		Metadata: map[string]string{"roles": "roles/viewer"}}
	assert.Equal(t, TierUnknown, AnalyzeIAMAssets(context.Background(), []asset.Asset{noPerms}).Tiers["bare"].Tier)
}

func TestStampTiers_CopiesMetadata(t *testing.T) {
	shared := map[string]string{"k": "v"}
	assets := []asset.Asset{{ID: "a", Metadata: shared}, {ID: "b", Metadata: shared}}
	StampTiers(assets, map[string]TierVerdict{"a": {TierHigh, "ciem:x"}})
	require.Equal(t, "high", assets[0].Metadata[MetaPrivilegeTier])
	assert.Equal(t, "ciem:x", assets[0].Metadata[MetaPrivilegeTierSource])
	assert.NotContains(t, assets[1].Metadata, MetaPrivilegeTier, "stamping one asset must not leak through a shared map")
	assert.NotContains(t, shared, MetaPrivilegeTier)
}

func TestGraded(t *testing.T) {
	tests := []struct {
		name     string
		provider asset.Provider
		md       map[string]string
		want     bool
	}{
		{"never stamped", asset.ProviderAWS, map[string]string{"policies": "[]"}, false},
		{"tier unknown", asset.ProviderAWS, map[string]string{MetaPrivilegeTier: TierUnknown, "policies": "[]"}, false},
		{"organization coverage unknown", asset.ProviderAWS, map[string]string{MetaPrivilegeTier: TierStandard, "policies": "[]"}, false},
		{"standard with policies read", asset.ProviderAWS, map[string]string{MetaPrivilegeTier: TierStandard, "policies": "[]", MetaAWSOrganizationComplete: "true"}, true},
		{"collector admin, permissions unread", asset.ProviderAWS, map[string]string{MetaPrivilegeTier: TierAdmin, MetaPrivilegeTierSource: TierSourceCollector, "admin": "true"}, false},
		{"collector admin, permissions read", asset.ProviderAWS, map[string]string{MetaPrivilegeTier: TierAdmin, MetaPrivilegeTierSource: TierSourceCollector, "policies": "[]", MetaAWSOrganizationComplete: "true"}, true},
		{"gcp reads complete permissions", asset.ProviderGCP, map[string]string{MetaPrivilegeTier: TierHigh, "permissions": "", "permissions_complete": "true"}, true},
		{"gcp legacy completeness unknown", asset.ProviderGCP, map[string]string{MetaPrivilegeTier: TierHigh, "permissions": ""}, false},
		{"gcp without permissions", asset.ProviderGCP, map[string]string{MetaPrivilegeTier: TierHigh, "policies": "[]"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, Graded(asset.Asset{Provider: tt.provider, Metadata: tt.md}))
		})
	}
}
