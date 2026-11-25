package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

var errFakeDenied = errors.New("AccessDeniedException")

// fakeBackup serves vaults in pages of one, a policy per vault name, and
// recovery points in pages of one.
type fakeBackup struct {
	vaults      []backuptypes.BackupVaultListMember
	vaultPage2  error // error answering the second vault page
	policies    map[string]string
	policyErr   map[string]error
	points      map[string][]backuptypes.RecoveryPointByBackupVault
	pointsErr   error
	plans       []backuptypes.BackupPlansListMember
	plansErr    error
	selections  map[string][]backuptypes.BackupSelection // plan id → selections
	selectErr   error
	optIn       map[string]bool
	settingsErr error
}

func fakePage(token *string) int {
	if token == nil {
		return 0
	}
	var n int
	for _, c := range *token {
		n = n*10 + int(c-'0')
	}
	return n
}

func fakeNextToken(i, n int) *string {
	if i+1 >= n {
		return nil
	}
	s := string(rune('0' + i + 1))
	return &s
}

func (f *fakeBackup) ListBackupVaults(_ context.Context, in *backup.ListBackupVaultsInput, _ ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
	i := fakePage(in.NextToken)
	if i == 1 && f.vaultPage2 != nil {
		return nil, f.vaultPage2
	}
	if i >= len(f.vaults) {
		return &backup.ListBackupVaultsOutput{}, nil
	}
	return &backup.ListBackupVaultsOutput{BackupVaultList: f.vaults[i : i+1], NextToken: fakeNextToken(i, len(f.vaults))}, nil
}

func (f *fakeBackup) GetBackupVaultAccessPolicy(_ context.Context, in *backup.GetBackupVaultAccessPolicyInput, _ ...func(*backup.Options)) (*backup.GetBackupVaultAccessPolicyOutput, error) {
	name := awssdk.ToString(in.BackupVaultName)
	if err := f.policyErr[name]; err != nil {
		return nil, err
	}
	doc, ok := f.policies[name]
	if !ok {
		return nil, &backuptypes.ResourceNotFoundException{}
	}
	return &backup.GetBackupVaultAccessPolicyOutput{Policy: awssdk.String(doc)}, nil
}

func (f *fakeBackup) ListRecoveryPointsByBackupVault(_ context.Context, in *backup.ListRecoveryPointsByBackupVaultInput, _ ...func(*backup.Options)) (*backup.ListRecoveryPointsByBackupVaultOutput, error) {
	pts := f.points[awssdk.ToString(in.BackupVaultName)]
	i := fakePage(in.NextToken)
	if i == 1 && f.pointsErr != nil {
		return nil, f.pointsErr
	}
	if i >= len(pts) {
		return &backup.ListRecoveryPointsByBackupVaultOutput{}, nil
	}
	return &backup.ListRecoveryPointsByBackupVaultOutput{RecoveryPoints: pts[i : i+1], NextToken: fakeNextToken(i, len(pts))}, nil
}

func (f *fakeBackup) ListBackupPlans(context.Context, *backup.ListBackupPlansInput, ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
	if f.plansErr != nil {
		return nil, f.plansErr
	}
	return &backup.ListBackupPlansOutput{BackupPlansList: f.plans}, nil
}

func (f *fakeBackup) ListBackupSelections(_ context.Context, in *backup.ListBackupSelectionsInput, _ ...func(*backup.Options)) (*backup.ListBackupSelectionsOutput, error) {
	if f.selectErr != nil {
		return nil, f.selectErr
	}
	var out []backuptypes.BackupSelectionsListMember
	for i := range f.selections[awssdk.ToString(in.BackupPlanId)] {
		out = append(out, backuptypes.BackupSelectionsListMember{BackupPlanId: in.BackupPlanId, SelectionId: awssdk.String(string(rune('a' + i)))})
	}
	return &backup.ListBackupSelectionsOutput{BackupSelectionsList: out}, nil
}

func (f *fakeBackup) GetBackupSelection(_ context.Context, in *backup.GetBackupSelectionInput, _ ...func(*backup.Options)) (*backup.GetBackupSelectionOutput, error) {
	sel := f.selections[awssdk.ToString(in.BackupPlanId)][int(awssdk.ToString(in.SelectionId)[0]-'a')]
	return &backup.GetBackupSelectionOutput{BackupSelection: &sel}, nil
}

func (f *fakeBackup) DescribeRegionSettings(context.Context, *backup.DescribeRegionSettingsInput, ...func(*backup.Options)) (*backup.DescribeRegionSettingsOutput, error) {
	if f.settingsErr != nil {
		return nil, f.settingsErr
	}
	return &backup.DescribeRegionSettingsOutput{ResourceTypeOptInPreference: f.optIn}, nil
}

var (
	_ backupAPI     = (*fakeBackup)(nil)
	_ backupPlanAPI = (*fakeBackup)(nil)
)

func fakeVault(name string, points int64, locked *bool) backuptypes.BackupVaultListMember {
	return backuptypes.BackupVaultListMember{
		EncryptionKeyArn: keyFor(name),
		BackupVaultName:  awssdk.String(name), BackupVaultArn: awssdk.String("arn:aws:backup:us-east-1:111111111111:backup-vault:" + name),
		NumberOfRecoveryPoints: points, Locked: locked,
	}
}

// keyFor gives every fake vault a key except "unkeyed".
func keyFor(name string) *string {
	if name == "unkeyed" {
		return nil
	}
	return awssdk.String("arn:aws:kms:us-east-1:111111111111:key/" + name)
}

const publicVaultPolicy = `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"backup:CopyFromBackupVault","Resource":"*"}]}`

func storageAssetsByName(assets []asset.Asset, typ string) map[string]asset.Asset {
	out := map[string]asset.Asset{}
	for _, a := range assets {
		if a.Type == typ {
			out[a.Name] = a
		}
	}
	return out
}

func TestCollectBackupVaults(t *testing.T) {
	f := &fakeBackup{
		vaults: []backuptypes.BackupVaultListMember{
			fakeVault("open", 2, awssdk.Bool(false)),
			fakeVault("closed", 0, awssdk.Bool(true)),
			fakeVault("unread", 1, nil),
		},
		policies:  map[string]string{"open": publicVaultPolicy},
		policyErr: map[string]error{"unread": errFakeDenied},
		points: map[string][]backuptypes.RecoveryPointByBackupVault{
			"open":   {{IsEncrypted: true}, {IsEncrypted: false}},
			"unread": {{IsEncrypted: true}},
		},
	}
	assets, err := collectBackupVaults(context.Background(), f, "us-east-1", "111111111111", time.Now())
	require.NoError(t, err)
	v := storageAssetsByName(assets, "backup_vault")
	require.Len(t, v, 3)

	require.Equal(t, asset.PublicAccessConfirmed, v["open"].Metadata["public_access"])
	require.Equal(t, "1", v["open"].Metadata["unencrypted_recovery_points"], "every page is read")
	require.Equal(t, "false", v["open"].Metadata["locked"])

	require.Equal(t, asset.PublicAccessNone, v["closed"].Metadata["public_access"], "ResourceNotFound is no policy")
	require.Equal(t, "0", v["closed"].Metadata["unencrypted_recovery_points"], "an empty vault is not listed")
	require.Equal(t, "true", v["closed"].Metadata["locked"])

	_, ok := v["unread"].Metadata["public_access"]
	require.False(t, ok, "a denied policy read is unknown, not private")
	require.Equal(t, "false", v["unread"].Metadata["locked"], "a vault without Vault Lock reports no Locked flag")

	s := storageAssetsByName(assets, backupSettingsType)
	require.Len(t, s, 1)
	for _, a := range s {
		require.Equal(t, "aws:111111111111:us-east-1:backup-settings", a.ID)
		require.Equal(t, map[string]string{"backup_vaults": "3", "recovery_points": "3", "backup_plans": "0"}, a.Metadata)
	}
}

func TestCollectBackupVaultsEncryptionKey(t *testing.T) {
	assets, err := collectBackupVaults(context.Background(), &fakeBackup{
		vaults: []backuptypes.BackupVaultListMember{fakeVault("keyed", 0, nil), fakeVault("unkeyed", 0, nil)},
	}, "us-east-1", "111111111111", time.Now())
	require.NoError(t, err)
	v := storageAssetsByName(assets, "backup_vault")
	require.Equal(t, "arn:aws:kms:us-east-1:111111111111:key/keyed", v["keyed"].Metadata["encryption_key_arn"])
	key, ok := v["unkeyed"].Metadata["encryption_key_arn"]
	require.True(t, ok, "the listing carries the field, so a missing key is observed, not unknown")
	require.Empty(t, key)
}

func TestCollectBackupVaultsDegradedReads(t *testing.T) {
	_, err := collectBackupVaults(context.Background(), &fakeBackup{
		vaults:     []backuptypes.BackupVaultListMember{fakeVault("a", 0, nil), fakeVault("b", 0, nil)},
		vaultPage2: errFakeDenied,
	}, "us-east-1", "111111111111", time.Now())
	require.Error(t, err, "a failed second vault page fails the listing")

	assets, err := collectBackupVaults(context.Background(), &fakeBackup{
		vaults:    []backuptypes.BackupVaultListMember{fakeVault("a", 2, nil)},
		points:    map[string][]backuptypes.RecoveryPointByBackupVault{"a": {{IsEncrypted: false}, {IsEncrypted: false}}},
		pointsErr: errFakeDenied,
		plansErr:  errFakeDenied,
	}, "us-east-1", "111111111111", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 1, "no settings rollup without the plan listing")
	_, ok := assets[0].Metadata["unencrypted_recovery_points"]
	require.False(t, ok, "a partial recovery-point listing is not a count")
}
