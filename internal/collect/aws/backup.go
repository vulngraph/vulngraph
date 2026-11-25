package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// backupSettingsType is the per-region AWS Backup rollup: whether the region
// holds backups with no plan producing new ones. One asset per account-region,
// so the finding is one per region rather than one per vault.
const backupSettingsType = "aws_backup_settings"

// backupVaultReadTimeout bounds one vault's reads. Longer than
// eachBoundedTimeout: the recovery-point listing pages through every backup
// the vault holds, and a vault with thousands is normal.
const backupVaultReadTimeout = 2 * time.Minute

// backupVaultSensitiveActions are the vault-policy actions that hand an
// outsider the backups themselves (copy out, restore) or let them destroy or
// shorten them — the actions a public grant of which is data exposure or
// ransomware leverage, as opposed to metadata reads.
var backupVaultSensitiveActions = []string{
	"backup:copyfrombackupvault", "backup:startrestorejob",
	"backup:deleterecoverypoint", "backup:updaterecoverypointlifecycle",
	"backup:deletebackupvault", "backup:putbackupvaultaccesspolicy",
	"backup:deletebackupvaultaccesspolicy",
}

type backupAPI interface {
	ListBackupVaults(context.Context, *backup.ListBackupVaultsInput, ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error)
	// GetBackupVaultAccessPolicy answers a vault with no policy with
	// ResourceNotFoundException, an observation of "no grant".
	GetBackupVaultAccessPolicy(context.Context, *backup.GetBackupVaultAccessPolicyInput, ...func(*backup.Options)) (*backup.GetBackupVaultAccessPolicyOutput, error)
	// ListRecoveryPointsByBackupVault is granted by ViewOnlyAccess, not
	// SecurityAudit (FSBP Backup.1).
	ListRecoveryPointsByBackupVault(context.Context, *backup.ListRecoveryPointsByBackupVaultInput, ...func(*backup.Options)) (*backup.ListRecoveryPointsByBackupVaultOutput, error)
	ListBackupPlans(context.Context, *backup.ListBackupPlansInput, ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error)
}

func collectBackup(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectBackup: %w", err)
	}
	return collectBackupVaults(ctx, backup.NewFromConfig(awsCfg), region, accountID, now)
}

type backupVault struct {
	member backuptypes.BackupVaultListMember
	meta   map[string]string
}

// collectBackupVaults emits every backup vault and the region's
// aws_backup_settings rollup. A failed vault listing fails the collector; a
// failed policy or recovery-point read leaves that vault's key absent.
func collectBackupVaults(ctx context.Context, client backupAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	vaults, err := listBackupVaults(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("collectBackupVaults: %w", err)
	}
	var policyFailed, pointsFailed atomic.Int32
	eachBounded(ctx, len(vaults), backupVaultReadTimeout, "backup", func(ctx context.Context, i int) {
		v := &vaults[i]
		name := v.member.BackupVaultName
		pol, err := client.GetBackupVaultAccessPolicy(ctx, &backup.GetBackupVaultAccessPolicyInput{BackupVaultName: name})
		var notFound *backuptypes.ResourceNotFoundException
		switch {
		case err == nil:
			pub, policies := resourcePolicyMetadata(awssdk.ToString(pol.Policy), awssdk.ToString(name)+"-resource", backupVaultSensitiveActions)
			v.meta["public_access"] = pub
			if policies != "" {
				v.meta["policies"] = policies
			}
		case errors.As(err, &notFound):
			v.meta["public_access"] = asset.PublicAccessNone
		default:
			policyFailed.Add(1)
		}
		if n, ok := unencryptedRecoveryPoints(ctx, client, v.member); ok {
			v.meta["unencrypted_recovery_points"] = strconv.Itoa(n)
		} else {
			pointsFailed.Add(1)
		}
	})
	if n := policyFailed.Load(); n > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int32("vaults", n).
			Msg("backup: vault access policy unreadable (check backup:GetBackupVaultAccessPolicy); public grant unknown for those vaults")
	}
	if n := pointsFailed.Load(); n > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int32("vaults", n).
			Msg("backup: recovery points unreadable (check backup:ListRecoveryPointsByBackupVault); their encryption is unknown this sweep")
	}

	assets := make([]asset.Asset, 0, len(vaults)+1)
	var recoveryPoints int64
	for _, v := range vaults {
		recoveryPoints += v.member.NumberOfRecoveryPoints
		assets = append(assets, asset.Asset{
			ID:           awssdk.ToString(v.member.BackupVaultArn),
			Name:         awssdk.ToString(v.member.BackupVaultName),
			Type:         "backup_vault",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     v.meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	// The rollup needs both listings; without the plan count it would carry
	// nothing a check could grade, so it is not emitted.
	plans, err := listBackupPlanIDs(ctx, client)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("region", region).
			Msg("backup: plans unreadable (check backup:ListBackupPlans); plan coverage unknown this sweep")
		return assets, nil
	}
	return append(assets, asset.Asset{
		ID:        "aws:" + accountID + ":" + region + ":backup-settings",
		Name:      "AWS Backup (" + region + ")",
		Type:      backupSettingsType,
		Provider:  asset.ProviderAWS,
		Region:    region,
		AccountID: accountID,
		Metadata: map[string]string{
			"backup_vaults":   strconv.Itoa(len(vaults)),
			"recovery_points": strconv.FormatInt(recoveryPoints, 10),
			"backup_plans":    strconv.Itoa(len(plans)),
		},
		DiscoveredAt: now,
		LastSeen:     now,
	}), nil
}

func listBackupVaults(ctx context.Context, client backupAPI) ([]backupVault, error) {
	var (
		out  []backupVault
		next *string
	)
	for {
		page, err := client.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listBackupVaults: %w", err)
		}
		for _, m := range page.BackupVaultList {
			meta := map[string]string{
				// Locked is reported for every vault; a vault that never had
				// Vault Lock configured answers false.
				"locked":     strconv.FormatBool(awssdk.ToBool(m.Locked)),
				"vault_type": string(m.VaultType),
				// The listing always carries the field, so an empty value is
				// the API's answer that the vault has no encryption key.
				"encryption_key_arn": awssdk.ToString(m.EncryptionKeyArn),
			}
			if m.MinRetentionDays != nil {
				meta["lock_min_retention_days"] = strconv.FormatInt(*m.MinRetentionDays, 10)
			}
			if m.MaxRetentionDays != nil {
				meta["lock_max_retention_days"] = strconv.FormatInt(*m.MaxRetentionDays, 10)
			}
			out = append(out, backupVault{member: m, meta: meta})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

// unencryptedRecoveryPoints counts the vault's recovery points that are not
// encrypted at rest (FSBP Backup.1). A vault the listing reports as empty is
// not read. ok is false when any page failed: a partial count would undercount.
func unencryptedRecoveryPoints(ctx context.Context, client backupAPI, v backuptypes.BackupVaultListMember) (int, bool) {
	if v.NumberOfRecoveryPoints == 0 {
		return 0, true
	}
	var (
		n    int
		next *string
	)
	for {
		page, err := client.ListRecoveryPointsByBackupVault(ctx, &backup.ListRecoveryPointsByBackupVaultInput{
			BackupVaultName: v.BackupVaultName, NextToken: next,
		})
		if err != nil {
			return 0, false
		}
		for _, rp := range page.RecoveryPoints {
			if !rp.IsEncrypted {
				n++
			}
		}
		if page.NextToken == nil {
			return n, true
		}
		next = page.NextToken
	}
}
