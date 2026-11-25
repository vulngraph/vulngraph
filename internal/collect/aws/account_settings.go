package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// accountSettingsType is the one-per-account asset carrying account-wide
// posture: a setting that applies to the whole account gets ONE finding here,
// not one per resource it happens to govern. Several global collectors
// contribute keys (the S3 account Block Public Access, the CloudTrail rollup,
// the password policy and security contact read below), so the asset is
// assembled after they all finish (collectGlobalServices).
//
// Every key is written only from a successful read; a failed read leaves it
// absent, which the checks read as unknown.
const accountSettingsType = "aws_account_settings"

// accountSettings accumulates the account-settings keys from concurrently
// running global collectors.
type accountSettings struct {
	mu   sync.Mutex
	meta map[string]string
}

func newAccountSettings() *accountSettings {
	return &accountSettings{meta: map[string]string{}}
}

func (s *accountSettings) set(kv map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range kv {
		s.meta[k] = v
	}
}

// asset returns the account-settings asset. It is emitted even when every
// contribution failed: an asset with no keys leaves every account-wide check
// unevaluable, so an open finding stays open instead of reading as fixed
// because its resource vanished from the sweep.
func (s *accountSettings) asset(accountID string, now time.Time) asset.Asset {
	s.mu.Lock()
	defer s.mu.Unlock()
	meta := make(map[string]string, len(s.meta))
	for k, v := range s.meta {
		meta[k] = v
	}
	return asset.Asset{
		ID:           "aws:" + accountID + ":account-settings",
		Name:         "Account settings (" + accountID + ")",
		Type:         accountSettingsType,
		Provider:     asset.ProviderAWS,
		Region:       "global",
		AccountID:    accountID,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// accountBPASettings renders the account-level S3 Block Public Access the S3
// collector already reads. Unobserved yields nothing; no configured block is
// an observation that all four flags are off.
func accountBPASettings(acct accountBPA) map[string]string {
	if !acct.observed {
		return nil
	}
	flag := func(v *bool) string { return strconv.FormatBool(awssdk.ToBool(v)) }
	out := map[string]string{
		"s3_bpa_block_public_acls":       "false",
		"s3_bpa_ignore_public_acls":      "false",
		"s3_bpa_block_public_policy":     "false",
		"s3_bpa_restrict_public_buckets": "false",
		"s3_bpa_all_enabled":             "false",
	}
	if c := acct.cfg; c != nil {
		out["s3_bpa_block_public_acls"] = flag(c.BlockPublicAcls)
		out["s3_bpa_ignore_public_acls"] = flag(c.IgnorePublicAcls)
		out["s3_bpa_block_public_policy"] = flag(c.BlockPublicPolicy)
		out["s3_bpa_restrict_public_buckets"] = flag(c.RestrictPublicBuckets)
		out["s3_bpa_all_enabled"] = strconv.FormatBool(fullyBlocked(c))
	}
	return out
}

// trailRollupSettings answers the account-wide question the per-trail checks
// cannot: is at least one multi-region trail logging? Called only with a
// successful trail listing, so zero trails is an observation, and that is the
// case a per-trail check can never report.
//
// A multi-region trail whose logging status could not be read leaves the
// answer unknown unless another trail already settles it.
func trailRollupSettings(trails []asset.Asset) map[string]string {
	out := map[string]string{"cloudtrail_trail_count": strconv.Itoa(len(trails))}
	unknown := false
	for _, t := range trails {
		if t.Metadata["multi_region"] != "true" {
			continue
		}
		switch t.Metadata["is_logging"] {
		case "true":
			out["cloudtrail_multi_region_logging"] = "true"
			return out
		case "":
			unknown = true
		}
	}
	if !unknown {
		out["cloudtrail_multi_region_logging"] = "false"
	}
	return out
}

type passwordPolicyAPI interface {
	GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
}

type alternateContactAPI interface {
	GetAlternateContact(context.Context, *account.GetAlternateContactInput, ...func(*account.Options)) (*account.GetAlternateContactOutput, error)
}

// collectAccountSettings reads the account's IAM password policy and SECURITY
// alternate contact into settings. It errors only when both reads failed, so
// a connector missing both permissions is reported like any other skipped
// collector.
func collectAccountSettings(ctx context.Context, cfg map[string]string, settings *accountSettings) error {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("collectAccountSettings: %w", err)
	}
	awsCfg.Region = globalRegionFor(awsCfg.Region)
	ppErr := readPasswordPolicy(ctx, iam.NewFromConfig(awsCfg), settings)
	scErr := readSecurityContact(ctx, account.NewFromConfig(awsCfg), settings)
	if ppErr != nil && scErr != nil {
		return fmt.Errorf("collectAccountSettings: %w", errors.Join(ppErr, scErr))
	}
	// One read failing is not a skipped collector, but a permanently missing
	// permission must still be visible: its checks stay silent every sweep.
	if err := errors.Join(ppErr, scErr); err != nil {
		log.FromContext(ctx).Warn().Err(err).
			Msg("aws account settings read failed; its checks cannot evaluate this sweep (check iam:GetAccountPasswordPolicy, account:GetAlternateContact)")
	}
	return nil
}

// readPasswordPolicy records the account password policy. NoSuchEntity is
// AWS saying the account has none — an observation (AWS then applies its
// weak default), not a gap.
func readPasswordPolicy(ctx context.Context, client passwordPolicyAPI, settings *accountSettings) error {
	out, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		if awsErrCode(err) == "NoSuchEntity" {
			settings.set(map[string]string{"password_policy": "absent"})
			return nil
		}
		return fmt.Errorf("readPasswordPolicy: %w", err)
	}
	if out == nil || out.PasswordPolicy == nil {
		return errors.New("readPasswordPolicy: empty response")
	}
	p := out.PasswordPolicy
	settings.set(map[string]string{
		"password_policy":            "present",
		"password_min_length":        strconv.Itoa(int(awssdk.ToInt32(p.MinimumPasswordLength))),
		"password_reuse_prevention":  strconv.Itoa(int(awssdk.ToInt32(p.PasswordReusePrevention))),
		"password_require_uppercase": strconv.FormatBool(p.RequireUppercaseCharacters),
		"password_require_lowercase": strconv.FormatBool(p.RequireLowercaseCharacters),
		"password_require_numbers":   strconv.FormatBool(p.RequireNumbers),
		"password_require_symbols":   strconv.FormatBool(p.RequireSymbols),
	})
	return nil
}

// readSecurityContact records whether a SECURITY alternate contact is
// registered. ResourceNotFoundException is the observed "none registered".
func readSecurityContact(ctx context.Context, client alternateContactAPI, settings *accountSettings) error {
	out, err := client.GetAlternateContact(ctx, &account.GetAlternateContactInput{
		AlternateContactType: accounttypes.AlternateContactTypeSecurity,
	})
	if err != nil {
		if awsErrCode(err) == "ResourceNotFoundException" {
			settings.set(map[string]string{"security_contact": "false"})
			return nil
		}
		return fmt.Errorf("readSecurityContact: %w", err)
	}
	settings.set(map[string]string{
		"security_contact": strconv.FormatBool(out != nil && out.AlternateContact != nil && awssdk.ToString(out.AlternateContact.EmailAddress) != ""),
	})
	return nil
}
