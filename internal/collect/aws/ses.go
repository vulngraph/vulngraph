package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// sesConfigurationSetType is one SES configuration set (FSBP SES.3).
const sesConfigurationSetType = "ses_configuration_set"

type sesAPI interface {
	ListConfigurationSets(context.Context, *sesv2.ListConfigurationSetsInput, ...func(*sesv2.Options)) (*sesv2.ListConfigurationSetsOutput, error)
	GetConfigurationSet(context.Context, *sesv2.GetConfigurationSetInput, ...func(*sesv2.Options)) (*sesv2.GetConfigurationSetOutput, error)
}

func collectSES(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectSES: %w", err)
	}
	return readSESConfigurationSets(ctx, sesv2.NewFromConfig(awsCfg), region, accountID, now)
}

// readSESConfigurationSets lists configuration sets (the listing carries names
// only) and reads each one's delivery TLS policy.
func readSESConfigurationSets(ctx context.Context, client sesAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out          []asset.Asset
		next         *string
		describeErrs []error
	)
	for {
		page, err := client.ListConfigurationSets(ctx, &sesv2.ListConfigurationSetsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readSESConfigurationSets: ses:ListConfigurationSets: %w", err)
		}
		for _, name := range page.ConfigurationSets {
			meta := map[string]string{}
			if d, err := client.GetConfigurationSet(ctx, &sesv2.GetConfigurationSetInput{ConfigurationSetName: awssdk.String(name)}); err == nil {
				// No delivery options means SES's documented default, OPTIONAL
				// (opportunistic TLS), not an unread setting.
				policy := sestypes.TlsPolicyOptional
				if d.DeliveryOptions != nil && d.DeliveryOptions.TlsPolicy != "" {
					policy = d.DeliveryOptions.TlsPolicy
				}
				meta["tls_policy"] = string(policy)
			} else {
				describeErrs = append(describeErrs, fmt.Errorf("%s: %w", name, err))
			}
			out = append(out, asset.Asset{
				ID:           fmt.Sprintf("arn:%s:ses:%s:%s:configuration-set/%s", partitionFor(region), region, accountID, name),
				Name:         name,
				Type:         sesConfigurationSetType,
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.NextToken == nil {
			break
		}
		next = page.NextToken
	}
	if len(describeErrs) > 0 {
		log.FromContext(ctx).Warn().Err(errors.Join(describeErrs...)).Str("region", region).
			Msg("ses: configuration set unreadable (check ses:GetConfigurationSet); TLS policy unknown for those sets this sweep")
	}
	return out, nil
}
