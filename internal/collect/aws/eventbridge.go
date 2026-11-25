package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// eventBusType is one EventBridge event bus — the account's default bus, a
// custom bus, or a partner bus (FSBP EventBridge.3, CIS AWS 2.21).
const eventBusType = "eventbridge_bus"

// eventBridgeSensitiveActions are the actions a public bus grant exposes: a
// caller who can put events onto the bus drives every rule and target on it.
var eventBridgeSensitiveActions = []string{"events:putevents"}

type eventBridgeAPI interface {
	ListEventBuses(context.Context, *eventbridge.ListEventBusesInput, ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error)
	DescribeEventBus(context.Context, *eventbridge.DescribeEventBusInput, ...func(*eventbridge.Options)) (*eventbridge.DescribeEventBusOutput, error)
}

func collectEventBridge(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectEventBridge: %w", err)
	}
	return readEventBuses(ctx, eventbridge.NewFromConfig(awsCfg), region, accountID, now)
}

// eventBusKind classifies a bus by name: the account's "default" bus, a
// partner bus a SaaS provider created ("aws.partner/…"), or a custom bus.
func eventBusKind(name string) string {
	switch {
	case name == "default":
		return "default"
	case strings.HasPrefix(name, "aws.partner/"):
		return "partner"
	default:
		return "custom"
	}
}

// readEventBuses lists the region's buses and reads each one's resource policy
// through DescribeEventBus, whose answer for a bus without a policy is an
// empty Policy — an observation, unlike a failed call, which leaves
// has_resource_policy and public_access absent.
//
// Every region has a default bus, so its mere existence says nothing: it is
// emitted only when it carries a policy (which can be public) or its policy
// could not be read, so an account that never touched EventBridge gets no
// asset per region.
func readEventBuses(ctx context.Context, client eventBridgeAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out          []asset.Asset
		next         *string
		describeErrs []error
	)
	for {
		page, err := client.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readEventBuses: events:ListEventBuses: %w", err)
		}
		for _, b := range page.EventBuses {
			name := awssdk.ToString(b.Name)
			meta := map[string]string{"bus_kind": eventBusKind(name)}
			if v := awssdk.ToString(b.ManagedBy); v != "" {
				meta["managed_by"] = v
			}
			if d, err := client.DescribeEventBus(ctx, &eventbridge.DescribeEventBusInput{Name: b.Name}); err == nil {
				doc := awssdk.ToString(d.Policy)
				meta["has_resource_policy"] = strconv.FormatBool(doc != "")
				pub, policies := resourcePolicyMetadata(doc, name+"-resource", eventBridgeSensitiveActions)
				meta["public_access"] = pub
				if policies != "" {
					meta["policies"] = policies
				}
			} else {
				describeErrs = append(describeErrs, fmt.Errorf("%s: %w", name, err))
			}
			if meta["bus_kind"] == "default" && meta["has_resource_policy"] == "false" {
				continue
			}
			out = append(out, asset.Asset{
				ID:           awssdk.ToString(b.Arn),
				Name:         name,
				Type:         eventBusType,
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
			Msg("eventbridge: bus policy unreadable (check events:DescribeEventBus); policy posture unknown for those buses this sweep")
	}
	return out, nil
}
