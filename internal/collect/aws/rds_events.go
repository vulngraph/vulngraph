package aws

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// rdsSettingsType carries the region's RDS-wide settings — today the event
// notification coverage FSBP RDS.19-22 grade — on one asset per
// account-region, so a missing subscription is one finding per region rather
// than one per database.
const rdsSettingsType = "aws_rds_settings"

// rdsEventCoverage is one FSBP event-subscription requirement: a source type
// and the event categories a subscription must deliver for it.
type rdsEventCoverage struct {
	key        string
	sourceType string
	categories []string
}

// rdsEventRequirements are FSBP RDS.19 (clusters), RDS.20 (instances), RDS.21
// (parameter groups) and RDS.22 (security groups), verbatim from the Security
// Hub control reference.
var rdsEventRequirements = []rdsEventCoverage{
	{key: "cluster_events_covered", sourceType: "db-cluster", categories: []string{"maintenance", "failure"}},
	{key: "instance_events_covered", sourceType: "db-instance", categories: []string{"maintenance", "configuration change", "failure"}},
	{key: "parameter_group_events_covered", sourceType: "db-parameter-group", categories: []string{"configuration change"}},
	{key: "security_group_events_covered", sourceType: "db-security-group", categories: []string{"configuration change", "failure"}},
}

// rdsRegionSettings lists the region's event subscriptions and builds the
// settings asset. It is only built from a complete picture: the instance and
// cluster listings already succeeded (the caller holds them), and a failed
// subscription listing returns an error so no coverage is guessed.
//
// has_event_subscriptions is recorded because FSBP passes a region with no
// subscriptions at all ("the control passes if there are no existing event
// subscriptions"); has_clusters / has_instances because a coverage gap only
// matters where there are databases emitting those events.
func rdsRegionSettings(ctx context.Context, client rdsPostureAPI, region, accountID string, now time.Time, instances, clusters []asset.Asset) (asset.Asset, error) {
	subs, err := listEventSubscriptions(ctx, client)
	if err != nil {
		return asset.Asset{}, err
	}
	meta := map[string]string{
		"event_subscriptions":     strconv.Itoa(len(subs)),
		"has_event_subscriptions": strconv.FormatBool(len(subs) > 0),
		"has_instances":           strconv.FormatBool(len(instances) > 0),
		"has_clusters":            strconv.FormatBool(len(clusters) > 0),
	}
	for _, req := range rdsEventRequirements {
		meta[req.key] = strconv.FormatBool(slices.ContainsFunc(subs, func(s rdstypes.EventSubscription) bool {
			return subscriptionCovers(s, req)
		}))
	}
	return asset.Asset{
		ID:           "aws:" + accountID + ":" + region + ":rds-settings",
		Name:         "RDS settings (" + region + ")",
		Type:         rdsSettingsType,
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}, nil
}

// subscriptionCovers reports whether an enabled subscription delivers every
// required category for every resource of the source type. An empty source
// type subscribes to every source, an empty category list to every category;
// a subscription scoped to named source IDs does not cover the resources it
// leaves out, so it does not count.
func subscriptionCovers(s rdstypes.EventSubscription, req rdsEventCoverage) bool {
	if !awssdk.ToBool(s.Enabled) || len(s.SourceIdsList) > 0 {
		return false
	}
	if st := awssdk.ToString(s.SourceType); st != "" && st != req.sourceType {
		return false
	}
	if len(s.EventCategoriesList) == 0 {
		return true
	}
	for _, c := range req.categories {
		if !slices.Contains(s.EventCategoriesList, c) {
			return false
		}
	}
	return true
}

func listEventSubscriptions(ctx context.Context, client rdsPostureAPI) ([]rdstypes.EventSubscription, error) {
	var (
		out    []rdstypes.EventSubscription
		marker *string
	)
	for {
		page, err := client.DescribeEventSubscriptions(ctx, &rds.DescribeEventSubscriptionsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("listEventSubscriptions: %w", err)
		}
		out = append(out, page.EventSubscriptionsList...)
		if page.Marker == nil {
			return out, nil
		}
		marker = page.Marker
	}
}
