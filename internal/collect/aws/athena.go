package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Athena workgroup posture (FSBP Athena.4: the workgroup publishes query
// metrics to CloudWatch). ListWorkGroups carries names only; the setting comes
// from one GetWorkGroup per workgroup.

// athenaPrimaryWorkgroup is the workgroup every account-region has by default.
const athenaPrimaryWorkgroup = "primary"

type athenaAPI interface {
	ListWorkGroups(context.Context, *athena.ListWorkGroupsInput, ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error)
	GetWorkGroup(context.Context, *athena.GetWorkGroupInput, ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error)
	ListQueryExecutions(context.Context, *athena.ListQueryExecutionsInput, ...func(*athena.Options)) (*athena.ListQueryExecutionsOutput, error)
}

func collectAthena(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectAthena: %w", err)
	}
	return collectAthenaWorkgroups(ctx, athena.NewFromConfig(awsCfg), region, accountID, now)
}

func collectAthenaWorkgroups(ctx context.Context, client athenaAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		groups []athenatypes.WorkGroupSummary
		next   *string
	)
	for {
		out, err := client.ListWorkGroups(ctx, &athena.ListWorkGroupsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("collectAthenaWorkgroups: %w", err)
		}
		groups = append(groups, out.WorkGroups...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}

	metas := make([]map[string]string, len(groups))
	eachBounded(ctx, len(groups), eachBoundedTimeout, "athena:GetWorkGroup", func(ctx context.Context, i int) {
		metas[i] = athenaWorkgroupFacts(ctx, client, awssdk.ToString(groups[i].Name))
	})

	assets := make([]asset.Asset, 0, len(groups))
	unread := 0
	for i, g := range groups {
		name := awssdk.ToString(g.Name)
		meta := metas[i]
		if meta == nil {
			unread++
			meta = map[string]string{}
		}
		meta["state"] = string(g.State)
		assets = append(assets, asset.Asset{
			ID:           fmt.Sprintf("arn:%s:athena:%s:%s:workgroup/%s", partitionFor(region), region, accountID, name),
			Name:         name,
			Type:         "athena_workgroup",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	if unread > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int("workgroups", len(groups)).Int("unread", unread).
			Msg("athena: GetWorkGroup failed for some workgroups (check athena:GetWorkGroup); their metrics setting is unknown this sweep")
	}
	return assets, nil
}

// athenaWorkgroupFacts reads one workgroup's CloudWatch metrics setting, nil
// when it could not be read. For the stock primary workgroup it also records
// whether any query ever ran in it: every account-region has one, so grading
// an untouched primary workgroup would report every region of every account.
func athenaWorkgroupFacts(ctx context.Context, client athenaAPI, name string) map[string]string {
	out, err := client.GetWorkGroup(ctx, &athena.GetWorkGroupInput{WorkGroup: awssdk.String(name)})
	if err != nil || out == nil || out.WorkGroup == nil || out.WorkGroup.Configuration == nil {
		return nil
	}
	// A workgroup whose configuration never set the flag omits it, and Athena
	// then publishes no metrics: the read configuration is the observation.
	meta := map[string]string{
		"cloudwatch_metrics_enabled": strconv.FormatBool(awssdk.ToBool(out.WorkGroup.Configuration.PublishCloudWatchMetricsEnabled)),
	}
	if name == athenaPrimaryWorkgroup {
		q, err := client.ListQueryExecutions(ctx, &athena.ListQueryExecutionsInput{WorkGroup: awssdk.String(name), MaxResults: awssdk.Int32(1)})
		if err == nil && q != nil {
			meta["has_query_history"] = strconv.FormatBool(len(q.QueryExecutionIds) > 0)
		}
	}
	return meta
}
