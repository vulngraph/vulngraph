package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/datasync"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// dataSyncTaskType is one DataSync task (FSBP DataSync.1).
const dataSyncTaskType = "datasync_task"

type dataSyncAPI interface {
	ListTasks(context.Context, *datasync.ListTasksInput, ...func(*datasync.Options)) (*datasync.ListTasksOutput, error)
	DescribeTask(context.Context, *datasync.DescribeTaskInput, ...func(*datasync.Options)) (*datasync.DescribeTaskOutput, error)
}

func collectDataSync(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectDataSync: %w", err)
	}
	return readDataSyncTasks(ctx, datasync.NewFromConfig(awsCfg), region, accountID, now)
}

// readDataSyncTasks lists tasks and reads each one's CloudWatch logging setup
// from DescribeTask: the log group (log_group, "" when none), the publish
// level (log_level, absent when the task options carry none) and the task
// mode — an Enhanced-mode task logs to /aws/datasync without a log group set.
func readDataSyncTasks(ctx context.Context, client dataSyncAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out     []asset.Asset
		next    *string
		readErr []error
	)
	for {
		page, err := client.ListTasks(ctx, &datasync.ListTasksInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readDataSyncTasks: datasync:ListTasks: %w", err)
		}
		for _, t := range page.Tasks {
			arn := awssdk.ToString(t.TaskArn)
			meta := map[string]string{"status": string(t.Status)}
			if d, err := client.DescribeTask(ctx, &datasync.DescribeTaskInput{TaskArn: t.TaskArn}); err == nil {
				meta["log_group"] = awssdk.ToString(d.CloudWatchLogGroupArn)
				meta["task_mode"] = string(d.TaskMode)
				if d.Options != nil && d.Options.LogLevel != "" {
					meta["log_level"] = string(d.Options.LogLevel)
				}
			} else {
				readErr = append(readErr, fmt.Errorf("%s: %w", arn, err))
			}
			name := awssdk.ToString(t.Name)
			if name == "" {
				name = arn
			}
			out = append(out, asset.Asset{
				ID:           arn,
				Name:         name,
				Type:         dataSyncTaskType,
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
	if len(readErr) > 0 {
		log.FromContext(ctx).Warn().Err(errors.Join(readErr...)).Str("region", region).
			Msg("datasync: task unreadable (check datasync:DescribeTask); logging unknown for those tasks this sweep")
	}
	return out, nil
}
