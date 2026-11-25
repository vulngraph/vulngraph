package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// stateMachineType is one Step Functions state machine (FSBP StepFunctions.1).
const stateMachineType = "stepfunctions_state_machine"

type sfnAPI interface {
	ListStateMachines(context.Context, *sfn.ListStateMachinesInput, ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error)
	DescribeStateMachine(context.Context, *sfn.DescribeStateMachineInput, ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error)
}

func collectStepFunctions(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectStepFunctions: %w", err)
	}
	return readStateMachines(ctx, sfn.NewFromConfig(awsCfg), region, accountID, now)
}

// readStateMachines lists state machines and reads each one's logging level,
// which only DescribeStateMachine returns. The definition it also returns is
// not stored: it can embed parameters Vulngraph has no reason to keep.
func readStateMachines(ctx context.Context, client sfnAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out          []asset.Asset
		next         *string
		describeErrs []error
	)
	for {
		page, err := client.ListStateMachines(ctx, &sfn.ListStateMachinesInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readStateMachines: states:ListStateMachines: %w", err)
		}
		for _, m := range page.StateMachines {
			arn := awssdk.ToString(m.StateMachineArn)
			meta := map[string]string{"workflow_type": string(m.Type)}
			if d, err := client.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
				// Metadata only: the definition of a state machine encrypted with a
				// customer key needs kms:Decrypt, which the read-only role lacks, and
				// the logging configuration does not.
				StateMachineArn: m.StateMachineArn, IncludedData: sfntypes.IncludedDataMetadataOnly,
			}); err == nil {
				// A state machine created without a logging configuration has
				// logging OFF — AWS's documented default, not a missing read.
				level := sfntypes.LogLevelOff
				if d.LoggingConfiguration != nil && d.LoggingConfiguration.Level != "" {
					level = d.LoggingConfiguration.Level
				}
				meta["log_level"] = string(level)
			} else {
				describeErrs = append(describeErrs, fmt.Errorf("%s: %w", arn, err))
			}
			out = append(out, asset.Asset{
				ID:           arn,
				Name:         awssdk.ToString(m.Name),
				Type:         stateMachineType,
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
			Msg("stepfunctions: logging configuration unreadable (check states:DescribeStateMachine); logging unknown for those state machines this sweep")
	}
	return out, nil
}
