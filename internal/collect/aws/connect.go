package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/connect"
	connecttypes "github.com/aws/aws-sdk-go-v2/service/connect/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// connectInstanceType is one Amazon Connect instance (FSBP Connect.2).
const connectInstanceType = "connect_instance"

type connectAPI interface {
	ListInstances(context.Context, *connect.ListInstancesInput, ...func(*connect.Options)) (*connect.ListInstancesOutput, error)
	ListInstanceAttributes(context.Context, *connect.ListInstanceAttributesInput, ...func(*connect.Options)) (*connect.ListInstanceAttributesOutput, error)
}

func collectConnect(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectConnect: %w", err)
	}
	return readConnectInstances(ctx, connect.NewFromConfig(awsCfg), region, accountID, now)
}

// readConnectInstances lists ACTIVE instances (one still being created or
// whose creation failed has no flows to log) and reads the CONTACTFLOW_LOGS
// attribute through ListInstanceAttributes — granted by ViewOnlyAccess's
// connect:List*, where DescribeInstanceAttribute is not.
func readConnectInstances(ctx context.Context, client connectAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out     []asset.Asset
		next    *string
		readErr []error
	)
	for {
		page, err := client.ListInstances(ctx, &connect.ListInstancesInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readConnectInstances: connect:ListInstances: %w", err)
		}
		for _, inst := range page.InstanceSummaryList {
			if inst.InstanceStatus != connecttypes.InstanceStatusActive {
				continue
			}
			id := awssdk.ToString(inst.Id)
			meta := map[string]string{}
			if v, err := connectContactFlowLogs(ctx, client, inst.Id); err == nil {
				meta["contact_flow_logs"] = v
			} else {
				readErr = append(readErr, fmt.Errorf("%s: %w", id, err))
			}
			name := awssdk.ToString(inst.InstanceAlias)
			if name == "" {
				name = id
			}
			out = append(out, asset.Asset{
				ID:           awssdk.ToString(inst.Arn),
				Name:         name,
				Type:         connectInstanceType,
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
			Msg("connect: instance attributes unreadable (check connect:ListInstanceAttributes); flow logging unknown for those instances this sweep")
	}
	return out, nil
}

// errNoFlowLogsAttribute is a complete attribute listing that lacks
// CONTACTFLOW_LOGS — unexpected, so unknown rather than "off".
var errNoFlowLogsAttribute = errors.New("CONTACTFLOW_LOGS attribute not listed")

// connectContactFlowLogs returns the instance's CONTACTFLOW_LOGS value
// ("true"/"false"), reading every attribute page.
func connectContactFlowLogs(ctx context.Context, client connectAPI, instanceID *string) (string, error) {
	var next *string
	for {
		page, err := client.ListInstanceAttributes(ctx, &connect.ListInstanceAttributesInput{InstanceId: instanceID, NextToken: next})
		if err != nil {
			return "", fmt.Errorf("connect:ListInstanceAttributes: %w", err)
		}
		for _, a := range page.Attributes {
			if a.AttributeType == connecttypes.InstanceAttributeTypeContactflowLogs && a.Value != nil {
				return *a.Value, nil
			}
		}
		if page.NextToken == nil {
			return "", errNoFlowLogsAttribute
		}
		next = page.NextToken
	}
}
