package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	mqtypes "github.com/aws/aws-sdk-go-v2/service/mq/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// mqBrokerType is one Amazon MQ broker (FSBP MQ.2).
const mqBrokerType = "mq_broker"

type mqAPI interface {
	ListBrokers(context.Context, *mq.ListBrokersInput, ...func(*mq.Options)) (*mq.ListBrokersOutput, error)
	DescribeBroker(context.Context, *mq.DescribeBrokerInput, ...func(*mq.Options)) (*mq.DescribeBrokerOutput, error)
}

func collectMQ(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectMQ: %w", err)
	}
	return readMQBrokers(ctx, mq.NewFromConfig(awsCfg), region, accountID, now)
}

// readMQBrokers lists brokers and reads each one's log settings, which only
// DescribeBroker returns. Audit logging exists for ActiveMQ only; RabbitMQ
// brokers carry no audit_logs key and are not graded on it.
func readMQBrokers(ctx context.Context, client mqAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out          []asset.Asset
		next         *string
		describeErrs []error
	)
	for {
		page, err := client.ListBrokers(ctx, &mq.ListBrokersInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readMQBrokers: mq:ListBrokers: %w", err)
		}
		for _, b := range page.BrokerSummaries {
			id := awssdk.ToString(b.BrokerId)
			meta := map[string]string{
				"engine_type":  string(b.EngineType),
				"broker_state": string(b.BrokerState),
			}
			if b.EngineType == mqtypes.EngineTypeActivemq {
				if audit, err := mqAuditLogs(ctx, client, b.BrokerId); err == nil {
					meta["audit_logs"] = strconv.FormatBool(audit)
				} else {
					describeErrs = append(describeErrs, fmt.Errorf("%s: %w", id, err))
				}
			}
			name := awssdk.ToString(b.BrokerName)
			if name == "" {
				name = id
			}
			out = append(out, asset.Asset{
				ID:           awssdk.ToString(b.BrokerArn),
				Name:         name,
				Type:         mqBrokerType,
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
			Msg("mq: broker log settings unreadable (check mq:DescribeBroker); audit logging unknown for those brokers this sweep")
	}
	return out, nil
}

// mqAuditLogs reports whether an ActiveMQ broker streams audit logs. Logs
// omitted from the answer means no log export is configured: both flags
// default to false when a broker is created without them.
func mqAuditLogs(ctx context.Context, client mqAPI, brokerID *string) (bool, error) {
	d, err := client.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: brokerID})
	if err != nil {
		return false, fmt.Errorf("mq:DescribeBroker: %w", err)
	}
	return d.Logs != nil && awssdk.ToBool(d.Logs.Audit), nil
}
