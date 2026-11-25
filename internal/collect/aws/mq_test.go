package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	mqtypes "github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/stretchr/testify/require"
)

type fakeMQ struct {
	pages     []*mq.ListBrokersOutput
	calls     int
	err       error
	desc      map[string]*mq.DescribeBrokerOutput
	described []string
}

func (f *fakeMQ) ListBrokers(_ context.Context, _ *mq.ListBrokersInput, _ ...func(*mq.Options)) (*mq.ListBrokersOutput, error) {
	if f.calls == len(f.pages) {
		return nil, f.err
	}
	p := f.pages[f.calls]
	f.calls++
	return p, nil
}

func (f *fakeMQ) DescribeBroker(_ context.Context, in *mq.DescribeBrokerInput, _ ...func(*mq.Options)) (*mq.DescribeBrokerOutput, error) {
	id := awssdk.ToString(in.BrokerId)
	f.described = append(f.described, id)
	d, ok := f.desc[id]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	return d, nil
}

func mqBroker(id string, engine mqtypes.EngineType) mqtypes.BrokerSummary {
	return mqtypes.BrokerSummary{BrokerId: awssdk.String(id), BrokerArn: awssdk.String("arn:" + id), BrokerName: awssdk.String(id), EngineType: engine}
}

func TestReadMQBrokers(t *testing.T) {
	client := &fakeMQ{
		pages: []*mq.ListBrokersOutput{
			{BrokerSummaries: []mqtypes.BrokerSummary{mqBroker("audit", mqtypes.EngineTypeActivemq)}, NextToken: awssdk.String("p2")},
			{BrokerSummaries: []mqtypes.BrokerSummary{
				mqBroker("noaudit", mqtypes.EngineTypeActivemq), mqBroker("nologs", mqtypes.EngineTypeActivemq),
				mqBroker("rabbit", mqtypes.EngineTypeRabbitmq), mqBroker("denied", mqtypes.EngineTypeActivemq),
			}},
		},
		desc: map[string]*mq.DescribeBrokerOutput{
			"audit":   {Logs: &mqtypes.LogsSummary{Audit: awssdk.Bool(true)}},
			"noaudit": {Logs: &mqtypes.LogsSummary{Audit: awssdk.Bool(false), General: awssdk.Bool(true)}},
			"nologs":  {},
		},
	}
	got, err := readMQBrokers(context.Background(), client, "us-east-1", "1", time.Now())
	require.NoError(t, err)
	m := indexAssetsByID(got)
	require.Len(t, m, 5)
	require.Equal(t, "true", m["arn:audit"].Metadata["audit_logs"])
	require.Equal(t, "false", m["arn:noaudit"].Metadata["audit_logs"])
	require.Equal(t, "false", m["arn:nologs"].Metadata["audit_logs"])
	require.NotContains(t, m["arn:rabbit"].Metadata, "audit_logs", "RabbitMQ has no audit log to grade")
	require.NotContains(t, client.described, "rabbit")
	require.NotContains(t, m["arn:denied"].Metadata, "audit_logs")

	_, err = readMQBrokers(context.Background(), &fakeMQ{pages: client.pages[:1], err: errors.New("throttled"), desc: client.desc}, "us-east-1", "1", time.Now())
	require.Error(t, err)
}
