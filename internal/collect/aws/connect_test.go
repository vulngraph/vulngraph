package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/connect"
	connecttypes "github.com/aws/aws-sdk-go-v2/service/connect/types"
	"github.com/stretchr/testify/require"
)

type fakeConnect struct {
	instances *connect.ListInstancesOutput
	listErr   error
	// attrs maps instance id → attribute pages; a missing id is denied.
	attrs map[string][][]connecttypes.Attribute
}

func (f *fakeConnect) ListInstances(_ context.Context, _ *connect.ListInstancesInput, _ ...func(*connect.Options)) (*connect.ListInstancesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.instances, nil
}

func (f *fakeConnect) ListInstanceAttributes(_ context.Context, in *connect.ListInstanceAttributesInput, _ ...func(*connect.Options)) (*connect.ListInstanceAttributesOutput, error) {
	pages, ok := f.attrs[awssdk.ToString(in.InstanceId)]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	i := 0
	if in.NextToken != nil {
		i = 1
	}
	out := &connect.ListInstanceAttributesOutput{Attributes: pages[i]}
	if i+1 < len(pages) {
		out.NextToken = awssdk.String("next")
	}
	return out, nil
}

func connectInstance(id string, status connecttypes.InstanceStatus) connecttypes.InstanceSummary {
	return connecttypes.InstanceSummary{Id: awssdk.String(id), Arn: awssdk.String("arn:" + id), InstanceAlias: awssdk.String(id), InstanceStatus: status}
}

func connectFlowLogs(v string) connecttypes.Attribute {
	return connecttypes.Attribute{AttributeType: connecttypes.InstanceAttributeTypeContactflowLogs, Value: awssdk.String(v)}
}

func TestReadConnectInstances(t *testing.T) {
	inbound := connecttypes.Attribute{AttributeType: connecttypes.InstanceAttributeTypeInboundCalls, Value: awssdk.String("true")}
	client := &fakeConnect{
		instances: &connect.ListInstancesOutput{InstanceSummaryList: []connecttypes.InstanceSummary{
			connectInstance("on", connecttypes.InstanceStatusActive),
			connectInstance("off", connecttypes.InstanceStatusActive),
			connectInstance("unlisted", connecttypes.InstanceStatusActive),
			connectInstance("denied", connecttypes.InstanceStatusActive),
			connectInstance("creating", connecttypes.InstanceStatusCreationInProgress),
		}},
		attrs: map[string][][]connecttypes.Attribute{
			"on":       {{inbound}, {connectFlowLogs("true")}},
			"off":      {{connectFlowLogs("false")}},
			"unlisted": {{inbound}},
		},
	}
	got, err := readConnectInstances(context.Background(), client, "us-east-1", "1", time.Now())
	require.NoError(t, err)
	m := indexAssetsByID(got)
	require.Len(t, m, 4, "an instance still being created is not emitted")
	require.Equal(t, "true", m["arn:on"].Metadata["contact_flow_logs"], "the attribute is found on a later page")
	require.Equal(t, "false", m["arn:off"].Metadata["contact_flow_logs"])
	require.NotContains(t, m["arn:unlisted"].Metadata, "contact_flow_logs", "an attribute the listing lacks is unknown, not off")
	require.NotContains(t, m["arn:denied"].Metadata, "contact_flow_logs")

	_, err = readConnectInstances(context.Background(), &fakeConnect{listErr: errors.New("throttled")}, "us-east-1", "1", time.Now())
	require.Error(t, err)
}
