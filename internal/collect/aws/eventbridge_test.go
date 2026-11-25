package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeEventBridge struct {
	pages []*eventbridge.ListEventBusesOutput
	calls int
	err   error
	desc  map[string]*eventbridge.DescribeEventBusOutput
}

func (f *fakeEventBridge) ListEventBuses(_ context.Context, _ *eventbridge.ListEventBusesInput, _ ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
	if f.calls == len(f.pages) {
		return nil, f.err
	}
	p := f.pages[f.calls]
	f.calls++
	return p, nil
}

func (f *fakeEventBridge) DescribeEventBus(_ context.Context, in *eventbridge.DescribeEventBusInput, _ ...func(*eventbridge.Options)) (*eventbridge.DescribeEventBusOutput, error) {
	d, ok := f.desc[awssdk.ToString(in.Name)]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	return d, nil
}

const (
	publicBusPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"events:PutEvents","Resource":"*"}]}`
	orgBusPolicy    = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"events:PutEvents","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc"}}}]}`
)

func ebBus(name string) ebtypes.EventBus {
	return ebtypes.EventBus{Name: awssdk.String(name), Arn: awssdk.String("arn:" + name)}
}

func TestReadEventBuses(t *testing.T) {
	client := &fakeEventBridge{
		pages: []*eventbridge.ListEventBusesOutput{
			{EventBuses: []ebtypes.EventBus{ebBus("default"), ebBus("orders")}, NextToken: awssdk.String("p2")},
			{EventBuses: []ebtypes.EventBus{ebBus("public"), ebBus("org"), ebBus("aws.partner/saas.com/x"), ebBus("denied")}},
		},
		desc: map[string]*eventbridge.DescribeEventBusOutput{
			"default":                {},
			"orders":                 {},
			"public":                 {Policy: awssdk.String(publicBusPolicy)},
			"org":                    {Policy: awssdk.String(orgBusPolicy)},
			"aws.partner/saas.com/x": {},
		},
	}
	got, err := readEventBuses(context.Background(), client, "us-east-1", "1", time.Now())
	require.NoError(t, err)
	m := indexAssetsByID(got)
	require.NotContains(t, m, "arn:default", "a default bus observed without a policy is no evidence of use")
	require.Len(t, m, 5)
	require.Equal(t, "custom", m["arn:orders"].Metadata["bus_kind"])
	require.Equal(t, "false", m["arn:orders"].Metadata["has_resource_policy"])
	require.Equal(t, asset.PublicAccessNone, m["arn:orders"].Metadata["public_access"])
	require.Equal(t, asset.PublicAccessConfirmed, m["arn:public"].Metadata["public_access"])
	require.Equal(t, asset.PublicAccessNone, m["arn:org"].Metadata["public_access"], "an org-conditioned grant is not public")
	require.Equal(t, "true", m["arn:org"].Metadata["has_resource_policy"])
	require.NotEmpty(t, m["arn:org"].Metadata["policies"])
	require.Equal(t, "partner", m["arn:aws.partner/saas.com/x"].Metadata["bus_kind"])
	require.NotContains(t, m["arn:denied"].Metadata, "has_resource_policy", "an unread policy is unknown")
	require.NotContains(t, m["arn:denied"].Metadata, "public_access")

	withDefault := &fakeEventBridge{
		pages: []*eventbridge.ListEventBusesOutput{{EventBuses: []ebtypes.EventBus{ebBus("default")}}},
		desc:  map[string]*eventbridge.DescribeEventBusOutput{"default": {Policy: awssdk.String(publicBusPolicy)}},
	}
	got, err = readEventBuses(context.Background(), withDefault, "us-east-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1, "a default bus carrying a policy is emitted so it can be graded")

	_, err = readEventBuses(context.Background(), &fakeEventBridge{pages: client.pages[:1], err: errors.New("throttled"), desc: client.desc}, "us-east-1", "1", time.Now())
	require.Error(t, err)
}
