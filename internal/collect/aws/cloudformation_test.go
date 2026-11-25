package aws

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/stretchr/testify/require"
)

type fakeCloudFormation struct {
	pages []*cloudformation.DescribeStacksOutput
	err   error
	calls int
	// single answers a one-stack describe by stack id; a missing id fails.
	single map[string]cfntypes.Stack
	mu     sync.Mutex
}

func (f *fakeCloudFormation) DescribeStacks(_ context.Context, in *cloudformation.DescribeStacksInput, _ ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if in.StackName != nil {
		st, ok := f.single[*in.StackName]
		if !ok {
			return nil, errors.New("throttled")
		}
		return &cloudformation.DescribeStacksOutput{Stacks: []cfntypes.Stack{st}}, nil
	}
	if f.calls == len(f.pages) {
		return nil, f.err
	}
	p := f.pages[f.calls]
	f.calls++
	return p, nil
}

func TestReadCloudFormationStacks(t *testing.T) {
	client := &fakeCloudFormation{pages: []*cloudformation.DescribeStacksOutput{
		{Stacks: []cfntypes.Stack{
			{StackId: awssdk.String("arn:root"), StackName: awssdk.String("root"), StackStatus: cfntypes.StackStatusCreateComplete,
				EnableTerminationProtection: awssdk.Bool(false)},
			{StackId: awssdk.String("arn:gone"), StackStatus: cfntypes.StackStatusDeleteComplete},
		}, NextToken: awssdk.String("p2")},
		{Stacks: []cfntypes.Stack{
			{StackId: awssdk.String("arn:nested"), StackName: awssdk.String("root-Child"), StackStatus: cfntypes.StackStatusUpdateComplete,
				ParentId: awssdk.String("arn:root"), RoleARN: awssdk.String("arn:aws:iam::1:role/cfn"), EnableTerminationProtection: awssdk.Bool(true)},
			{StackId: awssdk.String("arn:noflag"), StackStatus: cfntypes.StackStatusCreateComplete},
			{StackId: awssdk.String("arn:ss"), StackName: awssdk.String("StackSet-GraphReadOnly-1a2b"), StackStatus: cfntypes.StackStatusCreateComplete},
		}},
	}, single: map[string]cfntypes.Stack{
		// The listing left the flag off; describing the one stack returns it.
		"arn:ss": {StackId: awssdk.String("arn:ss"), EnableTerminationProtection: awssdk.Bool(true)},
	}}
	got, err := readCloudFormationStacks(context.Background(), client, "us-east-1", "1", time.Now())
	require.NoError(t, err)
	m := indexAssetsByID(got)
	require.Len(t, m, 4, "DELETE_COMPLETE stacks are skipped")
	require.Equal(t, "false", m["arn:root"].Metadata["termination_protection"])
	require.Equal(t, "false", m["arn:root"].Metadata["nested"])
	require.Empty(t, m["arn:root"].Metadata["role_arn"])
	require.Equal(t, "true", m["arn:nested"].Metadata["nested"])
	require.Equal(t, "false", m["arn:root"].Metadata["stackset_instance"])
	require.Equal(t, "true", m["arn:ss"].Metadata["stackset_instance"])
	require.Equal(t, "arn:aws:iam::1:role/cfn", m["arn:nested"].Metadata["role_arn"])
	require.Equal(t, "true", m["arn:ss"].Metadata["termination_protection"], "a root stack listed without the flag is described on its own")
	require.NotContains(t, m["arn:noflag"].Metadata, "termination_protection", "a failed single-stack describe leaves it unknown")

	_, err = readCloudFormationStacks(context.Background(), &fakeCloudFormation{
		pages: client.pages[:1], err: errors.New("throttled"),
	}, "us-east-1", "1", time.Now())
	require.Error(t, err)
}
