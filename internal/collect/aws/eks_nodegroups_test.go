package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeEKSNodegroups struct {
	pages      map[string][][]string // cluster → pages of node group names
	listErr    map[string]error
	nodegroups map[string]*ekstypes.Nodegroup // name → described (nil → error)
}

func (f *fakeEKSNodegroups) ListNodegroups(_ context.Context, in *eks.ListNodegroupsInput, _ ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error) {
	cluster := awssdk.ToString(in.ClusterName)
	if err := f.listErr[cluster]; err != nil {
		return nil, err
	}
	pages := f.pages[cluster]
	i := 0
	if in.NextToken != nil {
		i = int((*in.NextToken)[0] - '0')
	}
	if i >= len(pages) {
		return &eks.ListNodegroupsOutput{}, nil
	}
	out := &eks.ListNodegroupsOutput{Nodegroups: pages[i]}
	if i+1 < len(pages) {
		out.NextToken = awssdk.String(string(rune('0' + i + 1)))
	}
	return out, nil
}

func (f *fakeEKSNodegroups) DescribeNodegroup(_ context.Context, in *eks.DescribeNodegroupInput, _ ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error) {
	ng := f.nodegroups[awssdk.ToString(in.NodegroupName)]
	if ng == nil {
		return nil, errors.New("throttled")
	}
	return &eks.DescribeNodegroupOutput{Nodegroup: ng}, nil
}

func TestCollectEKSNodegroups(t *testing.T) {
	const prodARN = "arn:aws:eks:eu-west-1:111:cluster/prod"
	clusters := []asset.Asset{
		{ID: prodARN, Name: "prod", Type: "eks_cluster", Metadata: map[string]string{"version": "1.33"}},
		{ID: "arn:aws:eks:eu-west-1:111:cluster/dev", Name: "dev", Type: "eks_cluster", Metadata: map[string]string{"version": "1.34"}},
		// A cluster we could not describe is not walked: nothing about it is known.
		{ID: "arn:aws:eks:eu-west-1:111:cluster/gone", Name: "gone", Type: "eks_cluster", Metadata: map[string]string{"describe_failed": "true"}},
	}
	f := &fakeEKSNodegroups{
		pages:   map[string][][]string{"prod": {{"a"}, {"b"}}},
		listErr: map[string]error{"dev": errors.New("AccessDenied")},
		nodegroups: map[string]*ekstypes.Nodegroup{
			"a": {NodegroupArn: awssdk.String("arn:aws:eks:eu-west-1:111:nodegroup/prod/a/uuid"), Version: awssdk.String("1.31"),
				ReleaseVersion: awssdk.String("1.31.0-20250101"), Status: ekstypes.NodegroupStatusActive},
		},
	}
	got, partial := collectEKSNodegroups(context.Background(), f, clusters, "eu-west-1", "111", time.Now())
	require.True(t, partial, "a cluster whose node groups could not be listed leaves them missing, not deleted")
	require.Len(t, got, 2, "pagination is followed; a failed describe still emits the node group")

	a, b := got[0], got[1]
	require.Equal(t, prodARN+"/nodegroup/a", a.ID)
	require.Equal(t, "eks_nodegroup", a.Type)
	require.Equal(t, "1.31", a.Metadata["version"])
	require.Equal(t, "1.33", a.Metadata["cluster_version"])
	require.Equal(t, "arn:aws:eks:eu-west-1:111:nodegroup/prod/a/uuid", a.Metadata["nodegroup_arn"])

	require.Equal(t, prodARN+"/nodegroup/b", b.ID, "the same identity whether or not the describe succeeded")
	require.NotContains(t, b.Metadata, "version", "an undescribed node group's version is unknown")
	require.Equal(t, "1.33", b.Metadata["cluster_version"])
}
