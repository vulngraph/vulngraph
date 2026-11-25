package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/stretchr/testify/require"
)

func TestCollectVolumes_EncryptionFlag(t *testing.T) {
	f := &fakeEC2{volumes: []ec2types.Volume{
		{VolumeId: awssdk.String("vol-enc"), Encrypted: awssdk.Bool(true), Size: awssdk.Int32(100), State: ec2types.VolumeStateInUse},
		{VolumeId: awssdk.String("vol-plain"), Encrypted: awssdk.Bool(false), Size: awssdk.Int32(8)},
	}}
	got, err := collectVolumes(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2)
	enc := map[string]string{}
	for _, a := range got {
		require.Equal(t, "ebs_volume", a.Type)
		enc[a.ID] = a.Metadata["encrypted"]
	}
	require.Equal(t, "true", enc["vol-enc"])
	require.Equal(t, "false", enc["vol-plain"])
}

type fakeEKS struct {
	names    []string
	clusters map[string]*ekstypes.Cluster
}

func (f *fakeEKS) ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	return &eks.ListClustersOutput{Clusters: f.names}, nil
}
func (f *fakeEKS) DescribeCluster(_ context.Context, in *eks.DescribeClusterInput, _ ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	c, ok := f.clusters[awssdk.ToString(in.Name)]
	if !ok {
		return nil, errors.New("not found")
	}
	return &eks.DescribeClusterOutput{Cluster: c}, nil
}

func TestCollectEKSClusters(t *testing.T) {
	f := &fakeEKS{
		names: []string{"prod"},
		clusters: map[string]*ekstypes.Cluster{
			"prod": {
				Name:               awssdk.String("prod"),
				Arn:                awssdk.String("arn:aws:eks:eu-west-1:111:cluster/prod"),
				Version:            awssdk.String("1.30"),
				Endpoint:           awssdk.String("https://abc.eks.eu-west-1.amazonaws.com"),
				ResourcesVpcConfig: &ekstypes.VpcConfigResponse{EndpointPublicAccess: true},
			},
		},
	}
	got, _, err := collectEKSClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "eks_cluster", got[0].Type)
	require.Equal(t, "1.30", got[0].Metadata["version"])
	require.Equal(t, "true", got[0].Metadata["endpoint_public_access"])
}
