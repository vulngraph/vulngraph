package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestCollectSnapshots_PublicFlag(t *testing.T) {
	f := &fakeEC2{
		snapshots: []ec2types.Snapshot{
			{SnapshotId: awssdk.String("snap-1"), VolumeId: awssdk.String("vol-1"), Encrypted: awssdk.Bool(false)},
		},
		snapshotPublic: true,
	}
	got, err := collectSnapshots(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "ebs_snapshot", got[0].Type)
	require.Equal(t, "true", got[0].Metadata["public"], "snapshot shared with 'all' is public")

	// A snapshot with no public permission is not flagged.
	f.snapshotPublic = false
	got, err = collectSnapshots(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Equal(t, "false", got[0].Metadata["public"])
}

// A failed public-snapshot listing must not sink the snapshot inventory: the
// sweep still emits every snapshot, with the public flag OMITTED (unknown) —
// "false" would auto-resolve real public-snapshot findings.
func TestCollectSnapshots_PublicListingError(t *testing.T) {
	f := &fakeEC2{
		snapshots: []ec2types.Snapshot{
			{SnapshotId: awssdk.String("snap-1"), VolumeId: awssdk.String("vol-1")},
		},
		snapshotPublic: true,
		snapPubErr:     errors.New("UnauthorizedOperation"),
	}
	got, err := collectSnapshots(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	_, present := got[0].Metadata["public"]
	require.False(t, present, "a failed read is unknown: neither a public flag nor a not-public fact")
	require.Equal(t, "false", got[0].Metadata["encrypted"], "the snapshot's other observed fields are kept")
}

func TestCollectImages_PublicFlag(t *testing.T) {
	f := &fakeEC2{
		images: []ec2types.Image{
			{ImageId: awssdk.String("ami-pub"), Name: awssdk.String("prod-base"), Public: awssdk.Bool(true)},
			{ImageId: awssdk.String("ami-priv"), Name: awssdk.String("internal"), Public: awssdk.Bool(false)},
		},
	}
	got, err := collectImages(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2)
	byID := map[string]string{}
	for _, a := range got {
		require.Equal(t, "ami", a.Type)
		byID[a.ID] = a.Metadata["public"]
	}
	require.Equal(t, "true", byID["ami-pub"])
	require.Equal(t, "false", byID["ami-priv"])
}

func TestAnnotateVolumeSnapshots(t *testing.T) {
	vol := func(id, region string) asset.Asset {
		return asset.Asset{ID: id, Type: "ebs_volume", Provider: asset.ProviderAWS, Region: region, Metadata: map[string]string{}}
	}
	assets := []asset.Asset{vol("vol-1", "eu-west-1"), vol("vol-2", "eu-west-1"), vol("vol-3", "us-east-1")}
	annotateVolumeSnapshots(assets, map[string]map[string]bool{"eu-west-1": {"vol-1": true}})
	require.Equal(t, "true", assets[0].Metadata["has_snapshot"])
	require.Equal(t, "false", assets[1].Metadata["has_snapshot"])
	_, present := assets[2].Metadata["has_snapshot"]
	require.False(t, present, "a region whose snapshot listing was not read stays unknown")
}

func TestSnapshotVolumeIDs(t *testing.T) {
	got := snapshotVolumeIDs([]asset.Asset{
		{Metadata: map[string]string{"volume_id": "vol-1"}},
		{Metadata: map[string]string{"volume_id": ""}},
	})
	require.Equal(t, map[string]bool{"vol-1": true}, got)
}
