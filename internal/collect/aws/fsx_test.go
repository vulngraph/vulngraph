package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
	"github.com/stretchr/testify/require"
)

type fakeFSx struct {
	fss   []fsxtypes.FileSystem
	page2 error
}

func (f *fakeFSx) DescribeFileSystems(_ context.Context, in *fsx.DescribeFileSystemsInput, _ ...func(*fsx.Options)) (*fsx.DescribeFileSystemsOutput, error) {
	i := fakePage(in.NextToken)
	if i == 1 && f.page2 != nil {
		return nil, f.page2
	}
	if i >= len(f.fss) {
		return &fsx.DescribeFileSystemsOutput{}, nil
	}
	return &fsx.DescribeFileSystemsOutput{FileSystems: f.fss[i : i+1], NextToken: fakeNextToken(i, len(f.fss))}, nil
}

var _ fsxAPI = (*fakeFSx)(nil)

func TestCollectFSx(t *testing.T) {
	f := &fakeFSx{fss: []fsxtypes.FileSystem{
		{
			FileSystemId: awssdk.String("fs-zfs"), ResourceARN: awssdk.String("arn:zfs"), FileSystemType: fsxtypes.FileSystemTypeOpenzfs,
			Tags:                 []fsxtypes.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("zfs")}},
			OpenZFSConfiguration: &fsxtypes.OpenZFSFileSystemConfiguration{DeploymentType: fsxtypes.OpenZFSDeploymentTypeSingleAz1, CopyTagsToBackups: awssdk.Bool(true)},
		},
		{
			FileSystemId: awssdk.String("fs-lustre"), ResourceARN: awssdk.String("arn:lustre"), FileSystemType: fsxtypes.FileSystemTypeLustre,
			LustreConfiguration: &fsxtypes.LustreFileSystemConfiguration{DeploymentType: fsxtypes.LustreDeploymentTypePersistent2},
		},
		{
			FileSystemId: awssdk.String("fs-ontap"), ResourceARN: awssdk.String("arn:ontap"), FileSystemType: fsxtypes.FileSystemTypeOntap,
			OntapConfiguration: &fsxtypes.OntapFileSystemConfiguration{DeploymentType: fsxtypes.OntapDeploymentTypeMultiAz2, FsxAdminPassword: awssdk.String("secret")},
		},
		{FileSystemId: awssdk.String("fs-win"), ResourceARN: awssdk.String("arn:win"), FileSystemType: fsxtypes.FileSystemTypeWindows},
	}}
	assets, err := collectFSxFileSystems(context.Background(), f, "us-east-1", "111111111111", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 4, "every page is read")
	got := map[string]map[string]string{}
	for _, a := range assets {
		require.Equal(t, "fsx_file_system", a.Type)
		got[a.Name] = a.Metadata
	}
	require.Equal(t, "SINGLE_AZ_1", got["zfs"]["deployment_type"])
	require.Equal(t, "true", got["zfs"]["copy_tags_to_backups"])
	require.Equal(t, "false", got["zfs"]["copy_tags_to_volumes"], "an omitted CopyTags flag is the API default, off")
	require.Equal(t, "PERSISTENT_2", got["fs-lustre"]["deployment_type"])
	require.Equal(t, "false", got["fs-lustre"]["copy_tags_to_backups"])
	require.Equal(t, "MULTI_AZ_2", got["fs-ontap"]["deployment_type"])
	for _, v := range got["fs-ontap"] {
		require.NotEqual(t, "secret", v, "the ONTAP admin password is never stored")
	}
	_, ok := got["fs-win"]["deployment_type"]
	require.False(t, ok, "a missing configuration block leaves the deployment unknown")

	_, err = collectFSxFileSystems(context.Background(), &fakeFSx{fss: f.fss[:2], page2: errFakeDenied}, "us-east-1", "111111111111", time.Now())
	require.Error(t, err, "a failed second page fails the listing")
}
