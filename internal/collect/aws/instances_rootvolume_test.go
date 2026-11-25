package aws

import (
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
)

func TestRootVolumeID(t *testing.T) {
	inst := ec2types.Instance{
		RootDeviceName: awssdk.String("/dev/xvda"),
		BlockDeviceMappings: []ec2types.InstanceBlockDeviceMapping{
			{DeviceName: awssdk.String("/dev/xvdb"), Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: awssdk.String("vol-data")}},
			{DeviceName: awssdk.String("/dev/xvda"), Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: awssdk.String("vol-root")}},
		},
	}
	require.Equal(t, "vol-root", rootVolumeID(inst))
	require.Empty(t, rootVolumeID(ec2types.Instance{BlockDeviceMappings: inst.BlockDeviceMappings}), "no root device named")
	require.Empty(t, rootVolumeID(ec2types.Instance{RootDeviceName: awssdk.String("/dev/sda1")}), "instance store root")
}
