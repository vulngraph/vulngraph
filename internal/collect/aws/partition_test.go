package aws

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPartitionFor(t *testing.T) {
	tests := []struct {
		region, partition, global string
	}{
		{"eu-west-1", "aws", "us-east-1"},
		{"us-east-1", "aws", "us-east-1"},
		{"", "aws", "us-east-1"},
		{"us-gov-west-1", "aws-us-gov", "us-gov-west-1"},
		{"us-gov-east-1", "aws-us-gov", "us-gov-west-1"},
		{"cn-north-1", "aws-cn", "cn-north-1"},
		{"cn-northwest-1", "aws-cn", "cn-north-1"},
		{"us-iso-east-1", "aws-iso", "us-iso-east-1"},
		{"us-isob-east-1", "aws-iso-b", "us-isob-east-1"},
		{"eu-isoe-west-1", "aws-iso-e", "eu-isoe-west-1"},
		{"us-isof-south-1", "aws-iso-f", "us-isof-south-1"},
	}
	for _, tt := range tests {
		t.Run(tt.region, func(t *testing.T) {
			require.Equal(t, tt.partition, partitionFor(tt.region))
			require.Equal(t, tt.global, globalRegionFor(tt.region))
		})
	}
}
