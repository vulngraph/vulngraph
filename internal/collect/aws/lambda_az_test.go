package aws

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestStampLambdaAZCount(t *testing.T) {
	subnet := func(id, az string) asset.Asset {
		return asset.Asset{ID: id, Type: "subnet", Provider: asset.ProviderAWS, Metadata: map[string]string{"availability_zone": az}}
	}
	fn := func(id, subnets string) asset.Asset {
		return asset.Asset{ID: id, Type: "lambda_function", Provider: asset.ProviderAWS, Metadata: map[string]string{"subnet_ids": subnets}}
	}
	assets := []asset.Asset{
		subnet("subnet-a1", "eu-west-1a"), subnet("subnet-a2", "eu-west-1a"), subnet("subnet-b", "eu-west-1b"),
		fn("single", "subnet-a1,subnet-a2"),
		fn("multi", "subnet-a1,subnet-b"),
		fn("unknown", "subnet-a1,subnet-gone"),
		fn("no-vpc", ""),
	}
	stampLambdaAZCount(assets)
	by := map[string]map[string]string{}
	for _, a := range assets {
		by[a.ID] = a.Metadata
	}
	require.Equal(t, "1", by["single"]["vpc_az_count"])
	require.Equal(t, "2", by["multi"]["vpc_az_count"])
	require.NotContains(t, by["unknown"], "vpc_az_count", "an uncollected subnet makes the count unknown, not low")
	require.NotContains(t, by["no-vpc"], "vpc_az_count")
}
