package aws

import (
	"context"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func collectElasticIPs(ctx context.Context, client ec2API, region, accountID string, now time.Time) ([]asset.Asset, error) {
	out, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, fmt.Errorf("collectElasticIPs: %w", err)
	}
	var assets []asset.Asset
	for _, addr := range out.Addresses {
		id := awssdk.ToString(addr.AllocationId)
		if id == "" {
			id = awssdk.ToString(addr.PublicIp)
		}
		assets = append(assets, asset.Asset{
			ID:        id,
			Name:      nameTag(addr.Tags, id),
			Type:      "elastic_ip",
			Provider:  asset.ProviderAWS,
			Region:    region,
			AccountID: accountID,
			PublicIP:  awssdk.ToString(addr.PublicIp),
			Tags:      tagMap(addr.Tags),
			Metadata: map[string]string{
				"association_id":       awssdk.ToString(addr.AssociationId),
				"instance_id":          awssdk.ToString(addr.InstanceId),
				"network_interface_id": awssdk.ToString(addr.NetworkInterfaceId),
				"domain":               string(addr.Domain),
			},
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return assets, nil
}
