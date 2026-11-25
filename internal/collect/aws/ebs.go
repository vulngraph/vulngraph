package aws

import (
	"context"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectVolumes lists the region's EBS volumes (an EC2 API, so it reuses the
// region's ec2 client). Carries the encryption flag — unencrypted volumes are a
// common compliance finding.
func collectVolumes(ctx context.Context, client ec2API, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		token  *string
	)
	for {
		out, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("collectVolumes: %w", err)
		}
		for _, v := range out.Volumes {
			id := awssdk.ToString(v.VolumeId)
			assets = append(assets, asset.Asset{
				ID:        id,
				Name:      nameTag(v.Tags, id),
				Type:      "ebs_volume",
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Tags:      tagMap(v.Tags),
				Metadata: map[string]string{
					"encrypted":  fmt.Sprintf("%t", awssdk.ToBool(v.Encrypted)),
					"kms_key_id": awssdk.ToString(v.KmsKeyId),
					"state":      string(v.State),
					"size_gb":    fmt.Sprintf("%d", awssdk.ToInt32(v.Size)),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		token = out.NextToken
	}
}
