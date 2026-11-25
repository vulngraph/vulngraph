package aws

import (
	"context"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// eksNodegroupAPI lists a cluster's managed node groups (FSBP EKS.9).
type eksNodegroupAPI interface {
	ListNodegroups(context.Context, *eks.ListNodegroupsInput, ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error)
	DescribeNodegroup(context.Context, *eks.DescribeNodegroupInput, ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error)
}

// collectEKSNodegroups emits one eks_nodegroup asset per managed node group of
// every described cluster, stamped with its cluster's version so the
// node-group version check can step aside when the cluster's own finding
// already covers the upgrade. partial reports a cluster whose node-group
// listing failed: its node groups are missing this sweep, not deleted. A
// failed describe emits the node group with its version absent.
func collectEKSNodegroups(ctx context.Context, client eksNodegroupAPI, clusters []asset.Asset, region, accountID string, now time.Time) ([]asset.Asset, bool) {
	var (
		out     []asset.Asset
		partial bool
	)
	for _, c := range clusters {
		if c.Type != "eks_cluster" || c.Metadata["describe_failed"] == "true" {
			continue
		}
		names, err := listNodegroups(ctx, client, c.Name)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("cluster", c.Name).Str("region", region).
				Msg("eks: node groups unavailable (check eks:ListNodegroups); not graded this sweep")
			partial = true
			continue
		}
		for _, ng := range names {
			out = append(out, eksNodegroupAsset(ctx, client, c, ng, region, accountID, now))
		}
	}
	return out, partial
}

func listNodegroups(ctx context.Context, client eksNodegroupAPI, cluster string) ([]string, error) {
	var (
		names []string
		token *string
	)
	for {
		page, err := client.ListNodegroups(ctx, &eks.ListNodegroupsInput{ClusterName: awssdk.String(cluster), NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("listNodegroups: %w", err)
		}
		names = append(names, page.Nodegroups...)
		if page.NextToken == nil {
			return names, nil
		}
		token = page.NextToken
	}
}

func eksNodegroupAsset(ctx context.Context, client eksNodegroupAPI, cluster asset.Asset, name, region, accountID string, now time.Time) asset.Asset {
	meta := map[string]string{"cluster": cluster.ID}
	if v, ok := cluster.Metadata["version"]; ok {
		meta["cluster_version"] = v
	}
	// The real ARN ends in a generated suffix only DescribeNodegroup reveals, so
	// the asset is keyed on cluster ARN + name instead: a failed describe must
	// not mint a second identity for the same node group.
	id := cluster.ID + "/nodegroup/" + name
	d, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{ClusterName: awssdk.String(cluster.Name), NodegroupName: awssdk.String(name)})
	if err != nil || d == nil || d.Nodegroup == nil {
		log.FromContext(ctx).Warn().Err(err).Str("cluster", cluster.Name).Str("nodegroup", name).
			Msg("eks: node group describe failed (check eks:DescribeNodegroup); emitted without version")
	} else {
		ng := d.Nodegroup
		if arn := awssdk.ToString(ng.NodegroupArn); arn != "" {
			meta["nodegroup_arn"] = arn
		}
		if v := awssdk.ToString(ng.Version); v != "" {
			meta["version"] = v
		}
		if v := awssdk.ToString(ng.ReleaseVersion); v != "" {
			meta["release_version"] = v
		}
		if ng.Status != "" {
			meta["status"] = string(ng.Status)
		}
	}
	return asset.Asset{
		ID:           id,
		Name:         name,
		Type:         "eks_nodegroup",
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}
