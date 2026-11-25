package demo

import "github.com/vulngraph/vulngraph/internal/app/asset"

const (
	infraRepo = "acme-corp/infra"
	zoneID    = "Z0ACME00000001"
)

// danglingTarget is an S3 website endpoint that resolves to "no such bucket".
// The record still points at it, so anyone who creates a bucket of that name
// serves content under status.acme.example.
const danglingTarget = "acme-corp-status-decommissioned.s3-website-us-east-1.amazonaws.com"

// dns adds the public zone, a CNAME left behind when the status page's bucket
// was deleted, and the Terraform repository that declares the gateway service.
func (b *builder) dns() {
	zone := "aws-zone:" + zoneID
	b.add(asset.Asset{
		ID: zone, Name: "acme.example", Type: "dns_zone", Provider: asset.ProviderAWS, Region: "global",
		Metadata: map[string]string{"zone_id": zoneID, "provider": "aws", "private_zone": "false"},
	})
	record := zoneID + "/CNAME/status.acme.example"
	b.add(asset.Asset{
		ID: record, Name: "status.acme.example", Type: "dns_record", Provider: asset.ProviderAWS, Region: "global",
		Domain: "status.acme.example",
		Metadata: map[string]string{
			"zone_id": zoneID, "zone_name": "acme.example", "type": "CNAME", "ttl": "300",
			"values": danglingTarget, "private": "false", "public": "true",
		},
	})
	b.edges = append(b.edges, asset.Edge{
		SrcID: record, SrcType: "dns_record", DstID: zone, DstType: "dns_zone", EdgeType: "member_of_zone",
	})

	b.add(asset.Asset{
		ID: infraRepo, Name: infraRepo, Type: "github_repo", Provider: asset.ProviderGitHub, Region: "global",
		Metadata: map[string]string{"full_name": infraRepo, "visibility": "private", "default_branch": "main"},
	})
	b.add(asset.Asset{
		ID: "declared_tf_resource:" + infraRepo + ":aws_ecs_service.ai_gateway", Name: "aws_ecs_service.ai_gateway",
		Type: "declared_tf_resource",
		Metadata: map[string]string{
			"repo": infraRepo, "address": "aws_ecs_service.ai_gateway",
			"target_arn": arn("ecs", "service/acme-prod/ai-gateway"), "account_id": accountID,
		},
	})
}
