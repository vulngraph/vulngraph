package demo

import "github.com/vulngraph/vulngraph/internal/app/asset"

// compute adds the two EC2 instances: the public web server and a private
// batch worker. The web server still allows IMDSv1, so an SSRF in the app can
// read its role's credentials.
func (b *builder) compute() {
	b.add(asset.Asset{
		ID: "i-0acme00000000web1", Name: "acme-web-1", Type: "ec2_instance", Provider: asset.ProviderAWS, Region: region,
		PublicIP: "54.210.17.34", PrivateIP: "10.0.1.14",
		Tags: map[string]string{"env": "prod", "team": "storefront"},
		Metadata: map[string]string{
			"state": "running", "instance_type": "m6i.large", "security_groups": sgWeb,
			"http_tokens": "optional", "http_endpoint": "enabled", "iam_role_arn": roleWeb,
			"subnet_id": "subnet-0acme000000000a1", "vpc_id": "vpc-0acme000000000001",
		},
	})
	b.add(asset.Asset{
		ID: "i-0acme0000000batch1", Name: "acme-batch-1", Type: "ec2_instance", Provider: asset.ProviderAWS, Region: region,
		PrivateIP: "10.0.2.31",
		Tags:      map[string]string{"env": "prod", "team": "data"},
		Metadata: map[string]string{
			"state": "running", "instance_type": "c6i.xlarge", "security_groups": sgInt,
			"http_tokens": "required", "http_endpoint": "enabled", "iam_role_arn": roleBatch,
			"subnet_id": "subnet-0acme000000000b1", "vpc_id": "vpc-0acme000000000001",
		},
	})
}
