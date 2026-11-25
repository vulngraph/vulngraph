package aws

import "strings"

// partitionRegions maps a region prefix to its AWS partition and the region
// that partition's global services (IAM, Organizations, Route 53, S3's
// ListBuckets) are signed for. Longest prefix first: "us-isob-" must win over
// "us-iso-", and both over the commercial default.
var partitionRegions = []struct{ prefix, partition, global string }{
	{"us-isob-", "aws-iso-b", "us-isob-east-1"},
	{"us-isof-", "aws-iso-f", "us-isof-south-1"},
	{"eu-isoe-", "aws-iso-e", "eu-isoe-west-1"},
	{"us-iso-", "aws-iso", "us-iso-east-1"},
	{"us-gov-", "aws-us-gov", "us-gov-west-1"},
	{"cn-", "aws-cn", "cn-north-1"},
}

// partitionFor returns the ARN partition a region belongs to. Every ARN a
// collector mints MUST use it: a hard-coded "arn:aws:" never equals the
// "arn:aws-us-gov:" / "arn:aws-cn:" ARN AWS itself returns, so in GovCloud or
// China every join between a constructed ID and a listed one silently misses.
func partitionFor(region string) string {
	for _, p := range partitionRegions {
		if strings.HasPrefix(region, p.prefix) {
			return p.partition
		}
	}
	return "aws"
}

// globalRegionFor returns the region a global service is signed for in the
// partition region belongs to. Pinning "us-east-1" outright makes every IAM /
// Organizations / Route 53 call from a GovCloud or China connector fail.
func globalRegionFor(region string) string {
	for _, p := range partitionRegions {
		if strings.HasPrefix(region, p.prefix) {
			return p.global
		}
	}
	return "us-east-1"
}
