package checks

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Network-placement checks over the routing facts the AWS collector derives
// from route tables (internal/collect/aws/routes.go). `in_public_subnet` is
// "true" when some subnet the resource can sit in routes to an internet
// gateway, "false" when every one was read and none does, and ABSENT when the
// route tables were not read or a default route goes somewhere public-ness
// cannot be judged from — so an unread routing table is silence, never a
// finding.

// awsRDSPublicSubnetIGW grades placement and the public flag together:
//
//   - High: publicly accessible AND in a subnet routed to an internet gateway.
//     The public DNS name resolves to an address internet clients can
//     actually connect to; only the security group and the database
//     credential stand in the way.
//   - Medium: not publicly accessible but placed in a public subnet. Not
//     reachable today, but one modify-db-instance flag away from it, with no
//     routing layer left to catch the mistake.
//
// A publicly-accessible instance whose subnets are all private stays with
// aws-rds-publicly-accessible alone: its public endpoint cannot complete a
// connection, which is exactly why this check does not fire.
var awsRDSPublicSubnetIGW = Check{
	ID:          "aws-rds-public-subnet-igw",
	Title:       "RDS instance is in a public subnet routed to an internet gateway",
	Description: "The RDS instance's DB subnet group contains a subnet whose route table sends traffic to an internet gateway. When the instance is also publicly accessible, its endpoint is reachable from the internet and only the security group and database credentials protect it. When it is not, it is one configuration change away from being reachable, with no network layer to stop it.",
	Remediation: "Move the instance to a DB subnet group made only of private subnets (route tables with no internet gateway route; use a NAT gateway for outbound access), and disable public accessibility: `aws rds modify-db-instance --db-instance-identifier ID --no-publicly-accessible`.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates:    rdsPublicSubnetIGWViolates,
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["publicly_accessible"] == "true" {
			return finding.SeverityHigh
		}
		return finding.SeverityMedium
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["publicly_accessible"] == "true" {
			return "Publicly accessible RDS instance is in a public subnet routed to an internet gateway"
		}
		return "RDS instance is in a public subnet routed to an internet gateway"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{"in_public_subnet": "true"}
		if v, ok := a.Metadata["publicly_accessible"]; ok {
			ev["publicly_accessible"] = v
		}
		if v := a.Metadata["subnet_ids"]; v != "" {
			ev["subnet_ids"] = v
		}
		// aws-rds-publicly-accessible steps aside for this check, so carry its
		// port evidence: a public endpoint on the engine's default port is what
		// scanners enumerate first.
		if port := a.Metadata["port"]; port != "" && a.Metadata["publicly_accessible"] == "true" {
			ev["port"] = port
			ev["default_db_port"] = strconv.FormatBool(isDefaultDatabasePort(port))
		}
		return ev
	},
}

// rdsPublicSubnetIGWViolates is aws-rds-public-subnet-igw's predicate, shared
// with aws-rds-publicly-accessible so that check can step aside when this one
// fires.
func rdsPublicSubnetIGWViolates(a asset.Asset) bool {
	return a.Metadata["in_public_subnet"] == "true"
}

// networkChecks returns the checks in this file for registration via Default().
func networkChecks() []Check {
	return []Check{awsRDSPublicSubnetIGW}
}
