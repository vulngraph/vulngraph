package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// A publicly accessible RDS instance in a subnet routed to an internet gateway
// is one root cause: aws-rds-public-subnet-igw reports it at High (carrying the
// port evidence), and aws-rds-publicly-accessible steps aside. Either fact on
// its own still fires its own check.
func TestRDSPublicExposureFiresOnce(t *testing.T) {
	r := NewRegistry()
	r.Register(awsRDSPubliclyAccessible, awsRDSPublicSubnetIGW)
	rds := func(md map[string]string) asset.Asset {
		return asset.Asset{ID: "db", Type: "rds_instance", Provider: asset.ProviderAWS, Metadata: md}
	}
	tests := []struct {
		name string
		md   map[string]string
		want map[string]finding.Severity
	}{
		{"public and in an IGW subnet", map[string]string{"publicly_accessible": "true", "in_public_subnet": "true", "port": "5432"},
			map[string]finding.Severity{"aws-rds-public-subnet-igw": finding.SeverityHigh}},
		{"public, private subnets", map[string]string{"publicly_accessible": "true", "in_public_subnet": "false", "port": "5432"},
			map[string]finding.Severity{"aws-rds-publicly-accessible": finding.SeverityMedium}},
		{"public, routing unread", map[string]string{"publicly_accessible": "true", "port": "6000"},
			map[string]finding.Severity{"aws-rds-publicly-accessible": finding.SeverityLow}},
		{"private, in an IGW subnet", map[string]string{"publicly_accessible": "false", "in_public_subnet": "true"},
			map[string]finding.Severity{"aws-rds-public-subnet-igw": finding.SeverityMedium}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := map[string]finding.Severity{}
			for _, f := range r.Run([]asset.Asset{rds(tt.md)}, fixedTime) {
				got[f.CheckID] = f.Severity
				if f.CheckID == "aws-rds-public-subnet-igw" && tt.md["publicly_accessible"] == "true" {
					require.Equal(t, "5432", f.Metadata["port"])
					require.Equal(t, "true", f.Metadata["default_db_port"])
				}
			}
			require.Equal(t, tt.want, got)
		})
	}
}
