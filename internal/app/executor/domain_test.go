package executor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// HasExecutableAction is what respond.Decide consumes to annotate a
// remediate/modify plan no in-cluster action can carry out.
func TestHasExecutableAction(t *testing.T) {
	cases := []struct {
		resourceType string
		want         bool
	}{
		{"ec2_instance", true},
		{"security_group", true},
		{"iam_user", true},
		{"s3_bucket", true},
		{"gcp_service_account", true},
		{"gcp_firewall", true},
		{"dns_record", false},
		{"eks_cluster", false},
		{"github_repo", false},
		{"gce_instance", false},
		{"", false},
	}
	for _, tc := range cases {
		require.Equalf(t, tc.want, HasExecutableAction(tc.resourceType),
			"HasExecutableAction(%q)", tc.resourceType)
	}
}
