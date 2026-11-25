package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Nested stacks take termination protection and the service role from the
// root stack, so only the root is graded: one finding per root cause.
func TestCFNStackChecksGradeRootStacksOnly(t *testing.T) {
	tests := []struct {
		name             string
		md               map[string]string
		protection, role bool
	}{
		{"root, unprotected, no role", map[string]string{"nested": "false", "stackset_instance": "false", "termination_protection": "false", "role_arn": ""}, true, true},
		{"root, protected, role", map[string]string{"nested": "false", "stackset_instance": "false", "termination_protection": "true", "role_arn": "arn:r"}, false, false},
		{"nested, unprotected, no role", map[string]string{"nested": "true", "stackset_instance": "false", "termination_protection": "false", "role_arn": ""}, false, false},
		// A StackSet deploys through its execution role, never the caller's credentials.
		{"stackset-named stack, no role (graded Info)", map[string]string{"nested": "false", "stackset_instance": "true", "termination_protection": "false", "role_arn": ""}, true, true},
		{"nesting unknown", map[string]string{"termination_protection": "false", "role_arn": ""}, false, false},
	}
	for _, tt := range tests {
		a := awsAsset("cloudformation_stack", tt.md)
		require.Equal(t, tt.protection, awsCFNStackNoTerminationProtection.Violates(a), tt.name)
		require.Equal(t, tt.role, awsCFNStackNoServiceRole.Violates(a), tt.name)
	}
	named := awsAsset("cloudformation_stack", map[string]string{"nested": "false", "stackset_instance": "true", "role_arn": ""})
	require.Equal(t, finding.SeverityInfo, awsCFNStackNoServiceRole.SeverityFor(named), "a spoofable name lowers the grade, it never silences")
	plain := awsAsset("cloudformation_stack", map[string]string{"nested": "false", "stackset_instance": "false", "role_arn": ""})
	require.Equal(t, finding.SeverityLow, awsCFNStackNoServiceRole.SeverityFor(plain))
}

func TestEventBridgeBusChecks(t *testing.T) {
	tests := []struct {
		name           string
		md             map[string]string
		noPolicy, open bool
	}{
		{"custom bus without a policy", map[string]string{"bus_kind": "custom", "has_resource_policy": "false", "public_access": asset.PublicAccessNone}, true, false},
		{"custom bus with an org-scoped policy", map[string]string{"bus_kind": "custom", "has_resource_policy": "true", "public_access": asset.PublicAccessNone}, false, false},
		{"custom bus open to everyone", map[string]string{"bus_kind": "custom", "has_resource_policy": "true", "public_access": asset.PublicAccessConfirmed}, false, true},
		// EventBridge.3 is about custom buses; a partner or default bus without
		// a policy is the AWS-managed shape.
		{"partner bus without a policy", map[string]string{"bus_kind": "partner", "has_resource_policy": "false"}, false, false},
		{"default bus open to everyone", map[string]string{"bus_kind": "default", "has_resource_policy": "true", "public_access": asset.PublicAccessConfirmed}, false, true},
	}
	for _, tt := range tests {
		a := awsAsset("eventbridge_bus", tt.md)
		require.Equal(t, tt.noPolicy, awsEventBridgeBusNoPolicy.Violates(a), tt.name)
		require.Equal(t, tt.open, awsEventBridgeBusPolicyPublic.Violates(a), tt.name)
	}
}

func TestDataSyncTaskLoggingDisabled(t *testing.T) {
	tests := []struct {
		name  string
		md    map[string]string
		fires bool
	}{
		{"basic, no log group", map[string]string{"log_group": "", "task_mode": "BASIC"}, true},
		{"older task with no mode, no log group", map[string]string{"log_group": "", "task_mode": ""}, true},
		{"basic, log group, level unset", map[string]string{"log_group": "arn:lg", "task_mode": "BASIC"}, false},
		{"basic, log group, level OFF", map[string]string{"log_group": "arn:lg", "task_mode": "BASIC", "log_level": "OFF"}, true},
		{"enhanced logs without a group", map[string]string{"log_group": "", "task_mode": "ENHANCED", "log_level": "TRANSFER"}, false},
		{"enhanced at level OFF", map[string]string{"log_group": "", "task_mode": "ENHANCED", "log_level": "OFF"}, true},
		{"unread", map[string]string{"status": "AVAILABLE"}, false},
	}
	for _, tt := range tests {
		require.Equal(t, tt.fires, awsDataSyncTaskLoggingDisabled.Violates(awsAsset("datasync_task", tt.md)), tt.name)
	}
}

func TestPCARootCAActive(t *testing.T) {
	tests := []struct {
		typ, status string
		fires       bool
	}{
		{"ROOT", "ACTIVE", true},
		{"ROOT", "DISABLED", false},
		{"ROOT", "PENDING_CERTIFICATE", false},
		{"ROOT", "EXPIRED", false},
		{"SUBORDINATE", "ACTIVE", false},
	}
	for _, tt := range tests {
		a := awsAsset("acmpca_certificate_authority", map[string]string{"ca_type": tt.typ, "ca_status": tt.status})
		require.Equal(t, tt.fires, awsPCARootCAActive.Violates(a), "%s/%s", tt.typ, tt.status)
	}
}

func TestSESTLSNotRequired(t *testing.T) {
	for policy, fires := range map[string]bool{"OPTIONAL": true, "REQUIRE": false} {
		require.Equal(t, fires, awsSESTLSNotRequired.Violates(awsAsset("ses_configuration_set", map[string]string{"tls_policy": policy})), policy)
	}
}

func TestServiceCatalogPortfolioAccountShareEvidence(t *testing.T) {
	a := awsAsset("servicecatalog_portfolio", map[string]string{"account_shares": "222222222222,333333333333"})
	require.True(t, awsServiceCatalogPortfolioAccountShare.Violates(a))
	require.Equal(t, map[string]string{"accounts": "222222222222,333333333333"}, awsServiceCatalogPortfolioAccountShare.EvidenceFor(a))
}
