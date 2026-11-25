package checks

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func ec2PostureAsset(typ, name string, pubIP string, md map[string]string) asset.Asset {
	return asset.Asset{ID: "x-1", Name: name, Type: typ, Provider: asset.ProviderAWS, PublicIP: pubIP, Metadata: md}
}

func TestEC2InternetFacingWithProfile(t *testing.T) {
	const arn = "arn:aws:iam::1:instance-profile/p"
	tests := []struct {
		name string
		a    asset.Asset
		want bool
	}{
		{"public ip and profile", ec2PostureAsset("ec2_instance", "i", "1.2.3.4", map[string]string{"iam_instance_profile": arn}), true},
		{"profile but private", ec2PostureAsset("ec2_instance", "i", "", map[string]string{"iam_instance_profile": arn}), false},
		{"public but no profile", ec2PostureAsset("ec2_instance", "i", "1.2.3.4", map[string]string{"iam_instance_profile": ""}), false},
		{"profile key absent", ec2PostureAsset("ec2_instance", "i", "1.2.3.4", map[string]string{}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, awsEC2InternetFacingWithProfile.Violates(tt.a))
		})
	}
}

func TestEC2InstanceTooOld(t *testing.T) {
	at := func(days int) string {
		return time.Now().Add(-time.Duration(days)*24*time.Hour - time.Hour).UTC().Format(time.RFC3339)
	}
	tests := []struct {
		name string
		md   map[string]string
		want bool
	}{
		{"running 200 days", map[string]string{"state": "running", "launched_at": at(200)}, true},
		{"running 181 days", map[string]string{"state": "running", "launched_at": at(181)}, true},
		{"running exactly 180 days is not over the limit", map[string]string{"state": "running", "launched_at": at(180)}, false},
		{"running 179 days", map[string]string{"state": "running", "launched_at": at(179)}, false},
		{"stopped and old", map[string]string{"state": "stopped", "launched_at": at(400)}, false},
		{"launch time unread", map[string]string{"state": "running", "launched_at": ""}, false},
		{"launch time absent", map[string]string{"state": "running"}, false},
		{"state absent", map[string]string{"launched_at": at(400)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, awsEC2InstanceTooOld.Violates(ec2PostureAsset("ec2_instance", "i", "", tt.md)))
		})
	}
	ev := awsEC2InstanceTooOld.EvidenceFor(ec2PostureAsset("ec2_instance", "i", "", map[string]string{"state": "running", "launched_at": at(200)}))
	require.Equal(t, "200", ev["age_days"])
}

func TestEBSSnapshotAndVolumeChecks(t *testing.T) {
	require.True(t, awsEBSSnapshotUnencrypted.Violates(ec2PostureAsset("ebs_snapshot", "s", "", map[string]string{"encrypted": "false"})))
	require.False(t, awsEBSSnapshotUnencrypted.Violates(ec2PostureAsset("ebs_snapshot", "s", "", map[string]string{"encrypted": "true"})))
	require.False(t, awsEBSSnapshotUnencrypted.Violates(ec2PostureAsset("ebs_snapshot", "s", "", map[string]string{})))

	require.True(t, awsEBSVolumeNoSnapshot.Violates(ec2PostureAsset("ebs_volume", "v", "", map[string]string{"has_snapshot": "false"})))
	require.False(t, awsEBSVolumeNoSnapshot.Violates(ec2PostureAsset("ebs_volume", "v", "", map[string]string{"has_snapshot": "true"})))
	require.False(t, awsEBSVolumeNoSnapshot.Violates(ec2PostureAsset("ebs_volume", "v", "", map[string]string{})), "unread snapshot listing is unknown, not 'no snapshot'")
}

func TestSGLaunchWizard(t *testing.T) {
	for name, want := range map[string]bool{"launch-wizard-1": true, "my-launch-wizard-2": true, "web-sg": false, "Launch-Wizard-1": false, "": false} {
		require.Equal(t, want, awsSGLaunchWizard.Violates(ec2PostureAsset("security_group", name, "", map[string]string{})), name)
	}
}

func TestSGManyRules(t *testing.T) {
	tests := []struct {
		name string
		md   map[string]string
		want bool
	}{
		{"51 ingress", map[string]string{"ingress_rules": "51", "egress_rules": "1"}, true},
		{"51 egress", map[string]string{"ingress_rules": "1", "egress_rules": "51"}, true},
		{"exactly 50 each", map[string]string{"ingress_rules": "50", "egress_rules": "50"}, false},
		{"sum over 50 but each under", map[string]string{"ingress_rules": "30", "egress_rules": "30"}, false},
		{"counts absent", map[string]string{}, false},
		{"count unreadable", map[string]string{"ingress_rules": "many", "egress_rules": ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, awsSGManyRules.Violates(ec2PostureAsset("security_group", "g", "", tt.md)))
		})
	}
	require.Equal(t, "51", awsSGManyRules.EvidenceFor(ec2PostureAsset("security_group", "g", "", map[string]string{"ingress_rules": "51"}))["ingress_rules"])
	require.Contains(t, awsSGManyRules.Description, strconv.Itoa(maxSGRulesPerDirection))
	require.False(t, strings.Contains(awsSGManyRules.Remediation, "TODO"))
}
