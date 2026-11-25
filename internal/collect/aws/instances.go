package aws

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectInstances lists EC2 instances. profileRoles maps instance-profile ARN
// to the role ARN inside it (see instanceprofile.go); it may be nil, in which
// case no iam_role_arn is written at all.
func collectInstances(ctx context.Context, client ec2API, region, accountID string, now time.Time, profileRoles map[string]string) ([]asset.Asset, []asset.Edge, error) {
	var (
		assets []asset.Asset
		edges  []asset.Edge
		token  *string
	)
	for {
		out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{NextToken: token})
		if err != nil {
			return nil, nil, fmt.Errorf("collectInstances: %w", err)
		}
		for _, res := range out.Reservations {
			for _, inst := range res.Instances {
				// Drop transient instances that are gone or going away. Terminated
				// instances linger in DescribeInstances output for ~1h with stale
				// metadata (public_ip clears, but instance_type/http_tokens/iam_profile
				// retain their last values), which would make checks like aws-ec2-no-iam-role
				// and aws-ec2-imdsv2-not-required keep re-emitting findings on dead hosts
				// (false positives on hosts that no longer exist). Excluding them here — not a
				// collection failure, so it must NOT flag result.Partial — lets the sync
				// deletion reconciliation see them absent and auto-resolve their
				// findings — terminated instances aren't inventory.
				switch inst.State.Name {
				case ec2types.InstanceStateNameTerminated, ec2types.InstanceStateNameShuttingDown:
					continue
				}
				id := awssdk.ToString(inst.InstanceId)
				profileARN := iamProfileARN(inst.IamInstanceProfile)
				meta := map[string]string{
					"instance_id":          id,
					"instance_type":        string(inst.InstanceType),
					"vpc_id":               awssdk.ToString(inst.VpcId),
					"subnet_id":            awssdk.ToString(inst.SubnetId),
					"state":                string(inst.State.Name),
					"launched_at":          launchTime(inst.LaunchTime),
					"security_groups":      sgCSV(inst.SecurityGroups),
					"iam_instance_profile": profileARN,
					// The AMI the instance launched from: the root-cause grouping
					// key for package CVEs across a fleet (internal/jobs/vmvuln.go).
					"image_id": awssdk.ToString(inst.ImageId),
				}
				// Omitted when DescribeInstances carried no MetadataOptions: an
				// absent http_tokens must not read as "IMDSv1 allowed".
				if tokens, ok := ec2HttpTokens(inst.MetadataOptions); ok {
					meta["http_tokens"] = tokens
					// A disabled endpoint answers nothing, so optional tokens on
					// it are not an IMDSv1 exposure.
					if ep := string(inst.MetadataOptions.HttpEndpoint); ep != "" {
						meta["http_endpoint"] = ep
					}
				}
				// The boot volume the agentless disk scan reads; omitted when the
				// root device is not an EBS volume.
				if rv := rootVolumeID(inst); rv != "" {
					meta["root_volume_id"] = rv
				}
				if vt := string(inst.VirtualizationType); vt != "" {
					meta["virtualization_type"] = vt
				}
				// DescribeInstances returns every attached interface, so the count
				// is an observation whenever the instance itself was described.
				meta["eni_count"] = strconv.Itoa(len(inst.NetworkInterfaces))
				meta["source_dest_check_disabled_enis"] = strings.Join(sourceDestCheckDisabled(inst.NetworkInterfaces), ",")
				// EC2 gives an IPv6 address no separate public form: an instance
				// without a public IPv4 can still be internet-facing through one.
				meta["ipv6_addresses"] = strings.Join(ipv6Addresses(inst.NetworkInterfaces), ",")
				if inst.State.Name == ec2types.InstanceStateNameStopped {
					if at, ok := stoppedAt(awssdk.ToString(inst.StateTransitionReason)); ok {
						meta["stopped_at"] = at.Format(time.RFC3339)
					}
				}
				// The exact role ARN, resolved through IAM — never derived from the
				// profile ARN by string substitution, which silently fails for every
				// EKS managed node group. Omitted when unresolved so a consumer can
				// tell "no role known" from "no role attached".
				if roleARN, ok := instanceRoleARN(profileRoles, profileARN); ok {
					meta["iam_role_arn"] = roleARN
				}
				assets = append(assets, asset.Asset{
					ID:           id,
					Name:         nameTag(inst.Tags, id),
					Type:         "ec2_instance",
					Provider:     asset.ProviderAWS,
					Region:       region,
					AccountID:    accountID,
					PublicIP:     awssdk.ToString(inst.PublicIpAddress),
					PrivateIP:    awssdk.ToString(inst.PrivateIpAddress),
					Tags:         tagMap(inst.Tags),
					Metadata:     meta,
					DiscoveredAt: now,
					LastSeen:     now,
				})
				if accountID != "" {
					edges = append(edges, ownsEdge(accountID, id))
				}
				for _, sg := range inst.SecurityGroups {
					edges = append(edges, asset.Edge{
						SrcID: id, SrcType: "ec2_instance",
						DstID: awssdk.ToString(sg.GroupId), DstType: "security_group",
						EdgeType: "protected_by",
					})
				}
				if inst.SubnetId != nil {
					edges = append(edges, asset.Edge{
						SrcID: id, SrcType: "ec2_instance",
						DstID: awssdk.ToString(inst.SubnetId), DstType: "subnet",
						EdgeType: "in_subnet",
					})
				}
				if vpc := awssdk.ToString(inst.VpcId); vpc != "" {
					edges = append(edges, asset.Edge{
						SrcID: id, SrcType: "ec2_instance",
						DstID: vpc, DstType: "vpc",
						EdgeType: "in_vpc",
					})
				}
			}
		}
		if out.NextToken == nil {
			return assets, edges, nil
		}
		token = out.NextToken
	}
}

// stateTransitionTime matches the timestamp EC2 embeds in StateTransitionReason,
// e.g. "User initiated (2024-01-02 03:04:05 GMT)". EC2 exposes no structured
// stop time, so this string is the only record of when an instance stopped.
var stateTransitionTime = regexp.MustCompile(`\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)`)

// stoppedAt extracts the stop time from a StateTransitionReason. ok is false
// when the reason carries no parseable timestamp (some AWS-initiated stops), so
// the caller omits stopped_at rather than inventing an age.
func stoppedAt(reason string) (time.Time, bool) {
	m := stateTransitionTime.FindStringSubmatch(reason)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.DateTime, m[1])
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// ipv6Addresses returns every IPv6 address on the instance's interfaces.
func ipv6Addresses(nis []ec2types.InstanceNetworkInterface) []string {
	var out []string
	for _, ni := range nis {
		for _, a := range ni.Ipv6Addresses {
			if v := awssdk.ToString(a.Ipv6Address); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// sourceDestCheckDisabled returns the attached interfaces with source/
// destination checking switched off, of the user-managed types FSBP EC2.180
// grades (an unset type is a standard interface). Trunk interfaces are
// AWS-managed for ENI trunking and are skipped, as the control skips them.
func sourceDestCheckDisabled(nis []ec2types.InstanceNetworkInterface) []string {
	var out []string
	for _, ni := range nis {
		switch awssdk.ToString(ni.InterfaceType) {
		case "", "interface", "efa", "efa-only", "branch":
		default:
			continue
		}
		if ni.SourceDestCheck != nil && !*ni.SourceDestCheck {
			out = append(out, awssdk.ToString(ni.NetworkInterfaceId))
		}
	}
	return out
}

// rootVolumeID is the EBS volume mapped at the instance's root device.
func rootVolumeID(inst ec2types.Instance) string {
	root := awssdk.ToString(inst.RootDeviceName)
	for _, bd := range inst.BlockDeviceMappings {
		if bd.Ebs != nil && root != "" && awssdk.ToString(bd.DeviceName) == root {
			return awssdk.ToString(bd.Ebs.VolumeId)
		}
	}
	return ""
}
