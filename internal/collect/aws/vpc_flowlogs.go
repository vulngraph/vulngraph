package aws

// vpc_flowlogs.go — VPC flow-log coverage (CIS AWS 4.7, FSBP EC2.6).

import (
	"context"
	"fmt"
	"strconv"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// annotateFlowLogs stamps flow_logs_enabled on each VPC: an ACTIVE flow log on
// the VPC itself capturing rejected traffic (REJECT or ALL — FSBP EC2.6's
// default; ACCEPT-only misses the denied probes the control is for). Subnet-
// and ENI-level flow logs do not count: they leave the rest of the VPC
// unlogged.
//
// Default VPCs also get in_use (any network interface in them), so the check
// can skip an untouched default VPC — AWS creates one in every region, and a
// VPC nothing runs in has no traffic to log.
//
// On error the keys stay absent: an unread flow-log listing is not a VPC
// without flow logs.
func annotateFlowLogs(ctx context.Context, client ec2API, vpcs []asset.Asset) error {
	logged := map[string]bool{}
	var next *string
	for {
		out, err := client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{NextToken: next})
		if err != nil {
			return fmt.Errorf("annotateFlowLogs: %w", err)
		}
		for _, fl := range out.FlowLogs {
			if awssdk.ToString(fl.FlowLogStatus) == "ACTIVE" &&
				(fl.TrafficType == ec2types.TrafficTypeAll || fl.TrafficType == ec2types.TrafficTypeReject) {
				logged[awssdk.ToString(fl.ResourceId)] = true
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}
	for i := range vpcs {
		v := &vpcs[i]
		v.Metadata["flow_logs_enabled"] = strconv.FormatBool(logged[v.ID])
		if v.Metadata["is_default"] != "true" || logged[v.ID] {
			continue
		}
		// One small page answers "anything here at all"; a failure leaves
		// in_use absent, which the check reads as in use.
		enis, err := client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
			Filters:    []ec2types.Filter{{Name: awssdk.String("vpc-id"), Values: []string{v.ID}}},
			MaxResults: awssdk.Int32(5),
		})
		if err == nil {
			v.Metadata["in_use"] = strconv.FormatBool(len(enis.NetworkInterfaces) > 0)
		}
	}
	return nil
}
