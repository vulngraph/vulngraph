package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func collectVPNConnections(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	client, err := ec2NetworkClient(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectVPNConnections: %w", err)
	}
	return readVPNConnections(ctx, client, region, accountID, now)
}

// readVPNConnections lists the region's Site-to-Site VPN connections.
// DescribeVpnConnections has no pagination: one nil-error response is the
// whole set. Deleted connections linger in the listing and are dropped.
//
// Each tunnel fact is a count over the tunnels the response described, and is
// omitted when the response carried no tunnel data at all — no telemetry is
// not "both tunnels up", and no tunnel options is not "logging on".
func readVPNConnections(ctx context.Context, client ec2NetworkAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	out, err := client.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{})
	if err != nil {
		return nil, fmt.Errorf("readVPNConnections: %w", err)
	}
	var assets []asset.Asset
	for _, vpn := range out.VpnConnections {
		id := awssdk.ToString(vpn.VpnConnectionId)
		if id == "" || vpn.State == ec2types.VpnStateDeleted || vpn.State == ec2types.VpnStateDeleting {
			continue
		}
		meta := map[string]string{
			"state":              string(vpn.State),
			"vpn_gateway_id":     awssdk.ToString(vpn.VpnGatewayId),
			"transit_gateway_id": awssdk.ToString(vpn.TransitGatewayId),
		}
		if len(vpn.VgwTelemetry) > 0 {
			down := 0
			for _, t := range vpn.VgwTelemetry {
				if t.Status != ec2types.TelemetryStatusUp {
					down++
				}
			}
			meta["tunnel_count"] = strconv.Itoa(len(vpn.VgwTelemetry))
			meta["tunnels_down"] = strconv.Itoa(down)
		}
		if vpn.Options != nil && len(vpn.Options.TunnelOptions) > 0 {
			noLog, ikev1 := 0, 0
			for _, t := range vpn.Options.TunnelOptions {
				if !tunnelLogsToCloudWatch(t) {
					noLog++
				}
				if tunnelAllowsIKEv1(t) {
					ikev1++
				}
			}
			meta["tunnels_without_logging"] = strconv.Itoa(noLog)
			meta["tunnels_allowing_ikev1"] = strconv.Itoa(ikev1)
		}
		assets = append(assets, asset.Asset{
			ID:           id,
			Name:         nameTag(vpn.Tags, id),
			Type:         "vpn_connection",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Tags:         tagMap(vpn.Tags),
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return assets, nil
}

func tunnelLogsToCloudWatch(t ec2types.TunnelOption) bool {
	return t.LogOptions != nil && t.LogOptions.CloudWatchLogOptions != nil &&
		awssdk.ToBool(t.LogOptions.CloudWatchLogOptions.LogEnabled)
}

// tunnelAllowsIKEv1 reports whether a tunnel can negotiate IKEv1. A tunnel
// with no IKE versions listed accepts both (the AWS default), so only an
// explicit ikev2-only list passes — the FSBP EC2.183 condition.
func tunnelAllowsIKEv1(t ec2types.TunnelOption) bool {
	if len(t.IkeVersions) == 0 {
		return true
	}
	for _, v := range t.IkeVersions {
		if awssdk.ToString(v.Value) != "ikev2" {
			return true
		}
	}
	return false
}

func collectClientVPNEndpoints(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	client, err := ec2NetworkClient(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectClientVPNEndpoints: %w", err)
	}
	return readClientVPNEndpoints(ctx, client, region, accountID, now)
}

func readClientVPNEndpoints(ctx context.Context, client ec2NetworkAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		token  *string
	)
	for {
		out, err := client.DescribeClientVpnEndpoints(ctx, &ec2.DescribeClientVpnEndpointsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("readClientVPNEndpoints: %w", err)
		}
		for _, ep := range out.ClientVpnEndpoints {
			id := awssdk.ToString(ep.ClientVpnEndpointId)
			if id == "" {
				continue
			}
			meta := map[string]string{"vpc_id": awssdk.ToString(ep.VpcId)}
			if ep.Status != nil {
				if ep.Status.Code == ec2types.ClientVpnEndpointStatusCodeDeleted ||
					ep.Status.Code == ec2types.ClientVpnEndpointStatusCodeDeleting {
					continue
				}
				meta["status"] = string(ep.Status.Code)
			}
			if lo := ep.ConnectionLogOptions; lo != nil && lo.Enabled != nil {
				meta["connection_logging"] = strconv.FormatBool(*lo.Enabled)
			}
			assets = append(assets, asset.Asset{
				ID:           id,
				Name:         nameTag(ep.Tags, id),
				Type:         "client_vpn_endpoint",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Tags:         tagMap(ep.Tags),
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		token = out.NextToken
	}
}
