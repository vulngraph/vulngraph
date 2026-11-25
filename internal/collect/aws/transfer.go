package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Transfer Family servers (FSBP Transfer.2) and connectors (Transfer.3).
const (
	transferServerType    = "transfer_server"
	transferConnectorType = "transfer_connector"
)

type transferAPI interface {
	ListServers(context.Context, *transfer.ListServersInput, ...func(*transfer.Options)) (*transfer.ListServersOutput, error)
	DescribeServer(context.Context, *transfer.DescribeServerInput, ...func(*transfer.Options)) (*transfer.DescribeServerOutput, error)
	ListConnectors(context.Context, *transfer.ListConnectorsInput, ...func(*transfer.Options)) (*transfer.ListConnectorsOutput, error)
	DescribeConnector(context.Context, *transfer.DescribeConnectorInput, ...func(*transfer.Options)) (*transfer.DescribeConnectorOutput, error)
}

func collectTransfer(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectTransfer: %w", err)
	}
	return readTransfer(ctx, transfer.NewFromConfig(awsCfg), region, accountID, now)
}

// readTransfer lists servers and connectors. Either listing failing fails the
// call: a half-listed service would read as having fewer resources than it has.
func readTransfer(ctx context.Context, client transferAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	servers, err := readTransferServers(ctx, client, region, accountID, now)
	if err != nil {
		return nil, fmt.Errorf("readTransfer: %w", err)
	}
	connectors, err := readTransferConnectors(ctx, client, region, accountID, now)
	if err != nil {
		return nil, fmt.Errorf("readTransfer: %w", err)
	}
	return append(servers, connectors...), nil
}

func readTransferServers(ctx context.Context, client transferAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out          []asset.Asset
		next         *string
		describeErrs []error
	)
	for {
		page, err := client.ListServers(ctx, &transfer.ListServersInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("transfer:ListServers: %w", err)
		}
		for _, s := range page.Servers {
			id := awssdk.ToString(s.ServerId)
			meta := map[string]string{
				"state":         string(s.State),
				"endpoint_type": string(s.EndpointType),
			}
			// ListServers carries no protocol list; only DescribeServer does.
			// A failed describe leaves protocols absent (unknown).
			if d, err := client.DescribeServer(ctx, &transfer.DescribeServerInput{ServerId: s.ServerId}); err == nil && d.Server != nil {
				protocols := make([]string, 0, len(d.Server.Protocols))
				for _, p := range d.Server.Protocols {
					protocols = append(protocols, string(p))
				}
				meta["protocols"] = strings.Join(protocols, ",")
				meta["ftp_enabled"] = strconv.FormatBool(slices.Contains(d.Server.Protocols, transfertypes.ProtocolFtp))
			} else {
				describeErrs = append(describeErrs, fmt.Errorf("%s: %w", id, orEmpty(err)))
			}
			out = append(out, asset.Asset{
				ID:           awssdk.ToString(s.Arn),
				Name:         id,
				Type:         transferServerType,
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.NextToken == nil {
			break
		}
		next = page.NextToken
	}
	if len(describeErrs) > 0 {
		log.FromContext(ctx).Warn().Err(errors.Join(describeErrs...)).Str("region", region).
			Msg("transfer: server protocols unreadable (check transfer:DescribeServer); FTP use unknown for those servers this sweep")
	}
	return out, nil
}

func readTransferConnectors(ctx context.Context, client transferAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out          []asset.Asset
		next         *string
		describeErrs []error
	)
	for {
		page, err := client.ListConnectors(ctx, &transfer.ListConnectorsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("transfer:ListConnectors: %w", err)
		}
		for _, c := range page.Connectors {
			id := awssdk.ToString(c.ConnectorId)
			meta := map[string]string{"url": awssdk.ToString(c.Url)}
			// LoggingRole is the IAM role the connector writes CloudWatch logs
			// with; without one the connector logs nothing.
			if d, err := client.DescribeConnector(ctx, &transfer.DescribeConnectorInput{ConnectorId: c.ConnectorId}); err == nil && d.Connector != nil {
				meta["logging_role"] = awssdk.ToString(d.Connector.LoggingRole)
			} else {
				describeErrs = append(describeErrs, fmt.Errorf("%s: %w", id, orEmpty(err)))
			}
			out = append(out, asset.Asset{
				ID:           awssdk.ToString(c.Arn),
				Name:         id,
				Type:         transferConnectorType,
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.NextToken == nil {
			break
		}
		next = page.NextToken
	}
	if len(describeErrs) > 0 {
		log.FromContext(ctx).Warn().Err(errors.Join(describeErrs...)).Str("region", region).
			Msg("transfer: connector logging unreadable (check transfer:DescribeConnector); logging unknown for those connectors this sweep")
	}
	return out, nil
}
