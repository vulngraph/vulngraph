package aws

import (
	"context"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// API Gateway custom domain names and the TLS security policy each one offers
// clients (AWS FSBP APIGateway.11, AWS::ApiGateway::DomainName). The REST
// GetDomainNames listing returns every custom domain in the region, including
// ones mapped to HTTP or WebSocket APIs, so one read covers both API kinds.

const apiGatewayDomainType = "api_gateway_domain"

type apiGatewayDomainsAPI interface {
	GetDomainNames(context.Context, *apigateway.GetDomainNamesInput, ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error)
}

func collectAPIGatewayDomains(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectAPIGatewayDomains: %w", err)
	}
	return readAPIGatewayDomains(ctx, apigateway.NewFromConfig(awsCfg), region, accountID, now)
}

func readAPIGatewayDomains(ctx context.Context, client apiGatewayDomainsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		pos    *string
	)
	for {
		out, err := client.GetDomainNames(ctx, &apigateway.GetDomainNamesInput{Position: pos})
		if err != nil {
			return nil, fmt.Errorf("readAPIGatewayDomains: %w", err)
		}
		for _, d := range out.Items {
			name := awssdk.ToString(d.DomainName)
			if name == "" {
				continue
			}
			id := awssdk.ToString(d.DomainNameArn)
			if id == "" {
				id = "arn:" + partitionFor(region) + ":apigateway:" + region + "::/domainnames/" + name
			}
			meta := map[string]string{
				"domain_name":   name,
				"endpoint_type": apiEndpointScheme(d.EndpointConfiguration),
			}
			// The API always reports the policy; an empty one is an unread
			// value, so the key is left absent rather than graded.
			if p := string(d.SecurityPolicy); p != "" {
				meta["security_policy"] = p
			}
			assets = append(assets, asset.Asset{
				ID:           id,
				Name:         name,
				Type:         apiGatewayDomainType,
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Domain:       name,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.Position == nil {
			return assets, nil
		}
		pos = out.Position
	}
}
