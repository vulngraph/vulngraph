package aws

import (
	"context"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apitypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// apiGatewayAPI is the slice of the API Gateway SDK the collector needs.
type apiGatewayAPI interface {
	GetRestApis(context.Context, *apigateway.GetRestApisInput, ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error)
}

// collectAPIGateway lists REST API Gateway endpoints for a region. Each REST
// API is a public HTTPS endpoint unless explicitly configured as PRIVATE (VPC
// endpoint only), so most surface as exposed_internet=true.
func collectAPIGateway(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectAPIGateway: %w", err)
	}
	return collectAPIGatewayAPIs(ctx, apigateway.NewFromConfig(awsCfg), region, accountID, now)
}

func collectAPIGatewayAPIs(ctx context.Context, client apiGatewayAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	apis, err := listRestAPIs(ctx, client, region)
	if err != nil {
		return nil, fmt.Errorf("collectAPIGatewayAPIs: %w", err)
	}
	assets := make([]asset.Asset, 0, len(apis))
	for _, api := range apis {
		id := awssdk.ToString(api.Id)
		domain := id + ".execute-api." + region + ".amazonaws.com"
		assets = append(assets, asset.Asset{
			ID:           restAPIARN(region, id),
			Name:         awssdk.ToString(api.Name),
			Type:         "api_gateway",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Domain:       domain,
			Endpoint:     "https://" + domain,
			Metadata:     apiGatewayMeta(id, apiEndpointScheme(api.EndpointConfiguration)),
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return assets, nil
}

// listRestAPIs reads every REST API in the region once per sweep (the API and
// stage collectors share it); any page error fails the whole listing, so a
// nil error is the complete set.
func listRestAPIs(ctx context.Context, client apiGatewayAPI, region string) ([]apitypes.RestApi, error) {
	return memoized(ctx, "apigateway:restapis:"+region, func() ([]apitypes.RestApi, error) {
		return pageRestAPIs(ctx, client)
	})
}

func pageRestAPIs(ctx context.Context, client apiGatewayAPI) ([]apitypes.RestApi, error) {
	var (
		apis []apitypes.RestApi
		pos  *string
	)
	for {
		out, err := client.GetRestApis(ctx, &apigateway.GetRestApisInput{Position: pos})
		if err != nil {
			return nil, fmt.Errorf("listRestAPIs: %w", err)
		}
		for _, api := range out.Items {
			if awssdk.ToString(api.Id) != "" {
				apis = append(apis, api)
			}
		}
		if out.Position == nil {
			return apis, nil
		}
		pos = out.Position
	}
}

func restAPIARN(region, id string) string {
	return "arn:" + partitionFor(region) + ":apigateway:" + region + "::/restapis/" + id
}

// apiGatewayMeta builds the API's metadata. A non-PRIVATE endpoint is on a
// public DNS name, but authorizers / API keys / resource policies may still
// gate every method — that config isn't collected, so exposure is possible,
// never confirmed.
func apiGatewayMeta(id, scheme string) map[string]string {
	m := map[string]string{
		"api_id":        id,
		"api_type":      "REST",
		"endpoint_type": scheme,
		"public":        fmt.Sprintf("%t", scheme != "PRIVATE"),
	}
	if scheme != "PRIVATE" {
		m["public_access"] = asset.PublicAccessPossible
	}
	return m
}

// apiEndpointScheme returns the first endpoint type for the API, or "REGIONAL"
// when no configuration is present (the AWS default for new APIs).
func apiEndpointScheme(cfg *apitypes.EndpointConfiguration) string {
	if cfg == nil || len(cfg.Types) == 0 {
		return "REGIONAL"
	}
	return string(cfg.Types[0])
}
