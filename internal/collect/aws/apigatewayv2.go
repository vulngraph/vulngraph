package aws

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apiv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// HTTP and WebSocket APIs (API Gateway v2) as api_gateway assets, beside the
// REST APIs apigateway.go reads. A v2 API has no PRIVATE endpoint type: it is
// served on a public execute-api URL (or, with that disabled, on a custom
// domain, which is just as public), so every one is public with exposure
// possible — what gates its routes is their authorization, read here from
// GetRoutes (AWS FSBP APIGateway.8). GetIntegrations supplies the private
// (VPC link) integrations that send traffic to the backend without TLS
// (APIGateway.10).
//
// Routes and integrations are rolled up onto the API — one finding per API
// listing the offending routes, not one per route. A failed route or
// integration read leaves its keys absent on the API (unknown), never empty.

type apiGatewayV2API interface {
	apiGatewayV2StagesAPI
	GetRoutes(context.Context, *apigatewayv2.GetRoutesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error)
	GetIntegrations(context.Context, *apigatewayv2.GetIntegrationsInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetIntegrationsOutput, error)
	// Custom domains and their API mappings decide whether an API with its
	// execute-api endpoint disabled is reachable at all.
	GetDomainNames(context.Context, *apigatewayv2.GetDomainNamesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetDomainNamesOutput, error)
	GetApiMappings(context.Context, *apigatewayv2.GetApiMappingsInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApiMappingsOutput, error)
}

// websocketConnectRoute is the only WebSocket route that can carry an
// authorizer: API Gateway authorizes the connection once, at $connect, and
// rejects an authorization type on every other route.
const websocketConnectRoute = "$connect"

func collectAPIGatewayV2(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectAPIGatewayV2: %w", err)
	}
	return readAPIGatewayV2(ctx, apigatewayv2.NewFromConfig(awsCfg), region, accountID, now)
}

func readAPIGatewayV2(ctx context.Context, client apiGatewayV2API, region, accountID string, now time.Time) ([]asset.Asset, error) {
	apis, err := listV2APIs(ctx, client, region)
	if err != nil {
		return nil, fmt.Errorf("readAPIGatewayV2: %w", err)
	}
	assets := make([]asset.Asset, len(apis))
	// Each goroutine writes only its own index, so no lock is needed; per-API
	// sub-read failures are logged inside v2APIAsset and never fail the listing.
	_ = forEachBounded(len(apis), apiGatewayConcurrency, func(i int) error {
		assets[i] = v2APIAsset(ctx, client, apis[i], region, accountID, now)
		return nil
	})
	stampDisabledEndpointReach(ctx, client, apis, assets, region)
	return assets, nil
}

// stampDisabledEndpointReach decides whether an API whose default
// execute-api endpoint is disabled is still reachable: only through a custom
// domain mapped to it. Mapped (or the mappings unread) it stays public — an
// unproven "unreachable" is never graded down; unmapped it answers on no
// URL at all, so it is not public. The domain read runs only when some API
// has its endpoint disabled.
func stampDisabledEndpointReach(ctx context.Context, client apiGatewayV2API, apis []apiv2types.Api, assets []asset.Asset, region string) {
	var disabled []int
	for i, api := range apis {
		if awssdk.ToBool(api.DisableExecuteApiEndpoint) {
			disabled = append(disabled, i)
		}
	}
	if len(disabled) == 0 {
		return
	}
	mapped, err := v2MappedAPIs(ctx, client)
	if err != nil {
		log.FromContext(ctx).Warn().Str("region", region).Err(err).
			Msg("apigatewayv2 custom domain mappings unreadable; APIs with the default endpoint disabled are treated as reachable")
		return
	}
	for _, i := range disabled {
		m := assets[i].Metadata
		m["custom_domain_mapped"] = strconv.FormatBool(mapped[awssdk.ToString(apis[i].ApiId)])
		if m["custom_domain_mapped"] == "false" {
			m["public"] = "false"
			delete(m, "public_access")
		}
	}
}

// v2MappedAPIs returns the ids of the APIs some custom domain in the region
// maps to. Any page error fails the read: a short list would mark mapped APIs
// unreachable.
func v2MappedAPIs(ctx context.Context, client apiGatewayV2API) (map[string]bool, error) {
	var (
		domains []string
		token   *string
	)
	for {
		out, err := client.GetDomainNames(ctx, &apigatewayv2.GetDomainNamesInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("v2MappedAPIs: GetDomainNames: %w", err)
		}
		for _, d := range out.Items {
			if n := awssdk.ToString(d.DomainName); n != "" {
				domains = append(domains, n)
			}
		}
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	mapped := map[string]bool{}
	for _, d := range domains {
		token = nil
		for {
			out, err := client.GetApiMappings(ctx, &apigatewayv2.GetApiMappingsInput{DomainName: awssdk.String(d), NextToken: token})
			if err != nil {
				return nil, fmt.Errorf("v2MappedAPIs: GetApiMappings %s: %w", d, err)
			}
			for _, m := range out.Items {
				mapped[awssdk.ToString(m.ApiId)] = true
			}
			if out.NextToken == nil {
				break
			}
			token = out.NextToken
		}
	}
	return mapped, nil
}

func v2APIAsset(ctx context.Context, client apiGatewayV2API, api apiv2types.Api, region, accountID string, now time.Time) asset.Asset {
	id := awssdk.ToString(api.ApiId)
	meta := map[string]string{
		"api_id":        id,
		"api_type":      string(api.ProtocolType),
		"endpoint_type": "REGIONAL",
		"public":        "true",
		"public_access": asset.PublicAccessPossible,
		// With the default endpoint disabled the API answers only on its
		// custom domains — still public, just not on execute-api.
		"execute_api_endpoint_disabled": strconv.FormatBool(awssdk.ToBool(api.DisableExecuteApiEndpoint)),
	}
	if open, total, err := unauthorizedRoutes(ctx, client, api); err == nil {
		meta["unauthenticated_routes"] = strings.Join(open, ",")
		meta["route_count"] = strconv.Itoa(total)
	} else {
		log.FromContext(ctx).Warn().Str("region", region).Str("api_id", id).Err(err).Msg("apigatewayv2 route read failed; the API's route authorization is unknown this sweep")
	}
	if insecure, total, err := privateIntegrationsWithoutTLS(ctx, client, id); err == nil {
		meta["private_integrations_without_tls"] = strings.Join(insecure, ",")
		meta["private_integration_count"] = strconv.Itoa(total)
	} else {
		log.FromContext(ctx).Warn().Str("region", region).Str("api_id", id).Err(err).
			Msg("apigatewayv2 integration read failed; the API's private-integration TLS is unknown this sweep")
	}
	endpoint := awssdk.ToString(api.ApiEndpoint)
	return asset.Asset{
		ID:           v2APIARN(region, id),
		Name:         awssdk.ToString(api.Name),
		Type:         "api_gateway",
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Domain:       strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "wss://"),
		Endpoint:     endpoint,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// unauthorizedRoutes returns the route keys anyone can call — authorization
// type NONE (or unset, which the API reports for NONE) — and the number of
// routes graded. On a WebSocket API only $connect is graded: it is the one
// route that can be authorized, and it gates the whole connection. A
// WebSocket API with no $connect route at all accepts every connection
// anonymously, so it is reported as an open $connect.
func unauthorizedRoutes(ctx context.Context, client apiGatewayV2API, api apiv2types.Api) ([]string, int, error) {
	var (
		open  []string
		total int
		token *string
	)
	websocket := api.ProtocolType == apiv2types.ProtocolTypeWebsocket
	for {
		out, err := client.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{ApiId: api.ApiId, NextToken: token})
		if err != nil {
			return nil, 0, fmt.Errorf("unauthorizedRoutes: %w", err)
		}
		for _, r := range out.Items {
			key := awssdk.ToString(r.RouteKey)
			if websocket && key != websocketConnectRoute {
				continue
			}
			total++
			if r.AuthorizationType == "" || r.AuthorizationType == apiv2types.AuthorizationTypeNone {
				open = append(open, key)
			}
		}
		if out.NextToken == nil {
			if websocket && total == 0 {
				return []string{websocketConnectRoute}, 1, nil
			}
			sort.Strings(open)
			return open, total, nil
		}
		token = out.NextToken
	}
}

// privateIntegrationsWithoutTLS returns the VPC-link integrations with no TLS
// configuration — API Gateway forwards to the private backend over plain
// HTTP — and how many VPC-link integrations the API has.
func privateIntegrationsWithoutTLS(ctx context.Context, client apiGatewayV2API, apiID string) ([]string, int, error) {
	var (
		insecure []string
		total    int
		token    *string
	)
	for {
		out, err := client.GetIntegrations(ctx, &apigatewayv2.GetIntegrationsInput{ApiId: awssdk.String(apiID), NextToken: token})
		if err != nil {
			return nil, 0, fmt.Errorf("privateIntegrationsWithoutTLS: %w", err)
		}
		for _, in := range out.Items {
			if in.ConnectionType != apiv2types.ConnectionTypeVpcLink {
				continue
			}
			total++
			if in.TlsConfig == nil {
				insecure = append(insecure, awssdk.ToString(in.IntegrationId))
			}
		}
		if out.NextToken == nil {
			sort.Strings(insecure)
			return insecure, total, nil
		}
		token = out.NextToken
	}
}

// listV2APIs reads every HTTP and WebSocket API in the region once per sweep
// (the API and stage collectors share it); any page error fails the whole
// listing.
func listV2APIs(ctx context.Context, client apiGatewayV2StagesAPI, region string) ([]apiv2types.Api, error) {
	return memoized(ctx, "apigatewayv2:apis:"+region, func() ([]apiv2types.Api, error) {
		return pageV2APIs(ctx, client)
	})
}

func pageV2APIs(ctx context.Context, client apiGatewayV2StagesAPI) ([]apiv2types.Api, error) {
	var (
		apis  []apiv2types.Api
		token *string
	)
	for {
		out, err := client.GetApis(ctx, &apigatewayv2.GetApisInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("listV2APIs: %w", err)
		}
		for _, api := range out.Items {
			if awssdk.ToString(api.ApiId) != "" {
				apis = append(apis, api)
			}
		}
		if out.NextToken == nil {
			return apis, nil
		}
		token = out.NextToken
	}
}

func v2APIARN(region, id string) string {
	return "arn:" + partitionFor(region) + ":apigateway:" + region + "::/apis/" + id
}
