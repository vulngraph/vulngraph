package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apitypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apiv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeAPIGatewayREST struct {
	apis      []apitypes.RestApi
	stages    map[string][]apitypes.Stage
	stagesErr error
	domains   [][]apitypes.DomainName // pages
	domainErr error
}

func (f *fakeAPIGatewayREST) GetRestApis(context.Context, *apigateway.GetRestApisInput, ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	return &apigateway.GetRestApisOutput{Items: f.apis}, nil
}

func (f *fakeAPIGatewayREST) GetStages(_ context.Context, in *apigateway.GetStagesInput, _ ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
	if f.stagesErr != nil {
		return nil, f.stagesErr
	}
	return &apigateway.GetStagesOutput{Item: f.stages[awssdk.ToString(in.RestApiId)]}, nil
}

func (f *fakeAPIGatewayREST) GetDomainNames(_ context.Context, in *apigateway.GetDomainNamesInput, _ ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
	if f.domainErr != nil {
		return nil, f.domainErr
	}
	page := 0
	if in.Position != nil {
		page = 1
	}
	out := &apigateway.GetDomainNamesOutput{Items: f.domains[page]}
	if page+1 < len(f.domains) {
		out.Position = awssdk.String("p2")
	}
	return out, nil
}

type fakeAPIGatewayV2 struct {
	apis      []apiv2types.Api
	stages    map[string][][]apiv2types.Stage // pages per API
	routes    map[string][]apiv2types.Route
	routesErr error
	integ     map[string][]apiv2types.Integration
	domains   []string
	mappings  map[string][]apiv2types.ApiMapping
	domainErr error
}

func (f *fakeAPIGatewayV2) GetDomainNames(context.Context, *apigatewayv2.GetDomainNamesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetDomainNamesOutput, error) {
	if f.domainErr != nil {
		return nil, f.domainErr
	}
	out := &apigatewayv2.GetDomainNamesOutput{}
	for _, d := range f.domains {
		out.Items = append(out.Items, apiv2types.DomainName{DomainName: awssdk.String(d)})
	}
	return out, nil
}

func (f *fakeAPIGatewayV2) GetApiMappings(_ context.Context, in *apigatewayv2.GetApiMappingsInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApiMappingsOutput, error) {
	return &apigatewayv2.GetApiMappingsOutput{Items: f.mappings[awssdk.ToString(in.DomainName)]}, nil
}

func (f *fakeAPIGatewayV2) GetApis(context.Context, *apigatewayv2.GetApisInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	return &apigatewayv2.GetApisOutput{Items: f.apis}, nil
}

func (f *fakeAPIGatewayV2) GetStages(_ context.Context, in *apigatewayv2.GetStagesInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error) {
	pages := f.stages[awssdk.ToString(in.ApiId)]
	if len(pages) == 0 {
		return &apigatewayv2.GetStagesOutput{}, nil
	}
	page := 0
	if in.NextToken != nil {
		page = 1
	}
	out := &apigatewayv2.GetStagesOutput{Items: pages[page]}
	if page+1 < len(pages) {
		out.NextToken = awssdk.String("next")
	}
	return out, nil
}

func (f *fakeAPIGatewayV2) GetRoutes(_ context.Context, in *apigatewayv2.GetRoutesInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error) {
	if f.routesErr != nil {
		return nil, f.routesErr
	}
	return &apigatewayv2.GetRoutesOutput{Items: f.routes[awssdk.ToString(in.ApiId)]}, nil
}

func (f *fakeAPIGatewayV2) GetIntegrations(_ context.Context, in *apigatewayv2.GetIntegrationsInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetIntegrationsOutput, error) {
	return &apigatewayv2.GetIntegrationsOutput{Items: f.integ[awssdk.ToString(in.ApiId)]}, nil
}

func TestReadAPIGatewayStages(t *testing.T) {
	rest := &fakeAPIGatewayREST{
		apis: []apitypes.RestApi{
			{Id: awssdk.String("r1"), Name: awssdk.String("orders")},
			{Id: awssdk.String("r2"), Name: awssdk.String("internal"),
				EndpointConfiguration: &apitypes.EndpointConfiguration{Types: []apitypes.EndpointType{apitypes.EndpointTypePrivate}}},
		},
		stages: map[string][]apitypes.Stage{
			// A stage with nothing configured: every key is an observed "off".
			"r1": {{StageName: awssdk.String("prod")}},
			"r2": {{
				StageName:           awssdk.String("live"),
				ClientCertificateId: awssdk.String("cert-1"),
				TracingEnabled:      true,
				WebAclArn:           awssdk.String("arn:aws:wafv2:eu-west-1:1:regional/webacl/x/y"),
				CacheClusterEnabled: true,
				AccessLogSettings:   &apitypes.AccessLogSettings{DestinationArn: awssdk.String("arn:aws:logs:eu-west-1:1:log-group:rest")},
				MethodSettings: map[string]apitypes.MethodSetting{
					"*/*":         {LoggingLevel: awssdk.String("INFO"), CachingEnabled: true, CacheDataEncrypted: true},
					"/orders/GET": {LoggingLevel: awssdk.String("OFF"), CachingEnabled: true},
				},
			}},
		},
	}
	v2 := &fakeAPIGatewayV2{
		apis: []apiv2types.Api{
			{ApiId: awssdk.String("h1"), Name: awssdk.String("http"), ProtocolType: apiv2types.ProtocolTypeHttp},
			{ApiId: awssdk.String("w1"), Name: awssdk.String("ws"), ProtocolType: apiv2types.ProtocolTypeWebsocket},
		},
		stages: map[string][][]apiv2types.Stage{
			"h1": {{{StageName: awssdk.String("$default"), AccessLogSettings: &apiv2types.AccessLogSettings{DestinationArn: awssdk.String("arn:aws:logs:eu-west-1:1:log-group:http")}}}},
			// Two pages: the second page's stage must not be dropped.
			"w1": {
				{{StageName: awssdk.String("a"), DefaultRouteSettings: &apiv2types.RouteSettings{LoggingLevel: apiv2types.LoggingLevelError}}},
				{{StageName: awssdk.String("b")}},
			},
		},
	}
	got, err := readAPIGatewayStages(context.Background(), rest, v2, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 5)
	m := byID(got)

	prod := m["arn:aws:apigateway:eu-west-1::/restapis/r1/stages/prod"]
	require.Equal(t, apiGatewayStageType, prod.Type)
	require.Equal(t, map[string]string{
		"api_id": "r1", "api_type": "REST", "stage_name": "prod", "public": "true",
		"logging_level": "OFF", "execution_logging": "false", "client_certificate_id": "",
		"tracing_enabled": "false", "waf_web_acl_arn": "", "cache_cluster_enabled": "false",
		"cache_unencrypted_methods": "", "access_log_destination": "",
	}, prod.Metadata)

	live := m["arn:aws:apigateway:eu-west-1::/restapis/r2/stages/live"].Metadata
	require.Equal(t, "false", live["public"])
	require.Equal(t, "INFO", live["logging_level"])
	require.Equal(t, "false", live["execution_logging"], "a method override turning logging OFF fails the stage")
	require.Equal(t, "/orders/GET", live["cache_unencrypted_methods"])
	require.Equal(t, "true", live["tracing_enabled"])
	require.Equal(t, "arn:aws:logs:eu-west-1:1:log-group:rest", live["access_log_destination"])

	http := m["arn:aws:apigateway:eu-west-1::/apis/h1/stages/$default"].Metadata
	require.Equal(t, "HTTP", http["api_type"])
	require.NotContains(t, http, "execution_logging", "HTTP APIs have no execution logging to grade")
	require.Equal(t, "arn:aws:logs:eu-west-1:1:log-group:http", http["access_log_destination"])
	require.Equal(t, "", m["arn:aws:apigateway:eu-west-1::/apis/w1/stages/b"].Metadata["access_log_destination"], "access logging off is an observation")

	require.Equal(t, "true", m["arn:aws:apigateway:eu-west-1::/apis/w1/stages/a"].Metadata["execution_logging"])
	require.Equal(t, "false", m["arn:aws:apigateway:eu-west-1::/apis/w1/stages/b"].Metadata["execution_logging"],
		"an unset WebSocket logging level is API Gateway's default OFF")
}

func TestReadAPIGatewayStagesFailsWholeOnStageError(t *testing.T) {
	rest := &fakeAPIGatewayREST{apis: []apitypes.RestApi{{Id: awssdk.String("r1")}}, stagesErr: errors.New("throttled")}
	_, err := readAPIGatewayStages(context.Background(), rest, &fakeAPIGatewayV2{}, "eu-west-1", "111", time.Now())
	require.Error(t, err, "a short stage list would make the unread stages look deleted")
}

func TestReadAPIGatewayV2(t *testing.T) {
	v2 := &fakeAPIGatewayV2{
		apis: []apiv2types.Api{
			{ApiId: awssdk.String("h1"), Name: awssdk.String("http"), ProtocolType: apiv2types.ProtocolTypeHttp,
				ApiEndpoint: awssdk.String("https://h1.execute-api.eu-west-1.amazonaws.com")},
			{ApiId: awssdk.String("w1"), ProtocolType: apiv2types.ProtocolTypeWebsocket},
		},
		routes: map[string][]apiv2types.Route{
			"h1": {
				{RouteKey: awssdk.String("GET /public"), AuthorizationType: apiv2types.AuthorizationTypeNone},
				{RouteKey: awssdk.String("$default")}, // unset reads as NONE
				{RouteKey: awssdk.String("POST /orders"), AuthorizationType: apiv2types.AuthorizationTypeJwt},
			},
			"w1": {
				{RouteKey: awssdk.String("$connect"), AuthorizationType: apiv2types.AuthorizationTypeCustom},
				// Non-$connect WebSocket routes cannot be authorized: not graded.
				{RouteKey: awssdk.String("sendmessage"), AuthorizationType: apiv2types.AuthorizationTypeNone},
			},
		},
		integ: map[string][]apiv2types.Integration{
			"h1": {
				{IntegrationId: awssdk.String("i1"), ConnectionType: apiv2types.ConnectionTypeVpcLink},
				{IntegrationId: awssdk.String("i2"), ConnectionType: apiv2types.ConnectionTypeVpcLink,
					TlsConfig: &apiv2types.TlsConfig{ServerNameToVerify: awssdk.String("api.internal")}},
				{IntegrationId: awssdk.String("i3"), ConnectionType: apiv2types.ConnectionTypeInternet},
			},
		},
	}
	got, err := readAPIGatewayV2(context.Background(), v2, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	m := byID(got)
	h := m["arn:aws:apigateway:eu-west-1::/apis/h1"]
	require.Equal(t, "api_gateway", h.Type)
	require.Equal(t, "h1.execute-api.eu-west-1.amazonaws.com", h.Domain)
	require.Equal(t, "$default,GET /public", h.Metadata["unauthenticated_routes"])
	require.Equal(t, "3", h.Metadata["route_count"])
	require.Equal(t, "i1", h.Metadata["private_integrations_without_tls"])
	require.Equal(t, "2", h.Metadata["private_integration_count"])
	require.Equal(t, asset.PublicAccessPossible, h.Metadata["public_access"])

	w := m["arn:aws:apigateway:eu-west-1::/apis/w1"].Metadata
	require.Equal(t, "", w["unauthenticated_routes"])
	require.Equal(t, "1", w["route_count"])
	require.Equal(t, "", w["private_integrations_without_tls"], "no VPC-link integration is an observed none")

	v2.routesErr = errors.New("AccessDenied")
	got, err = readAPIGatewayV2(context.Background(), v2, "eu-west-1", "111", time.Now())
	require.NoError(t, err, "a failed route read keeps the API")
	require.NotContains(t, got[0].Metadata, "unauthenticated_routes", "an unread route set is unknown, never empty")
	require.NotContains(t, got[0].Metadata, "route_count")
}

func TestReadAPIGatewayDomains(t *testing.T) {
	rest := &fakeAPIGatewayREST{domains: [][]apitypes.DomainName{
		{{DomainName: awssdk.String("api.example.com"), SecurityPolicy: apitypes.SecurityPolicyTls12}},
		{{DomainName: awssdk.String("new.example.com"), SecurityPolicy: "SecurityPolicy_TLS13_1_3_2025_09",
			DomainNameArn: awssdk.String("arn:aws:apigateway:eu-west-1::/domainnames/new.example.com+abc")},
			{DomainName: awssdk.String("unread.example.com")}},
	}}
	got, err := readAPIGatewayDomains(context.Background(), rest, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3, "both pages are read")
	m := byID(got)
	require.Equal(t, "TLS_1_2", m["arn:aws:apigateway:eu-west-1::/domainnames/api.example.com"].Metadata["security_policy"])
	require.Equal(t, "SecurityPolicy_TLS13_1_3_2025_09", m["arn:aws:apigateway:eu-west-1::/domainnames/new.example.com+abc"].Metadata["security_policy"])
	require.NotContains(t, m["arn:aws:apigateway:eu-west-1::/domainnames/unread.example.com"].Metadata, "security_policy")

	rest.domainErr = errors.New("throttled")
	_, err = readAPIGatewayDomains(context.Background(), rest, "eu-west-1", "111", time.Now())
	require.Error(t, err)
}

// An API with its default endpoint disabled answers only on custom domains
// mapped to it: unmapped it is unreachable (not public, routes not graded);
// mapped, or with the mappings unread, it stays public.
func TestReadAPIGatewayV2DisabledEndpointReach(t *testing.T) {
	disabled := func(id string) apiv2types.Api {
		return apiv2types.Api{ApiId: awssdk.String(id), ProtocolType: apiv2types.ProtocolTypeHttp, DisableExecuteApiEndpoint: awssdk.Bool(true)}
	}
	v2 := &fakeAPIGatewayV2{
		apis:     []apiv2types.Api{disabled("mapped"), disabled("orphan"), {ApiId: awssdk.String("default"), ProtocolType: apiv2types.ProtocolTypeHttp}},
		domains:  []string{"api.example.com"},
		mappings: map[string][]apiv2types.ApiMapping{"api.example.com": {{ApiId: awssdk.String("mapped")}}},
	}
	got, err := readAPIGatewayV2(context.Background(), v2, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	m := byID(got)
	mapped := m["arn:aws:apigateway:eu-west-1::/apis/mapped"].Metadata
	require.Equal(t, "true", mapped["custom_domain_mapped"])
	require.Equal(t, "true", mapped["public"])
	orphan := m["arn:aws:apigateway:eu-west-1::/apis/orphan"].Metadata
	require.Equal(t, "false", orphan["custom_domain_mapped"])
	require.Equal(t, "false", orphan["public"], "no URL answers for it")
	require.NotContains(t, orphan, "public_access")
	require.NotContains(t, m["arn:aws:apigateway:eu-west-1::/apis/default"].Metadata, "custom_domain_mapped")

	v2.domainErr = errors.New("throttled")
	got, err = readAPIGatewayV2(context.Background(), v2, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	orphan = byID(got)["arn:aws:apigateway:eu-west-1::/apis/orphan"].Metadata
	require.Equal(t, "true", orphan["public"], "unread mappings never grade an API unreachable")
	require.NotContains(t, orphan, "custom_domain_mapped")
}

func TestReadAPIGatewayV2WebSocketWithoutConnectRoute(t *testing.T) {
	v2 := &fakeAPIGatewayV2{
		apis:   []apiv2types.Api{{ApiId: awssdk.String("w"), ProtocolType: apiv2types.ProtocolTypeWebsocket}},
		routes: map[string][]apiv2types.Route{"w": {{RouteKey: awssdk.String("$default")}}},
	}
	got, err := readAPIGatewayV2(context.Background(), v2, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Equal(t, "$connect", got[0].Metadata["unauthenticated_routes"], "no $connect route accepts every connection anonymously")
	require.Equal(t, "1", got[0].Metadata["route_count"])
}
