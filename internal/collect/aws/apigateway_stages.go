package aws

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apitypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apiv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// API Gateway stages, the resource AWS FSBP APIGateway.1-.5 grade
// (AWS::ApiGateway::Stage, AWS::ApiGatewayV2::Stage): execution logging,
// backend client certificate, X-Ray tracing, WAF association and cache
// encryption are all per-stage settings, so each stage is its own
// api_gateway_stage asset and each setting is one finding per stage.
//
// Stages are a separate task from the API listing (apigateway.go,
// apigatewayv2.go) so a failed stage read never costs the APIs themselves.
// Any failed GetStages fails the whole read: the stages are assets, and a
// short list would make the missing ones look deleted.

const apiGatewayStageType = "api_gateway_stage"

// apiGatewayConcurrency bounds per-API describe calls. API Gateway's GET
// limits are account-wide and low (around 10 requests per second), so the
// fan-out stays narrow and the SDK retryer absorbs bursts.
const apiGatewayConcurrency = 4

// restStageWide is the methodSettings key for settings that apply to every
// method of a REST stage.
const restStageWide = "*/*"

type apiGatewayStagesAPI interface {
	apiGatewayAPI
	GetStages(context.Context, *apigateway.GetStagesInput, ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error)
}

type apiGatewayV2StagesAPI interface {
	GetApis(context.Context, *apigatewayv2.GetApisInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error)
	GetStages(context.Context, *apigatewayv2.GetStagesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error)
}

func collectAPIGatewayStages(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectAPIGatewayStages: %w", err)
	}
	return readAPIGatewayStages(ctx, apigateway.NewFromConfig(awsCfg), apigatewayv2.NewFromConfig(awsCfg), region, accountID, now)
}

func readAPIGatewayStages(ctx context.Context, rest apiGatewayStagesAPI, v2 apiGatewayV2StagesAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	restAPIs, err := listRestAPIs(ctx, rest, region)
	if err != nil {
		return nil, fmt.Errorf("readAPIGatewayStages: %w", err)
	}
	v2APIs, err := listV2APIs(ctx, v2, region)
	if err != nil {
		return nil, fmt.Errorf("readAPIGatewayStages: %w", err)
	}
	var (
		mu     sync.Mutex
		assets []asset.Asset
	)
	add := func(more []asset.Asset) {
		mu.Lock()
		assets = append(assets, more...)
		mu.Unlock()
	}
	err = forEachBounded(len(restAPIs)+len(v2APIs), apiGatewayConcurrency, func(i int) error {
		if i < len(restAPIs) {
			more, err := restStages(ctx, rest, restAPIs[i], region, accountID, now)
			add(more)
			return err
		}
		more, err := v2Stages(ctx, v2, v2APIs[i-len(restAPIs)], region, accountID, now)
		add(more)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("readAPIGatewayStages: %w", err)
	}
	return assets, nil
}

func restStages(ctx context.Context, client apiGatewayStagesAPI, api apitypes.RestApi, region, accountID string, now time.Time) ([]asset.Asset, error) {
	id := awssdk.ToString(api.Id)
	// GetStages is not paginated: one call returns every stage of the API.
	out, err := client.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: api.Id})
	if err != nil {
		return nil, fmt.Errorf("restStages %s: %w", id, err)
	}
	public := apiEndpointScheme(api.EndpointConfiguration) != "PRIVATE"
	assets := make([]asset.Asset, 0, len(out.Item))
	for _, st := range out.Item {
		name := awssdk.ToString(st.StageName)
		meta := restStageMeta(st)
		meta["api_id"] = id
		meta["public"] = strconv.FormatBool(public)
		assets = append(assets, stageAsset(restAPIARN(region, id)+"/stages/"+name, awssdk.ToString(api.Name)+"/"+name, region, accountID, meta, now))
	}
	return assets, nil
}

// restStageMeta reads one REST stage's settings. Every key is written: the
// stage was read, so an unset setting is an observed "off", not an unknown.
func restStageMeta(st apitypes.Stage) map[string]string {
	level, on := restExecutionLogging(st.MethodSettings)
	return map[string]string{
		"api_type":                  "REST",
		"stage_name":                awssdk.ToString(st.StageName),
		"logging_level":             level,
		"execution_logging":         strconv.FormatBool(on),
		"client_certificate_id":     awssdk.ToString(st.ClientCertificateId),
		"tracing_enabled":           strconv.FormatBool(st.TracingEnabled),
		"waf_web_acl_arn":           awssdk.ToString(st.WebAclArn),
		"cache_cluster_enabled":     strconv.FormatBool(st.CacheClusterEnabled),
		"cache_unencrypted_methods": strings.Join(unencryptedCacheMethods(st.MethodSettings), ","),
		"access_log_destination":    restAccessLogDestination(st.AccessLogSettings),
	}
}

// restAccessLogDestination is the stage's access-log destination ARN, "" when
// access logging is off. Read for the logging checks (APIGateway.9 / CIS 4.10).
func restAccessLogDestination(s *apitypes.AccessLogSettings) string {
	if s == nil {
		return ""
	}
	return awssdk.ToString(s.DestinationArn)
}

// restExecutionLogging returns the stage-wide logging level ("OFF" when the
// stage sets none — API Gateway's default) and whether execution logging is on
// for every method: ERROR or INFO stage-wide, and no method override turning
// it OFF (FSBP APIGateway.1 requires it for the whole stage).
func restExecutionLogging(settings map[string]apitypes.MethodSetting) (string, bool) {
	level := "OFF"
	if s, ok := settings[restStageWide]; ok && awssdk.ToString(s.LoggingLevel) != "" {
		level = strings.ToUpper(awssdk.ToString(s.LoggingLevel))
	}
	on := level == "ERROR" || level == "INFO"
	for key, s := range settings {
		if key != restStageWide && strings.EqualFold(awssdk.ToString(s.LoggingLevel), "OFF") {
			on = false
		}
	}
	return level, on
}

// unencryptedCacheMethods lists the method-setting keys that cache responses
// without encrypting the cache (FSBP APIGateway.5 evaluates only methods with
// caching on), sorted so the value is stable across sweeps.
func unencryptedCacheMethods(settings map[string]apitypes.MethodSetting) []string {
	var out []string
	for key, s := range settings {
		if s.CachingEnabled && !s.CacheDataEncrypted {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func v2Stages(ctx context.Context, client apiGatewayV2StagesAPI, api apiv2types.Api, region, accountID string, now time.Time) ([]asset.Asset, error) {
	id := awssdk.ToString(api.ApiId)
	var (
		assets []asset.Asset
		token  *string
	)
	for {
		out, err := client.GetStages(ctx, &apigatewayv2.GetStagesInput{ApiId: api.ApiId, NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("v2Stages %s: %w", id, err)
		}
		for _, st := range out.Items {
			name := awssdk.ToString(st.StageName)
			meta := v2StageMeta(api.ProtocolType, st)
			meta["api_id"] = id
			assets = append(assets, stageAsset(v2APIARN(region, id)+"/stages/"+name, awssdk.ToString(api.Name)+"/"+name, region, accountID, meta, now))
		}
		if out.NextToken == nil {
			return assets, nil
		}
		token = out.NextToken
	}
}

// v2StageMeta reads one HTTP or WebSocket stage. Execution logging exists only
// for WebSocket APIs (HTTP APIs have access logging alone), so an HTTP stage
// carries no logging keys and the logging check does not apply to it. v2 APIs
// have no private endpoint type: every stage is on a public execute-api URL.
func v2StageMeta(protocol apiv2types.ProtocolType, st apiv2types.Stage) map[string]string {
	meta := map[string]string{
		"api_type":   string(protocol),
		"stage_name": awssdk.ToString(st.StageName),
		"public":     "true",
		// The access-log destination ARN, "" when access logging is off; read
		// for the logging checks (APIGateway.9 / CIS 4.10).
		"access_log_destination": "",
	}
	if st.AccessLogSettings != nil {
		meta["access_log_destination"] = awssdk.ToString(st.AccessLogSettings.DestinationArn)
	}
	if protocol != apiv2types.ProtocolTypeWebsocket {
		return meta
	}
	level := "OFF"
	if st.DefaultRouteSettings != nil && st.DefaultRouteSettings.LoggingLevel != "" {
		level = string(st.DefaultRouteSettings.LoggingLevel)
	}
	on := level == "ERROR" || level == "INFO"
	for _, rs := range st.RouteSettings {
		if rs.LoggingLevel == apiv2types.LoggingLevelOff {
			on = false
		}
	}
	meta["logging_level"] = level
	meta["execution_logging"] = strconv.FormatBool(on)
	return meta
}

func stageAsset(id, name, region, accountID string, meta map[string]string, now time.Time) asset.Asset {
	return asset.Asset{
		ID:           id,
		Name:         name,
		Type:         apiGatewayStageType,
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}
