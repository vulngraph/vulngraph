package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	appsynctypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type appsyncAPI interface {
	ListGraphqlApis(context.Context, *appsync.ListGraphqlApisInput, ...func(*appsync.Options)) (*appsync.ListGraphqlApisOutput, error)
	GetApiCache(context.Context, *appsync.GetApiCacheInput, ...func(*appsync.Options)) (*appsync.GetApiCacheOutput, error)
}

func collectAppSync(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectAppSync: %w", err)
	}
	return readAppSync(ctx, appsync.NewFromConfig(awsCfg), region, accountID, now)
}

// readAppSync lists the account's own GraphQL APIs (not ones shared into it)
// and reads each API's cache settings.
func readAppSync(ctx context.Context, client appsyncAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var assets []asset.Asset
	var next *string
	for {
		out, err := client.ListGraphqlApis(ctx, &appsync.ListGraphqlApisInput{
			Owner: appsynctypes.OwnershipCurrentAccount, NextToken: next,
		})
		if err != nil {
			return nil, fmt.Errorf("readAppSync: ListGraphqlApis: %w", err)
		}
		for _, api := range out.GraphqlApis {
			meta := graphqlAPIMetadata(api)
			appsyncCacheMetadata(ctx, client, region, api.ApiId, meta)
			assets = append(assets, asset.Asset{
				ID: awssdk.ToString(api.Arn), Name: awssdk.ToString(api.Name), Type: "appsync_graphql_api",
				Provider: asset.ProviderAWS, Region: region, AccountID: accountID, Metadata: meta,
				DiscoveredAt: now, LastSeen: now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		next = out.NextToken
	}
}

func graphqlAPIMetadata(api appsynctypes.GraphqlApi) map[string]string {
	types := []string{string(api.AuthenticationType)}
	for _, p := range api.AdditionalAuthenticationProviders {
		types = append(types, string(p.AuthenticationType))
	}
	// No log configuration means field-level logging is off; "" is that
	// observation, distinct from the key being absent.
	level := ""
	if api.LogConfig != nil {
		level = string(api.LogConfig.FieldLogLevel)
	}
	return map[string]string{
		"api_id":               awssdk.ToString(api.ApiId),
		"authentication_types": strings.Join(types, ","),
		"field_log_level":      level,
	}
}

// appsyncCacheMetadata records whether the API has a cache and, if so, its
// encryption flags. NotFoundException is the API having no cache; any other
// error leaves the keys absent.
func appsyncCacheMetadata(ctx context.Context, client appsyncAPI, region string, apiID *string, meta map[string]string) {
	out, err := client.GetApiCache(ctx, &appsync.GetApiCacheInput{ApiId: apiID})
	var notFound *appsynctypes.NotFoundException
	switch {
	case errors.As(err, &notFound):
		meta["api_cache"] = "false"
	case err != nil || out.ApiCache == nil:
		log.FromContext(ctx).Warn().Err(err).Str("region", region).Str("api_id", awssdk.ToString(apiID)).
			Msg("appsync: GetApiCache failed (check appsync:GetApiCache); cache encryption unknown this sweep")
	default:
		meta["api_cache"] = "true"
		meta["cache_at_rest_encryption"] = strconv.FormatBool(out.ApiCache.AtRestEncryptionEnabled)
		meta["cache_transit_encryption"] = strconv.FormatBool(out.ApiCache.TransitEncryptionEnabled)
	}
}
