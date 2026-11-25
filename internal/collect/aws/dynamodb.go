package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	aastypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	daxtypes "github.com/aws/aws-sdk-go-v2/service/dax/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// dynamodbSensitiveActions are the table-policy actions that read or change
// the table's items, or copy them out.
var dynamodbSensitiveActions = []string{
	"dynamodb:getitem", "dynamodb:batchgetitem", "dynamodb:query", "dynamodb:scan",
	"dynamodb:putitem", "dynamodb:updateitem", "dynamodb:deleteitem", "dynamodb:batchwriteitem",
	"dynamodb:partiqlselect", "dynamodb:partiqlinsert", "dynamodb:partiqlupdate", "dynamodb:partiqldelete",
	"dynamodb:exporttabletopointintime", "dynamodb:restoretabletopointintime",
}

type dynamodbAPI interface {
	ListTables(context.Context, *dynamodb.ListTablesInput, ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	DescribeContinuousBackups(context.Context, *dynamodb.DescribeContinuousBackupsInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error)
	// GetResourcePolicy answers a table without a policy with
	// PolicyNotFoundException, an observation of "no grant".
	GetResourcePolicy(context.Context, *dynamodb.GetResourcePolicyInput, ...func(*dynamodb.Options)) (*dynamodb.GetResourcePolicyOutput, error)
}

type scalableTargetsAPI interface {
	DescribeScalableTargets(context.Context, *applicationautoscaling.DescribeScalableTargetsInput, ...func(*applicationautoscaling.Options)) (*applicationautoscaling.DescribeScalableTargetsOutput, error)
}

func collectDynamoDB(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectDynamoDB: %w", err)
	}
	return collectDynamoDBTables(ctx, dynamodb.NewFromConfig(awsCfg), applicationautoscaling.NewFromConfig(awsCfg), region, accountID, now)
}

// collectDynamoDBTables emits every table with its capacity mode, auto
// scaling, point-in-time recovery, deletion protection and resource-policy
// exposure. A failed table listing fails the collector; a failed per-table or
// auto-scaling read leaves only those keys absent.
func collectDynamoDBTables(ctx context.Context, client dynamodbAPI, scaling scalableTargetsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	names, err := listDynamoDBTables(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("collectDynamoDBTables: %w", err)
	}
	if len(names) == 0 {
		return nil, nil
	}
	scaled, scalingErr := dynamodbScaledDimensions(ctx, scaling)
	if scalingErr != nil {
		log.FromContext(ctx).Warn().Err(scalingErr).Str("region", region).
			Msg("dynamodb: auto scaling targets unreadable (check application-autoscaling:DescribeScalableTargets); capacity scaling unknown this sweep")
	}
	arns := make([]string, len(names))
	metas := make([]map[string]string, len(names))
	var failed atomic.Int32
	eachBounded(ctx, len(names), eachBoundedTimeout, "dynamodb", func(ctx context.Context, i int) {
		arns[i] = "arn:" + partitionFor(region) + ":dynamodb:" + region + ":" + accountID + ":table/" + names[i]
		metas[i] = map[string]string{}
		if !readDynamoDBTable(ctx, client, names[i], scaled, metas[i], &arns[i]) {
			failed.Add(1)
		}
	})
	if n := failed.Load(); n > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int32("tables", n).
			Msg("dynamodb: some table reads failed (check dynamodb:DescribeTable, DescribeContinuousBackups, GetResourcePolicy); those settings unknown this sweep")
	}
	assets := make([]asset.Asset, 0, len(names))
	for i, name := range names {
		assets = append(assets, asset.Asset{
			ID:           arns[i],
			Name:         name,
			Type:         "dynamodb_table",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     metas[i],
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return assets, nil
}

func listDynamoDBTables(ctx context.Context, client dynamodbAPI) ([]string, error) {
	var (
		names []string
		start *string
	)
	for {
		page, err := client.ListTables(ctx, &dynamodb.ListTablesInput{ExclusiveStartTableName: start})
		if err != nil {
			return nil, fmt.Errorf("listDynamoDBTables: %w", err)
		}
		names = append(names, page.TableNames...)
		if page.LastEvaluatedTableName == nil {
			return names, nil
		}
		start = page.LastEvaluatedTableName
	}
}

// readDynamoDBTable fills one table's keys and reports whether every read
// succeeded. scaled is nil when the auto-scaling targets were unreadable.
func readDynamoDBTable(ctx context.Context, client dynamodbAPI, name string, scaled map[string]bool, meta map[string]string, arn *string) bool {
	ok := true
	if out, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: awssdk.String(name)}); err == nil && out.Table != nil {
		t := out.Table
		if a := awssdk.ToString(t.TableArn); a != "" {
			*arn = a
		}
		meta["table_status"] = string(t.TableStatus)
		// BillingModeSummary is omitted for tables that have always been
		// provisioned — PROVISIONED is the API's default capacity mode.
		mode := ddbtypes.BillingModeProvisioned
		if t.BillingModeSummary != nil && t.BillingModeSummary.BillingMode != "" {
			mode = t.BillingModeSummary.BillingMode
		}
		meta["billing_mode"] = string(mode)
		if scaled != nil {
			meta["read_autoscaling"] = strconv.FormatBool(scaled["table/"+name+"|"+string(aastypes.ScalableDimensionDynamoDBTableReadCapacityUnits)])
			meta["write_autoscaling"] = strconv.FormatBool(scaled["table/"+name+"|"+string(aastypes.ScalableDimensionDynamoDBTableWriteCapacityUnits)])
		}
		if t.DeletionProtectionEnabled != nil {
			meta["deletion_protection"] = strconv.FormatBool(*t.DeletionProtectionEnabled)
		}
	} else {
		ok = false
	}
	if out, err := client.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{TableName: awssdk.String(name)}); err == nil &&
		out.ContinuousBackupsDescription != nil && out.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
		meta["point_in_time_recovery"] = string(out.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus)
	} else {
		ok = false
	}
	var notFound *ddbtypes.PolicyNotFoundException
	switch pol, err := client.GetResourcePolicy(ctx, &dynamodb.GetResourcePolicyInput{ResourceArn: awssdk.String(*arn)}); {
	case err == nil:
		pub, policies := resourcePolicyMetadata(awssdk.ToString(pol.Policy), name+"-resource", dynamodbSensitiveActions)
		meta["public_access"] = pub
		if policies != "" {
			meta["policies"] = policies
		}
	case errors.As(err, &notFound):
		meta["public_access"] = asset.PublicAccessNone
	default:
		ok = false
	}
	return ok
}

// dynamodbScaledDimensions lists the region's DynamoDB auto-scaling targets
// once, keyed "table/<name>|<dimension>". A partial listing is an error: it
// would report scaled tables as fixed-capacity.
func dynamodbScaledDimensions(ctx context.Context, client scalableTargetsAPI) (map[string]bool, error) {
	out := map[string]bool{}
	var next *string
	for {
		page, err := client.DescribeScalableTargets(ctx, &applicationautoscaling.DescribeScalableTargetsInput{
			ServiceNamespace: aastypes.ServiceNamespaceDynamodb, NextToken: next,
		})
		if err != nil {
			return nil, fmt.Errorf("dynamodbScaledDimensions: %w", err)
		}
		for _, t := range page.ScalableTargets {
			out[awssdk.ToString(t.ResourceId)+"|"+string(t.ScalableDimension)] = true
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

// ── DAX ──────────────────────────────────────────────────────────────────────

type daxAPI interface {
	DescribeClusters(context.Context, *dax.DescribeClustersInput, ...func(*dax.Options)) (*dax.DescribeClustersOutput, error)
}

func collectDAX(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectDAX: %w", err)
	}
	return collectDAXClusters(ctx, dax.NewFromConfig(awsCfg), region, accountID, now)
}

// collectDAXClusters emits every DAX cluster with its at-rest and in-transit
// encryption (FSBP DynamoDB.3, DynamoDB.7). Both are fixed at creation and
// opt-in: an omitted SSEDescription is a cluster created without SSE, and an
// empty endpoint encryption type is the NONE default that predates TLS.
func collectDAXClusters(ctx context.Context, client daxAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		next   *string
	)
	for {
		page, err := client.DescribeClusters(ctx, &dax.DescribeClustersInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("collectDAXClusters: %w", err)
		}
		for _, c := range page.Clusters {
			sse := daxtypes.SSEStatusDisabled
			if c.SSEDescription != nil && c.SSEDescription.Status != "" {
				sse = c.SSEDescription.Status
			}
			tls := c.ClusterEndpointEncryptionType
			if tls == "" {
				tls = daxtypes.ClusterEndpointEncryptionTypeNone
			}
			assets = append(assets, asset.Asset{
				ID:        awssdk.ToString(c.ClusterArn),
				Name:      awssdk.ToString(c.ClusterName),
				Type:      "dax_cluster",
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Metadata: map[string]string{
					"sse_status":               string(sse),
					"endpoint_encryption_type": string(tls),
					"status":                   awssdk.ToString(c.Status),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.NextToken == nil {
			return assets, nil
		}
		next = page.NextToken
	}
}
