package aws

import (
	"context"
	"net"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	aastypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	daxtypes "github.com/aws/aws-sdk-go-v2/service/dax/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeDynamoDB struct {
	tables    []string
	page2     error
	describe  map[string]*ddbtypes.TableDescription // absent ⇒ AccessDenied
	pitr      map[string]ddbtypes.PointInTimeRecoveryStatus
	policies  map[string]string // absent ⇒ PolicyNotFoundException
	policyErr map[string]error
}

func (f *fakeDynamoDB) ListTables(_ context.Context, in *dynamodb.ListTablesInput, _ ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	i := 0
	if in.ExclusiveStartTableName != nil {
		for j, n := range f.tables {
			if n == *in.ExclusiveStartTableName {
				i = j + 1
			}
		}
	}
	if i == 1 && f.page2 != nil {
		return nil, f.page2
	}
	if i >= len(f.tables) {
		return &dynamodb.ListTablesOutput{}, nil
	}
	out := &dynamodb.ListTablesOutput{TableNames: f.tables[i : i+1]}
	if i+1 < len(f.tables) {
		out.LastEvaluatedTableName = awssdk.String(f.tables[i])
	}
	return out, nil
}

func (f *fakeDynamoDB) DescribeTable(_ context.Context, in *dynamodb.DescribeTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	t, ok := f.describe[awssdk.ToString(in.TableName)]
	if !ok {
		return nil, errFakeDenied
	}
	return &dynamodb.DescribeTableOutput{Table: t}, nil
}

func (f *fakeDynamoDB) DescribeContinuousBackups(_ context.Context, in *dynamodb.DescribeContinuousBackupsInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
	s, ok := f.pitr[awssdk.ToString(in.TableName)]
	if !ok {
		return nil, errFakeDenied
	}
	return &dynamodb.DescribeContinuousBackupsOutput{ContinuousBackupsDescription: &ddbtypes.ContinuousBackupsDescription{
		PointInTimeRecoveryDescription: &ddbtypes.PointInTimeRecoveryDescription{PointInTimeRecoveryStatus: s},
	}}, nil
}

func (f *fakeDynamoDB) GetResourcePolicy(_ context.Context, in *dynamodb.GetResourcePolicyInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetResourcePolicyOutput, error) {
	arn := awssdk.ToString(in.ResourceArn)
	if err := f.policyErr[arn]; err != nil {
		return nil, err
	}
	doc, ok := f.policies[arn]
	if !ok {
		return nil, &ddbtypes.PolicyNotFoundException{}
	}
	return &dynamodb.GetResourcePolicyOutput{Policy: awssdk.String(doc)}, nil
}

type fakeScaling struct {
	targets []aastypes.ScalableTarget
	err     error
}

func (f fakeScaling) DescribeScalableTargets(_ context.Context, in *applicationautoscaling.DescribeScalableTargetsInput, _ ...func(*applicationautoscaling.Options)) (*applicationautoscaling.DescribeScalableTargetsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if in.ServiceNamespace != aastypes.ServiceNamespaceDynamodb {
		return &applicationautoscaling.DescribeScalableTargetsOutput{}, nil
	}
	return &applicationautoscaling.DescribeScalableTargetsOutput{ScalableTargets: f.targets}, nil
}

var (
	_ dynamodbAPI        = (*fakeDynamoDB)(nil)
	_ scalableTargetsAPI = fakeScaling{}
)

func ddbTableARN(name string) string {
	return "arn:aws:dynamodb:us-east-1:111111111111:table/" + name
}

func TestCollectDynamoDBTables(t *testing.T) {
	f := &fakeDynamoDB{
		tables: []string{"scaled", "ondemand", "fixed", "unread"},
		describe: map[string]*ddbtypes.TableDescription{
			"scaled":   {TableArn: awssdk.String(ddbTableARN("scaled")), DeletionProtectionEnabled: awssdk.Bool(true), TableStatus: ddbtypes.TableStatusActive},
			"ondemand": {TableArn: awssdk.String(ddbTableARN("ondemand")), BillingModeSummary: &ddbtypes.BillingModeSummary{BillingMode: ddbtypes.BillingModePayPerRequest}, DeletionProtectionEnabled: awssdk.Bool(false)},
			"fixed":    {TableArn: awssdk.String(ddbTableARN("fixed")), BillingModeSummary: &ddbtypes.BillingModeSummary{BillingMode: ddbtypes.BillingModeProvisioned}},
		},
		pitr: map[string]ddbtypes.PointInTimeRecoveryStatus{"scaled": ddbtypes.PointInTimeRecoveryStatusEnabled, "ondemand": ddbtypes.PointInTimeRecoveryStatusDisabled},
		policies: map[string]string{
			ddbTableARN("ondemand"): `{"Statement":{"Effect":"Allow","Principal":"*","Action":"dynamodb:*","Resource":"*"}}`,
		},
		policyErr: map[string]error{ddbTableARN("fixed"): errFakeDenied},
	}
	scaling := fakeScaling{targets: []aastypes.ScalableTarget{
		{ResourceId: awssdk.String("table/scaled"), ScalableDimension: aastypes.ScalableDimensionDynamoDBTableReadCapacityUnits},
		{ResourceId: awssdk.String("table/scaled"), ScalableDimension: aastypes.ScalableDimensionDynamoDBTableWriteCapacityUnits},
		{ResourceId: awssdk.String("table/fixed"), ScalableDimension: aastypes.ScalableDimensionDynamoDBTableReadCapacityUnits},
	}}
	assets, err := collectDynamoDBTables(context.Background(), f, scaling, "us-east-1", "111111111111", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 4, "every page is read")
	got := map[string]asset.Asset{}
	for _, a := range assets {
		require.Equal(t, "dynamodb_table", a.Type)
		got[a.Name] = a
	}
	s := got["scaled"].Metadata
	require.Equal(t, "PROVISIONED", s["billing_mode"], "an omitted billing summary is the provisioned default")
	require.Equal(t, "true", s["read_autoscaling"])
	require.Equal(t, "true", s["write_autoscaling"])
	require.Equal(t, "true", s["deletion_protection"])
	require.Equal(t, "ENABLED", s["point_in_time_recovery"])
	require.Equal(t, asset.PublicAccessNone, s["public_access"])

	o := got["ondemand"].Metadata
	require.Equal(t, "PAY_PER_REQUEST", o["billing_mode"])
	require.Equal(t, "DISABLED", o["point_in_time_recovery"])
	require.Equal(t, asset.PublicAccessConfirmed, o["public_access"])

	x := got["fixed"].Metadata
	require.Equal(t, "true", x["read_autoscaling"])
	require.Equal(t, "false", x["write_autoscaling"])
	_, ok := x["deletion_protection"]
	require.False(t, ok, "an omitted deletion-protection flag is unknown")
	_, ok = x["public_access"]
	require.False(t, ok, "a denied policy read is unknown")

	u := got["unread"]
	require.Equal(t, ddbTableARN("unread"), u.ID, "the ARN is built when DescribeTable fails")
	for _, k := range []string{"billing_mode", "read_autoscaling", "point_in_time_recovery"} {
		_, ok := u.Metadata[k]
		require.Falsef(t, ok, "%s stays absent when its read failed", k)
	}
}

func TestCollectDynamoDBDegradedReads(t *testing.T) {
	_, err := collectDynamoDBTables(context.Background(), &fakeDynamoDB{tables: []string{"a", "b"}, page2: errFakeDenied},
		fakeScaling{}, "us-east-1", "111111111111", time.Now())
	require.Error(t, err, "a failed second page fails the listing")

	assets, err := collectDynamoDBTables(context.Background(), &fakeDynamoDB{
		tables:   []string{"t"},
		describe: map[string]*ddbtypes.TableDescription{"t": {TableArn: awssdk.String(ddbTableARN("t"))}},
	}, fakeScaling{err: errFakeDenied}, "us-east-1", "111111111111", time.Now())
	require.NoError(t, err)
	require.Equal(t, "PROVISIONED", assets[0].Metadata["billing_mode"])
	_, ok := assets[0].Metadata["read_autoscaling"]
	require.False(t, ok, "unreadable scaling targets are unknown, not off")
}

type fakeDAX struct {
	clusters []daxtypes.Cluster
	err      error
}

func (f fakeDAX) DescribeClusters(context.Context, *dax.DescribeClustersInput, ...func(*dax.Options)) (*dax.DescribeClustersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &dax.DescribeClustersOutput{Clusters: f.clusters}, nil
}

func TestCollectDAXClusters(t *testing.T) {
	assets, err := collectDAXClusters(context.Background(), fakeDAX{clusters: []daxtypes.Cluster{
		{ClusterArn: awssdk.String("arn:dax:a"), ClusterName: awssdk.String("a"), SSEDescription: &daxtypes.SSEDescription{Status: daxtypes.SSEStatusEnabled}, ClusterEndpointEncryptionType: daxtypes.ClusterEndpointEncryptionTypeTls},
		{ClusterArn: awssdk.String("arn:dax:b"), ClusterName: awssdk.String("b")},
	}}, "us-east-1", "111111111111", time.Now())
	require.NoError(t, err)
	require.Equal(t, "ENABLED", assets[0].Metadata["sse_status"])
	require.Equal(t, "TLS", assets[0].Metadata["endpoint_encryption_type"])
	require.Equal(t, "DISABLED", assets[1].Metadata["sse_status"], "SSE is opt-in at creation; no description is never enabled")
	require.Equal(t, "NONE", assets[1].Metadata["endpoint_encryption_type"])

	// Even an NXDOMAIN on the endpoint is a failed read, never "no clusters":
	// a DNS firewall answers NXDOMAIN too, and an empty answer would resolve
	// every stored cluster's findings.
	_, err = collectDAXClusters(context.Background(), fakeDAX{err: &net.DNSError{IsNotFound: true}}, "ap-east-2", "111111111111", time.Now())
	require.Error(t, err)
	_, err = collectDAXClusters(context.Background(), fakeDAX{err: errFakeDenied}, "us-east-1", "111111111111", time.Now())
	require.Error(t, err)
}
