package aws

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeLambda struct {
	fns    []lambdatypes.FunctionConfiguration
	urls   map[string]string // functionName → URL (empty = no URL configured)
	urlErr error             // returned instead of ResourceNotFoundException when set
}

func (f *fakeLambda) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: f.fns}, nil
}

func (f *fakeLambda) GetPolicy(_ context.Context, _ *lambda.GetPolicyInput, _ ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	return nil, fmt.Errorf("ResourceNotFoundException: no policy")
}

func (f *fakeLambda) GetFunctionUrlConfig(_ context.Context, in *lambda.GetFunctionUrlConfigInput, _ ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error) {
	name := awssdk.ToString(in.FunctionName)
	if url, ok := f.urls[name]; ok && url != "" {
		return &lambda.GetFunctionUrlConfigOutput{
			FunctionUrl: awssdk.String(url),
			AuthType:    lambdatypes.FunctionUrlAuthTypeNone,
		}, nil
	}
	if f.urlErr != nil {
		return nil, f.urlErr
	}
	// No URL configured: the real SDK returns the typed ResourceNotFoundException.
	return nil, &lambdatypes.ResourceNotFoundException{Message: awssdk.String("no function url")}
}

func TestCollectLambdaFunctions(t *testing.T) {
	f := &fakeLambda{fns: []lambdatypes.FunctionConfiguration{{
		FunctionName: awssdk.String("processor"),
		FunctionArn:  awssdk.String("arn:aws:lambda:eu-west-1:111:function:processor"),
		Runtime:      lambdatypes.RuntimeGo1x,
		Role:         awssdk.String("arn:aws:iam::111:role/processor-exec"),
	}}}
	got, err := collectLambdaFunctions(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "lambda_function", got[0].Type)
	require.Equal(t, "processor", got[0].Name)
	require.Equal(t, "eu-west-1", got[0].Region)
	require.Equal(t, "false", got[0].Metadata["public"]) // no URL configured
	authType, observed := got[0].Metadata["url_auth_type"]
	require.True(t, observed, "no URL is a read answer: the key is written empty so a finding for a removed URL can close")
	require.Empty(t, authType)
	require.Empty(t, got[0].Domain)
	// Execution role is captured for the executes_as edge (no extra API call).
	require.Equal(t, "arn:aws:iam::111:role/processor-exec", got[0].Metadata["exec_role"])
}

func TestCollectLambdaFunctions_WithURL(t *testing.T) {
	f := &fakeLambda{
		fns: []lambdatypes.FunctionConfiguration{{
			FunctionName: awssdk.String("api"),
			FunctionArn:  awssdk.String("arn:aws:lambda:eu-west-1:111:function:api"),
			Runtime:      lambdatypes.RuntimeGo1x,
		}},
		urls: map[string]string{
			"api": "https://abc123.lambda-url.eu-west-1.on.aws/",
		},
	}
	got, err := collectLambdaFunctions(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "abc123.lambda-url.eu-west-1.on.aws", got[0].Domain)
	require.Equal(t, "https://abc123.lambda-url.eu-west-1.on.aws/", got[0].Endpoint)
	require.Equal(t, "true", got[0].Metadata["public"])
	require.Equal(t, "NONE", got[0].Metadata["url_auth_type"])
}

type fakeRDS struct {
	dbs          []rdstypes.DBInstance
	snaps        []rdstypes.DBSnapshot
	clusterSnaps []rdstypes.DBClusterSnapshot
	// publicSnaps: snapshot IDs (DB or cluster) whose restore attribute includes "all".
	publicSnaps map[string]bool
	// attrErr: snapshot IDs whose attribute read fails.
	attrErr map[string]bool
	// inFlight / maxInFlight observe the attribute-read fan-out.
	inFlight, maxInFlight atomic.Int32
}

func (f *fakeRDS) enter() func() {
	n := f.inFlight.Add(1)
	for {
		m := f.maxInFlight.Load()
		if n <= m || f.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(time.Millisecond)
	return func() { f.inFlight.Add(-1) }
}

func (f *fakeRDS) DescribeDBClusterSnapshots(context.Context, *rds.DescribeDBClusterSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error) {
	return &rds.DescribeDBClusterSnapshotsOutput{DBClusterSnapshots: f.clusterSnaps}, nil
}

func (f *fakeRDS) DescribeDBClusterSnapshotAttributes(_ context.Context, in *rds.DescribeDBClusterSnapshotAttributesInput, _ ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotAttributesOutput, error) {
	defer f.enter()()
	id := awssdk.ToString(in.DBClusterSnapshotIdentifier)
	if f.attrErr[id] {
		return nil, apiErr{code: "Throttling"}
	}
	vals := []string{}
	if f.publicSnaps[id] {
		vals = []string{"123456789012", "all"}
	}
	return &rds.DescribeDBClusterSnapshotAttributesOutput{
		DBClusterSnapshotAttributesResult: &rdstypes.DBClusterSnapshotAttributesResult{
			DBClusterSnapshotAttributes: []rdstypes.DBClusterSnapshotAttribute{
				{AttributeName: awssdk.String("restore"), AttributeValues: vals},
			},
		},
	}, nil
}

func (f *fakeRDS) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: f.dbs}, nil
}

func (f *fakeRDS) DescribeDBSnapshots(context.Context, *rds.DescribeDBSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error) {
	return &rds.DescribeDBSnapshotsOutput{DBSnapshots: f.snaps}, nil
}

func (f *fakeRDS) DescribeDBSnapshotAttributes(_ context.Context, in *rds.DescribeDBSnapshotAttributesInput, _ ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error) {
	defer f.enter()()
	if f.attrErr[awssdk.ToString(in.DBSnapshotIdentifier)] {
		return nil, apiErr{code: "Throttling"}
	}
	vals := []string{}
	if f.publicSnaps[awssdk.ToString(in.DBSnapshotIdentifier)] {
		vals = []string{"all"}
	}
	return &rds.DescribeDBSnapshotAttributesOutput{
		DBSnapshotAttributesResult: &rdstypes.DBSnapshotAttributesResult{
			DBSnapshotAttributes: []rdstypes.DBSnapshotAttribute{
				{AttributeName: awssdk.String("restore"), AttributeValues: vals},
			},
		},
	}, nil
}

func TestCollectRDSSnapshots_PublicFlag(t *testing.T) {
	f := &fakeRDS{
		snaps: []rdstypes.DBSnapshot{
			{DBSnapshotIdentifier: awssdk.String("shared"), DBSnapshotArn: awssdk.String("arn:...:snapshot:shared"), Engine: awssdk.String("postgres")},
			{DBSnapshotIdentifier: awssdk.String("private"), DBSnapshotArn: awssdk.String("arn:...:snapshot:private"), Engine: awssdk.String("postgres")},
		},
		publicSnaps: map[string]bool{"shared": true},
	}
	got, err := collectRDSSnapshots(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2)
	byName := map[string]string{}
	for _, a := range got {
		require.Equal(t, "rds_snapshot", a.Type)
		byName[a.Name] = a.Metadata["public"]
	}
	require.Equal(t, "true", byName["shared"])
	require.Equal(t, "false", byName["private"])
}

// A failed attribute read is unknown: the public key is omitted, never
// written as "false" (which would auto-resolve a real public-snapshot finding).
func TestCollectRDSSnapshots_AttributeErrorOmitsPublic(t *testing.T) {
	f := &fakeRDS{
		snaps: []rdstypes.DBSnapshot{
			{DBSnapshotIdentifier: awssdk.String("shared"), DBSnapshotArn: awssdk.String("arn:...:snapshot:shared")},
		},
		publicSnaps: map[string]bool{"shared": true},
		attrErr:     map[string]bool{"shared": true},
	}
	got, err := collectRDSSnapshots(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1, "the snapshot itself was listed and is still emitted")
	_, present := got[0].Metadata["public"]
	require.False(t, present)
}

// Aurora cluster snapshots were never collected, so a cluster snapshot shared
// with "all" was invisible to the public-snapshot check.
func TestCollectRDSSnapshots_ClusterSnapshots(t *testing.T) {
	f := &fakeRDS{
		clusterSnaps: []rdstypes.DBClusterSnapshot{
			{DBClusterSnapshotIdentifier: awssdk.String("aurora-shared"), DBClusterSnapshotArn: awssdk.String("arn:aws:rds:eu-west-1:111:cluster-snapshot:aurora-shared"),
				DBClusterIdentifier: awssdk.String("orders"), Engine: awssdk.String("aurora-postgresql"), StorageEncrypted: awssdk.Bool(true)},
			{DBClusterSnapshotIdentifier: awssdk.String("aurora-unread"), DBClusterSnapshotArn: awssdk.String("arn:aws:rds:eu-west-1:111:cluster-snapshot:aurora-unread")},
		},
		publicSnaps: map[string]bool{"aurora-shared": true},
		attrErr:     map[string]bool{"aurora-unread": true},
	}
	got, err := collectRDSSnapshots(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2)
	byName := map[string]asset.Asset{}
	for _, a := range got {
		byName[a.Name] = a
	}
	shared := byName["aurora-shared"]
	require.Equal(t, "rds_snapshot", shared.Type)
	require.Equal(t, "arn:aws:rds:eu-west-1:111:cluster-snapshot:aurora-shared", shared.ID)
	require.Equal(t, "true", shared.Metadata["public"])
	require.Equal(t, "cluster", shared.Metadata["snapshot_kind"])
	require.Equal(t, "orders", shared.Metadata["db_cluster"])
	require.Equal(t, "true", shared.Metadata["encrypted"])
	require.NotContains(t, byName["aurora-unread"].Metadata, "public", "an unread attribute is unknown, not private")
}

func TestCollectRDSSnapshots_BoundedConcurrency(t *testing.T) {
	f := &fakeRDS{publicSnaps: map[string]bool{}}
	for i := range 40 {
		id := fmt.Sprintf("snap-%02d", i)
		f.snaps = append(f.snaps, rdstypes.DBSnapshot{DBSnapshotIdentifier: awssdk.String(id), DBSnapshotArn: awssdk.String("arn:aws:rds:eu-west-1:111:snapshot:" + id)})
		if i%2 == 0 {
			f.publicSnaps[id] = true
		}
	}
	got, err := collectRDSSnapshots(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 40)
	for _, a := range got {
		require.Equal(t, strconv.FormatBool(f.publicSnaps[a.Name]), a.Metadata["public"], a.Name)
	}
	require.Greater(t, f.maxInFlight.Load(), int32(1), "attribute reads fan out")
	require.LessOrEqual(t, f.maxInFlight.Load(), int32(rdsSnapshotAttrConcurrency))
}

func TestCollectRDSInstances(t *testing.T) {
	f := &fakeRDS{dbs: []rdstypes.DBInstance{{
		DBInstanceIdentifier: awssdk.String("prod-db"),
		DBInstanceArn:        awssdk.String("arn:aws:rds:eu-west-1:111:db:prod-db"),
		Engine:               awssdk.String("postgres"),
		PubliclyAccessible:   awssdk.Bool(true),
		StorageEncrypted:     awssdk.Bool(true),
		Endpoint:             &rdstypes.Endpoint{Address: awssdk.String("prod-db.abc.eu-west-1.rds.amazonaws.com")},
	}}}
	got, err := collectRDSInstances(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "rds_instance", got[0].Type)
	require.Equal(t, "postgres", got[0].Metadata["engine"])
	require.Equal(t, "true", got[0].Metadata["publicly_accessible"])
	require.Contains(t, got[0].Endpoint, "rds.amazonaws.com")
}

func TestCollectLambdaFunctions_URLReadErrorLeavesAuthTypeUnknown(t *testing.T) {
	f := &fakeLambda{
		fns:    []lambdatypes.FunctionConfiguration{{FunctionName: awssdk.String("api"), FunctionArn: awssdk.String("arn:aws:lambda:eu-west-1:111:function:api")}},
		urlErr: fmt.Errorf("AccessDeniedException: not authorized"),
	}
	got, err := collectLambdaFunctions(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.NotContains(t, got[0].Metadata, "url_auth_type", "an unreadable URL config must stay unknown, not read as no URL")
}
