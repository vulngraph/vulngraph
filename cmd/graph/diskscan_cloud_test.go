package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/diskscan/envelope"
	"github.com/vulngraph/vulngraph/internal/jobs"
	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

func testEnvKey() envelope.Key {
	var k envelope.Key
	for i := range k {
		k[i] = 7
	}
	return k
}

func sealFor(t *testing.T, a envelope.Access) []byte {
	t.Helper()
	sealed, err := envelope.Seal(testEnvKey(), "run-1", a)
	require.NoError(t, err)
	return sealed
}

func awsAccess(write bool, exp time.Time) envelope.Access {
	a := envelope.Access{
		ConnectorID: "c1", Type: "aws", Role: "arn:ds", OtherRoles: []string{"arn:ro"},
		Config:    map[string]string{"region": "eu-west-1"},
		AWSRead:   &envelope.Credentials{AccessKeyID: "ASIAREAD", SecretAccessKey: "rs", SessionToken: "rt", Expires: exp},
		ExpiresAt: exp,
	}
	if write {
		a.AWSWrite = &envelope.Credentials{AccessKeyID: "ASIAWRITE", SecretAccessKey: "ws", SessionToken: "wt", Expires: exp}
	}
	return a
}

func TestOpenRefusesExpiredAndForeignEnvelopes(t *testing.T) {
	d := &diskClouds{key: testEnvKey()}
	ctx := context.Background()

	_, err := d.Open(ctx, "c1", "run-1", sealFor(t, awsAccess(false, time.Now().Add(-time.Minute))))
	require.ErrorIs(t, err, jobs.ErrDiskCredentialsExpired)
	require.NotErrorIs(t, err, jobs.ErrDiskEnvelope)

	_, err = d.Open(ctx, "c1", "run-2", sealFor(t, awsAccess(false, time.Now().Add(time.Hour))))
	require.ErrorIs(t, err, jobs.ErrDiskEnvelope, "bound to another run")
	_, err = d.Open(ctx, "c1", "run-1", []byte("junk"))
	require.ErrorIs(t, err, jobs.ErrDiskEnvelope)
}

// The scanner builds AWS clients from the sealed sessions alone: it signs with
// them, and a run sealed without a disk-scan session cannot create or delete.
func TestOpenAWSUsesTheSealedSessionsAndAssumesNothing(t *testing.T) {
	d := &diskClouds{key: testEnvKey()}
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	acc, err := d.Open(ctx, "c1", "run-1", sealFor(t, awsAccess(false, exp)))
	require.NoError(t, err)
	require.Equal(t, "arn:ds", acc.Role)
	cloud := acc.Cloud.(*awsDiskCloud)
	got, err := cloud.readCfg.Credentials.Retrieve(ctx)
	require.NoError(t, err)
	require.Equal(t, "ASIAREAD", got.AccessKeyID)
	require.Equal(t, "rt", got.SessionToken)

	optIn, err := engine.Authorize(engine.ConnectorGrant{Mode: engine.ModeCreateSnapshots, DiskScanRole: "arn:ds", OtherRoles: []string{"arn:ro"}})
	require.NoError(t, err)
	_, err = cloud.Snapshotter(optIn)
	require.ErrorIs(t, err, engine.ErrNotAuthorized, "no write session was sealed")

	acc, err = d.Open(ctx, "c1", "run-1", sealFor(t, awsAccess(true, exp)))
	require.NoError(t, err)
	sn, err := acc.Cloud.Snapshotter(optIn)
	require.NoError(t, err)
	require.NotNil(t, sn)
	_, err = acc.Cloud.Snapshotter(engine.OptIn{})
	require.ErrorIs(t, err, engine.ErrNotAuthorized)
}

func TestMapAWSErrClassifiesExpiredSessions(t *testing.T) {
	for _, code := range []string{"ExpiredToken", "ExpiredTokenException", "RequestExpired"} {
		err := mapAWSErr(&smithy.GenericAPIError{Code: code})
		require.ErrorIs(t, err, jobs.ErrDiskCredentialsExpired, code)
	}
	require.NoError(t, mapAWSErr(nil))
	plain := &smithy.GenericAPIError{Code: "Throttling"}
	require.NotErrorIs(t, mapAWSErr(plain), jobs.ErrDiskCredentialsExpired)
}

// The sessions cap what the scanner holds to the snapshot actions.
func TestAWSSessionPoliciesAreExactlyTheSnapshotActions(t *testing.T) {
	actions := func(policy string) []string {
		var doc struct {
			Statement []struct {
				Effect string
				Action []string
			}
		}
		require.NoError(t, json.Unmarshal([]byte(policy), &doc))
		require.Len(t, doc.Statement, 1)
		require.Equal(t, "Allow", doc.Statement[0].Effect)
		return doc.Statement[0].Action
	}
	require.ElementsMatch(t, []string{"ec2:CreateSnapshot", "ec2:CreateTags", "ec2:DeleteSnapshot"}, actions(awsWriteSessionPolicy))
	require.ElementsMatch(t, []string{
		"ec2:DescribeSnapshots", "ec2:DescribeRegions",
		"ebs:ListSnapshotBlocks", "ebs:GetSnapshotBlock", "ebs:ListChangedBlocks",
		"kms:Decrypt", "kms:DescribeKey",
	}, actions(awsReadSessionPolicy))
	require.LessOrEqual(t, len(awsWriteSessionPolicy), 2048, "STS packs the policy under a size limit")
	require.LessOrEqual(t, len(awsReadSessionPolicy), 2048)
}

func azureAccess() envelope.Access {
	return envelope.Access{
		ConnectorID: "c1", Type: "azure", Role: "client-ds", OtherRoles: []string{"client-c"},
		Config: map[string]string{
			"subscription_id": "sub", "tenant_id": "t", "client_id": "client-c", "client_secret": "s",
			"disk_scan_client_id": "client-ds", "disk_scan_client_secret": "ds-secret",
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// Without a read opt-in an Azure snapshot is not readable and the failure is a
// recorded permission gap, not a retry.
func TestAzureReadNeedsTheReadOptIn(t *testing.T) {
	cloud, err := newAzureDiskCloud(azureAccess())
	require.NoError(t, err)
	_, err = cloud.Provider(jobs.DiskOptIns{}).Open(context.Background(), engine.Snapshot{ID: "snap", SizeBytes: 1 << 20})
	require.ErrorIs(t, err, jobs.ErrDiskPermissionDenied)

	readIn, err := engine.AuthorizeRead(engine.ConnectorGrant{Mode: engine.ModeExistingSnapshots, DiskScanRole: "client-ds", OtherRoles: []string{"client-c"}})
	require.NoError(t, err)
	require.NoError(t, cloud.Release(context.Background(), jobs.DiskOptIns{}, engine.Snapshot{}), "nothing to release without a grant")
	rd, err := cloud.reader(readIn)
	require.NoError(t, err)
	require.NotNil(t, rd)
	_, err = cloud.Snapshotter(engine.OptIn{})
	require.ErrorIs(t, err, engine.ErrNotAuthorized, "the read opt-in never reaches the snapshot writer")
}
