package github

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const tfBackendTF = `
terraform {
  backend "s3" {
    bucket = "state-bucket"
    key    = "org/repo/terraform.tfstate"
  }
}

resource "aws_iam_role" "app" {
  name = "app"
}
`

const tfStateJSON = `{
  "resources": [
    {
      "mode": "managed",
      "type": "aws_iam_role",
      "name": "app",
      "instances": [{"attributes": {"arn": "arn:aws:iam::123456789012:role/app", "id": "app"}}]
    },
    {
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "other",
      "instances": [{"attributes": {"arn": "arn:aws:s3:::other-bucket", "id": "other-bucket"}}]
    }
  ]
}`

func backendTF(bucket string) string {
	return `
terraform {
  backend "s3" {
    bucket = "` + bucket + `"
    key    = "org/repo/terraform.tfstate"
  }
}

resource "aws_iam_role" "app" {
  name = "app"
}
`
}

func fakeConn(connectorID string, ok bool, err error) connByAccount {
	return func(_ context.Context, _ string) (string, bool, error) { return connectorID, ok, err }
}

// fakeBucketAcct maps bucket name -> account id, reporting ok=false for any
// bucket not in the map (simulating no matching s3_bucket asset yet).
func fakeBucketAcct(byBucket map[string]string) bucketAccountResolver {
	return func(_ context.Context, bucket string) (string, bool, error) {
		accountID, ok := byBucket[bucket]
		return accountID, ok, nil
	}
}

// connByAccountRecording records every account id it was asked to resolve and
// maps account id -> connector id. Guarded by its own mutex: collectTFState
// fans repos out across goroutines (tfStateConcurrency), and this fake is
// shared across every repo in a test that exercises more than one — an
// unsynchronized append here is a reproducible data race under -race.
func connByAccountRecording(byAccount map[string]string, seen *[]string) connByAccount {
	var mu sync.Mutex
	return func(_ context.Context, accountID string) (string, bool, error) {
		mu.Lock()
		*seen = append(*seen, accountID)
		mu.Unlock()
		connectorID, ok := byAccount[accountID]
		return connectorID, ok, nil
	}
}

type fakeTFStateReader struct {
	data map[string][]byte // "bucket/key" -> bytes
	err  error
	// calls records every (connectorID, bucket) GetObject was invoked with.
	calls *[]string
	// readOrder records every "bucket/key" in call order.
	readOrder []string
	// mu guards calls/readOrder: collectTFState fans repos out across
	// goroutines (tfStateConcurrency), and a test exercising more than one
	// repo against the same *fakeTFStateReader — as
	// TestCollectTFState_PerBucketAccountResolution does — calls GetObject
	// concurrently from more than one goroutine. Without the mutex this is a
	// reproducible data race under -race.
	mu sync.Mutex
}

func (f *fakeTFStateReader) GetObject(_ context.Context, connectorID, bucket, key string) ([]byte, error) {
	f.mu.Lock()
	if f.calls != nil {
		*f.calls = append(*f.calls, connectorID+"/"+bucket)
	}
	f.readOrder = append(f.readOrder, bucket+"/"+key)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	d, ok := f.data[bucket+"/"+key]
	if !ok {
		return nil, errors.New("not found")
	}
	return d, nil
}

func TestCollectTFState_AttributionFilter(t *testing.T) {
	c := &Collector{
		tfStateFiles: func(_ context.Context, _, _ string, r repo) map[string]string {
			if r.FullName == "org/repo" {
				return map[string]string{"main.tf": tfBackendTF}
			}
			return nil
		},
	}
	reader := &fakeTFStateReader{data: map[string][]byte{
		"state-bucket/org/repo/terraform.tfstate": []byte(tfStateJSON),
	}}
	repos := []repo{{FullName: "org/repo", Name: "repo", DefaultBranch: "main"}}

	assets, _ := c.collectTFState(context.Background(), "", "", repos, reader, nil, fakeConn("conn-1", true, nil), "123456789012")

	require.Len(t, assets, 1, "only the declared aws_iam_role.app should be projected, not aws_s3_bucket.other")
	require.Equal(t, "declared_tf_resource", assets[0].Type)
	require.Equal(t, "aws_iam_role.app", assets[0].Metadata["address"])
	require.Equal(t, "arn:aws:iam::123456789012:role/app", assets[0].Metadata["target_arn"])
}

// TestCollectTFState_PerBucketAccountResolution proves two repos whose backend
// buckets live in DIFFERENT AWS accounts each resolve to their OWN account's
// connector, not one global configured account (multi-account).
func TestCollectTFState_PerBucketAccountResolution(t *testing.T) {
	c := &Collector{
		tfStateFiles: func(_ context.Context, _, _ string, r repo) map[string]string {
			switch r.FullName {
			case "org/repo-a":
				return map[string]string{"main.tf": backendTF("state-a")}
			case "org/repo-b":
				return map[string]string{"main.tf": backendTF("state-b")}
			}
			return nil
		},
	}
	var getObjectCalls []string
	reader := &fakeTFStateReader{
		data: map[string][]byte{
			"state-a/org/repo/terraform.tfstate": []byte(tfStateJSON),
			"state-b/org/repo/terraform.tfstate": []byte(tfStateJSON),
		},
		calls: &getObjectCalls,
	}
	bucketAcct := fakeBucketAcct(map[string]string{
		"state-a": "111111111111",
		"state-b": "222222222222",
	})
	var accountsResolved []string
	conn := connByAccountRecording(map[string]string{
		"111111111111": "conn-111",
		"222222222222": "conn-222",
	}, &accountsResolved)
	repos := []repo{
		{FullName: "org/repo-a", Name: "repo-a", DefaultBranch: "main"},
		{FullName: "org/repo-b", Name: "repo-b", DefaultBranch: "main"},
	}

	assets, _ := c.collectTFState(context.Background(), "", "", repos, reader, bucketAcct, conn, "")

	require.Len(t, assets, 2)
	require.ElementsMatch(t, []string{"111111111111", "222222222222"}, accountsResolved)
	require.ElementsMatch(t, []string{"conn-111/state-a", "conn-222/state-b"}, getObjectCalls)
}

func TestCollectTFState_BucketAcctUnknownFallsBackToConfiguredAccount(t *testing.T) {
	c := &Collector{
		tfStateFiles: func(_ context.Context, _, _ string, _ repo) map[string]string {
			return map[string]string{"main.tf": tfBackendTF}
		},
	}
	var getObjectCalls []string
	reader := &fakeTFStateReader{
		data:  map[string][]byte{"state-bucket/org/repo/terraform.tfstate": []byte(tfStateJSON)},
		calls: &getObjectCalls,
	}
	// Resolver knows nothing about "state-bucket" (ok=false) — fallback account kicks in.
	bucketAcct := fakeBucketAcct(map[string]string{})
	conn := fakeConn("conn-fallback", true, nil)
	repos := []repo{{FullName: "org/repo", Name: "repo", DefaultBranch: "main"}}

	assets, _ := c.collectTFState(context.Background(), "", "", repos, reader, bucketAcct, conn, "123456789012")

	require.Len(t, assets, 1)
	require.Equal(t, []string{"conn-fallback/state-bucket"}, getObjectCalls)
}

func TestCollectTFState_BucketAcctUnknownNoFallbackSkipsRepo(t *testing.T) {
	c := &Collector{
		tfStateFiles: func(_ context.Context, _, _ string, _ repo) map[string]string {
			return map[string]string{"main.tf": tfBackendTF}
		},
	}
	var getObjectCalls []string
	reader := &fakeTFStateReader{calls: &getObjectCalls}
	bucketAcct := fakeBucketAcct(map[string]string{}) // unknown bucket, ok=false
	conn := fakeConn("conn-1", true, nil)
	repos := []repo{{FullName: "org/repo", Name: "repo", DefaultBranch: "main"}}

	require.NotPanics(t, func() {
		assets, _ := c.collectTFState(context.Background(), "", "", repos, reader, bucketAcct, conn, "") // no fallback account
		require.Empty(t, assets)
	})
	require.Empty(t, getObjectCalls, "no account resolved for the bucket; GetObject must never be called")
}

func TestCollectTFState_NoBackendBlockSkipsGetObject(t *testing.T) {
	c := &Collector{
		tfStateFiles: func(_ context.Context, _, _ string, _ repo) map[string]string {
			return map[string]string{"main.tf": `resource "aws_iam_role" "app" {}`}
		},
	}
	var getObjectCalls []string
	reader := &fakeTFStateReader{calls: &getObjectCalls}
	repos := []repo{{FullName: "org/repo", Name: "repo", DefaultBranch: "main"}}

	assets, _ := c.collectTFState(context.Background(), "", "", repos, reader, nil, fakeConn("conn-1", true, nil), "123456789012")

	require.Empty(t, assets)
	require.Empty(t, getObjectCalls, "no backend block found; GetObject must never be called")
}

func TestCollectTFState_GetObjectErrorSkipsRepo(t *testing.T) {
	c := &Collector{
		tfStateFiles: func(_ context.Context, _, _ string, _ repo) map[string]string {
			return map[string]string{"main.tf": tfBackendTF}
		},
	}
	reader := &fakeTFStateReader{err: errors.New("not found")}
	repos := []repo{{FullName: "org/repo", Name: "repo", DefaultBranch: "main"}}

	require.NotPanics(t, func() {
		assets, findings := c.collectTFState(context.Background(), "", "", repos, reader, nil, fakeConn("conn-1", true, nil), "123456789012")
		require.Empty(t, assets)
		require.Empty(t, findings, "a non-AccessDenied read failure is not a grant gap; no finding")
	})
}

// TestCollectTFState_AccessDeniedEmitsFinding proves an AccessDenied state read
// surfaces an info-severity unreadable_tf_state finding naming the bucket,
// account, key and the exact IAM grant, and saying the grant exposes the
// state's secrets and is optional.
func TestCollectTFState_AccessDeniedEmitsFinding(t *testing.T) {
	c := &Collector{
		tfStateFiles: func(_ context.Context, _, _ string, _ repo) map[string]string {
			return map[string]string{"main.tf": tfBackendTF}
		},
	}
	reader := &fakeTFStateReader{err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}}
	repos := []repo{{FullName: "org/repo", Name: "repo", DefaultBranch: "main"}}

	assets, findings := c.collectTFState(context.Background(), "", "", repos, reader, nil, fakeConn("conn-1", true, nil), "123456789012")

	require.Empty(t, assets)
	require.Len(t, findings, 1)
	f := findings[0]
	require.Equal(t, "iac_terraform", f.Source)
	require.Equal(t, "unreadable_tf_state", f.Type)
	require.Equal(t, finding.SeverityInfo, f.Severity)
	require.Equal(t, "github_repo", f.ResourceType)
	require.Equal(t, "org/repo", f.ResourceID)
	require.Equal(t, "repo", f.ResourceName)
	require.Equal(t, "global", f.Region)
	require.Equal(t, "unreadable_tf_state", f.CheckID)
	require.Contains(t, f.Description, "state-bucket")
	require.Contains(t, f.Description, "123456789012")
	require.Contains(t, f.Description, "org/repo/terraform.tfstate")
	require.Contains(t, f.Description, "s3:GetObject")
	require.NotEmpty(t, f.Remediation)
	require.Contains(t, f.Remediation, "s3:GetObject")
	require.Contains(t, f.Remediation, "secrets")
	require.True(t, strings.HasPrefix(f.Remediation, "Optional."), "the grant is opt-in; the finding must not demand it")
}

// TestCollectTFState_AccessDeniedFindingIDIsDeterministic proves the same
// repo/bucket/key inputs produce the identical finding ID across syncs, so
// the finding upserts (idempotent) rather than duplicating, and auto-resolves
// via the deletion-reconciliation lifecycle once the read later succeeds.
func TestCollectTFState_AccessDeniedFindingIDIsDeterministic(t *testing.T) {
	newCollector := func() *Collector {
		return &Collector{
			tfStateFiles: func(_ context.Context, _, _ string, _ repo) map[string]string {
				return map[string]string{"main.tf": tfBackendTF}
			},
		}
	}
	reader := &fakeTFStateReader{err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}}
	repos := []repo{{FullName: "org/repo", Name: "repo", DefaultBranch: "main"}}

	_, findings1 := newCollector().collectTFState(context.Background(), "", "", repos, reader, nil, fakeConn("conn-1", true, nil), "123456789012")
	_, findings2 := newCollector().collectTFState(context.Background(), "", "", repos, reader, nil, fakeConn("conn-1", true, nil), "123456789012")

	require.Len(t, findings1, 1)
	require.Len(t, findings2, 1)
	require.Equal(t, findings1[0].ID, findings2[0].ID)
}

func TestCollectTFState_NoStateAccountIDIsNoop(t *testing.T) {
	c := &Collector{}
	repos := []repo{{FullName: "org/repo", Name: "repo", DefaultBranch: "main"}}
	assets, _ := c.collectTFState(context.Background(), "", "", repos, &fakeTFStateReader{}, nil, fakeConn("conn-1", true, nil), "")
	require.Empty(t, assets)
}

func TestCollectTFState_UnresolvedAccountIsNoop(t *testing.T) {
	c := &Collector{
		tfStateFiles: func(_ context.Context, _, _ string, _ repo) map[string]string {
			return map[string]string{"main.tf": tfBackendTF}
		},
	}
	repos := []repo{{FullName: "org/repo", Name: "repo", DefaultBranch: "main"}}
	assets, _ := c.collectTFState(context.Background(), "", "", repos, &fakeTFStateReader{}, nil, fakeConn("", false, nil), "123456789012")
	require.Empty(t, assets)
}

// TestCollectTFState_ReadsEveryRootModule guards coverage of Terraform-managed
// IAM in monorepos. Every root module has its own backend and its own state file,
// so a monorepo has many: an IAM repo may carry one state.tf per team directory
// and an infra repo one backend.tf per environment.
// Reading only the first backend found would leave nearly all of them invisible —
// and which one won would depend on file ordering.
func TestCollectTFState_ReadsEveryRootModule(t *testing.T) {
	const teamA = `
terraform {
  backend "s3" {
    bucket = "example-tf-state"
    key    = "team-a/terraform.tfstate"
  }
}
resource "aws_iam_role" "messaging_api" {}
`
	const teamB = `
terraform {
  backend "s3" {
    bucket = "example-tf-state"
    key    = "team-b/terraform.tfstate"
  }
}
resource "aws_iam_role" "orders_api" {}
`
	c := &Collector{
		tfStateFiles: func(_ context.Context, _, _ string, _ repo) map[string]string {
			return map[string]string{"team-a/state.tf": teamA, "team-b/state.tf": teamB}
		},
	}
	reader := &fakeTFStateReader{data: map[string][]byte{
		"example-tf-state/team-a/terraform.tfstate": []byte(`{"resources":[{"mode":"managed","type":"aws_iam_role","name":"messaging_api","instances":[{"attributes":{"arn":"arn:aws:iam::1:role/messaging-api","id":"messaging-api"}}]}]}`),
		"example-tf-state/team-b/terraform.tfstate": []byte(`{"resources":[{"mode":"managed","type":"aws_iam_role","name":"orders_api","instances":[{"attributes":{"arn":"arn:aws:iam::1:role/orders-api","id":"orders-api"}}]}]}`),
	}}
	repos := []repo{{FullName: "example-org/iam-config", Name: "iam-config", DefaultBranch: "main"}}

	assets, _ := c.collectTFState(context.Background(), "", "", repos, reader, nil, fakeConn("conn-1", true, nil), "123456789012")

	arns := map[string]bool{}
	for _, a := range assets {
		arns[a.Metadata["target_arn"]] = true
	}
	require.Len(t, assets, 2, "both root modules' states must be read, not just the first")
	require.True(t, arns["arn:aws:iam::1:role/messaging-api"])
	require.True(t, arns["arn:aws:iam::1:role/orders-api"])
}

// A repo declaring more backends than the fan-out cap must truncate
// deterministically — sorted by bucket then key — so coverage does not shuffle
// between sweeps.
func TestCollectTFState_BackendCapIsDeterministic(t *testing.T) {
	files := map[string]string{}
	want := []string{}
	for _, k := range []string{"c", "a", "b"} {
		files[k+"/state.tf"] = `
terraform {
  backend "s3" {
    bucket = "example-tf-state"
    key    = "` + k + `/terraform.tfstate"
  }
}
resource "aws_iam_role" "r_` + k + `" {}
`
		want = append(want, k)
	}
	c := &Collector{tfStateFiles: func(_ context.Context, _, _ string, _ repo) map[string]string { return files }}
	data := map[string][]byte{}
	for _, k := range want {
		data["example-tf-state/"+k+"/terraform.tfstate"] = []byte(`{"resources":[{"mode":"managed","type":"aws_iam_role","name":"r_` + k + `","instances":[{"attributes":{"arn":"arn:aws:iam::1:role/` + k + `","id":"` + k + `"}}]}]}`)
	}
	reader := &fakeTFStateReader{data: data}
	repos := []repo{{FullName: "org/mono", Name: "mono", DefaultBranch: "main"}}

	assets, _ := c.collectTFState(context.Background(), "", "", repos, reader, nil, fakeConn("conn-1", true, nil), "123456789012")
	require.Len(t, assets, 3)
	require.Equal(t, []string{"example-tf-state/a/terraform.tfstate", "example-tf-state/b/terraform.tfstate", "example-tf-state/c/terraform.tfstate"},
		reader.readOrder, "backends are read in sorted order")
}
