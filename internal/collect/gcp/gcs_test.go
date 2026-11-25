package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	storage "google.golang.org/api/storage/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/checks"
)

type fakeGCS struct {
	buckets []gcsBucket
	err     error
}

func (f *fakeGCS) ListBuckets(context.Context, string) ([]gcsBucket, error) {
	return f.buckets, f.err
}

var gcsNow = time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

func TestCollectGCS_MapsBucketsAndPublicFlag(t *testing.T) {
	client := &fakeGCS{buckets: []gcsBucket{
		{Name: "open-bucket", Location: "EU", Public: true, PublicKnown: true},
		{Name: "locked-bucket", Location: "US", Public: false, PublicKnown: true, PublicAccessPrevention: "enforced"},
	}}

	assets, edges, err := collectGCS(context.Background(), client, "proj-1", gcsNow)
	require.NoError(t, err)
	require.Len(t, assets, 2)
	require.Len(t, edges, 1, "only the public bucket should have an exposed_to_internet edge")
	require.Equal(t, "open-bucket", edges[0].SrcID)
	require.Equal(t, "internet", edges[0].DstID)
	require.Equal(t, "exposed_to_internet", edges[0].EdgeType)

	byID := map[string]asset.Asset{}
	for _, a := range assets {
		byID[a.ID] = a
	}

	open := byID["open-bucket"]
	require.Equal(t, "gcs_bucket", open.Type)
	require.Equal(t, asset.ProviderGCP, open.Provider)
	require.Equal(t, "proj-1", open.AccountID)
	require.Equal(t, "eu", open.Region, "location is lowercased")
	require.Equal(t, "open-bucket.storage.googleapis.com", open.Domain)
	require.Equal(t, "true", open.Metadata["public"])

	locked := byID["locked-bucket"]
	require.Equal(t, "false", locked.Metadata["public"])
	require.Equal(t, "enforced", locked.Metadata["public_access_prevention"])
}

// An unreadable bucket IAM policy is unknown exposure, not a private bucket:
// with public="false" the public-bucket check would count as evaluated and
// close an open High finding as fixed.
func TestBucketToNeutral_PolicyProbe(t *testing.T) {
	denied := func(context.Context, string) (*storage.Policy, error) {
		return nil, errors.New("403: storage.buckets.getIamPolicy denied")
	}
	public := func(context.Context, string) (*storage.Policy, error) {
		return &storage.Policy{Bindings: []*storage.PolicyBindings{{Role: "roles/storage.objectViewer", Members: []string{"allUsers"}}}}, nil
	}
	private := func(context.Context, string) (*storage.Policy, error) {
		return &storage.Policy{Bindings: []*storage.PolicyBindings{{Role: "roles/storage.admin", Members: []string{"user:a@example.com"}}}}, nil
	}
	empty := func(context.Context, string) (*storage.Policy, error) { return nil, nil }
	enforced := &storage.Bucket{Name: "b", IamConfiguration: &storage.BucketIamConfiguration{PublicAccessPrevention: "enforced"}}
	inherited := &storage.Bucket{Name: "b", IamConfiguration: &storage.BucketIamConfiguration{PublicAccessPrevention: "inherited"}}

	tests := []struct {
		name               string
		bucket             *storage.Bucket
		policy             func(context.Context, string) (*storage.Policy, error)
		wantKnown, wantPub bool
	}{
		{"probe error", inherited, denied, false, false},
		{"empty policy response", inherited, empty, false, false},
		{"allUsers binding", inherited, public, true, true},
		{"no public member", inherited, private, true, false},
		{"missing bucket setting", &storage.Bucket{Name: "b"}, public, false, false},
		{"prevention enforced skips the probe", enforced, denied, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := bucketToNeutral(context.Background(), tt.bucket, tt.policy, "not_enforced")
			require.Equal(t, tt.wantKnown, g.PublicKnown)
			require.Equal(t, tt.wantPub, g.Public)
		})
	}
}

func TestCollectGCS_UnknownExposureIsNotCompliant(t *testing.T) {
	client := &fakeGCS{buckets: []gcsBucket{{Name: "unread", Location: "EU"}}}
	assets, edges, err := collectGCS(context.Background(), client, "proj-1", gcsNow)
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.Empty(t, edges, "an unread policy is no evidence of internet exposure")
	require.NotContains(t, assets[0].Metadata, "public")
	require.Equal(t, publicAccessUnknown, assets[0].Metadata["public_access"],
		"DSPM must show an unread bucket as unobserved, not as a private one")

	c, ok := checks.Default().ByID("gcp-gcs-public-bucket")
	require.True(t, ok)
	require.False(t, c.Violates(assets[0]))
	require.False(t, c.Evaluable(assets[0]),
		"an unread policy must leave the check unevaluated so an open finding is not closed as fixed")

	read := &fakeGCS{buckets: []gcsBucket{{Name: "read", PublicKnown: true}}}
	assets, _, err = collectGCS(context.Background(), read, "proj-1", gcsNow)
	require.NoError(t, err)
	require.True(t, c.Evaluable(assets[0]))
	require.NotContains(t, assets[0].Metadata, "public_access")
}

func TestCollectGCS_SkipsUnnamed(t *testing.T) {
	assets, edges, err := collectGCS(context.Background(), &fakeGCS{buckets: []gcsBucket{{Name: ""}}}, "p", gcsNow)
	require.NoError(t, err)
	require.Empty(t, assets)
	require.Empty(t, edges)
}

func TestCollectGCS_ListError(t *testing.T) {
	_, _, err := collectGCS(context.Background(), &fakeGCS{err: errors.New("permission denied")}, "p", gcsNow)
	require.ErrorContains(t, err, "permission denied")
}

// `logging` was overloaded across two asset types with two incompatible value
// spaces: an enabled/disabled ENUM on s3_bucket, the destination log bucket's
// NAME here. Both readers were AssetType-scoped so nothing was cross-wired, but
// one shared key with two meanings is a check away from firing on the wrong one.
// The GCS side is now logging_bucket; `logging` must be gone from gcs_bucket so
// the ambiguity cannot come back by accident.
func TestCollectGCS_LoggingBucketKeyIsNotOverloaded(t *testing.T) {
	assets, _, err := collectGCS(context.Background(), &fakeGCS{buckets: []gcsBucket{
		{Name: "logged", LogBucket: "audit-logs"},
		{Name: "unlogged"},
	}}, "proj-1", gcsNow)
	require.NoError(t, err)

	md := map[string]map[string]string{}
	for _, a := range assets {
		md[a.Name] = a.Metadata
	}
	require.Equal(t, "audit-logs", md["logged"]["logging_bucket"])
	// Present-and-empty: what checks.observedNone requires in order to fire.
	require.Contains(t, md["unlogged"], "logging_bucket")
	require.Equal(t, "", md["unlogged"]["logging_bucket"])

	require.NotContains(t, md["logged"], "logging",
		"the enum-valued s3_bucket key name must not be reused for a bucket NAME")
	require.NotContains(t, md["unlogged"], "logging")
}
