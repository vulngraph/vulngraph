package jobs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// restampLastSeen must refresh LastSeen on EVERY collected asset, not only the
// ones whose content changed — that gap is what turned last_seen into "last
// changed" and dropped stable live assets from the graph.
func TestRestampLastSeen_StampsEveryAsset(t *testing.T) {
	old := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	in := []asset.Asset{
		{ID: "a", Type: "k8s_pod", LastSeen: old},
		{ID: "b", Type: "ec2_instance", LastSeen: time.Time{}},
		{ID: "c", Type: "s3_bucket", LastSeen: now},
	}

	out := restampLastSeen(in, now)

	require.Len(t, out, 3)
	for _, a := range out {
		require.Equal(t, now, a.LastSeen, "asset %s must carry the sweep clock", a.ID)
	}
}

// The re-stamp must not mutate the caller's slice: sync.go hands the same
// res.Assets to CIEM and to the content diff after ingesting, and a mutated
// LastSeen there would be a silent aliasing bug.
func TestRestampLastSeen_DoesNotMutateInput(t *testing.T) {
	old := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	in := []asset.Asset{{ID: "a", LastSeen: old}}

	out := restampLastSeen(in, now)

	require.Equal(t, old, in[0].LastSeen, "input slice must be untouched")
	require.Equal(t, now, out[0].LastSeen)
}

// Everything except LastSeen must survive the copy — the re-stamped assets are
// the rows actually written to ClickHouse, so dropping a field here would blank
// it for every stable asset in the corpus.
func TestRestampLastSeen_PreservesAllOtherFields(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	discovered := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	in := []asset.Asset{{
		ID:           "arn:aws:iam::1:role/r",
		Name:         "r",
		Type:         "iam_role",
		Provider:     asset.ProviderAWS,
		Region:       "eu-west-1",
		AccountID:    "1",
		Endpoint:     "e",
		PublicIP:     "1.2.3.4",
		PrivateIP:    "10.0.0.1",
		Domain:       "d.example.com",
		Tags:         map[string]string{"env": "prod"},
		Metadata:     map[string]string{"trust_entry": "service"},
		RiskScore:    42,
		DiscoveredAt: discovered,
		LastSeen:     discovered,
	}}

	got := restampLastSeen(in, now)[0]

	want := in[0]
	want.LastSeen = now
	require.Equal(t, want, got)
	require.Equal(t, discovered, got.DiscoveredAt, "first-seen must never be overwritten by the re-stamp")
}

func TestRestampLastSeen_EmptyInput(t *testing.T) {
	require.Empty(t, restampLastSeen(nil, time.Now()))
}
