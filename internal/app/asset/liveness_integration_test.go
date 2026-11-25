//go:build integration

package asset

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// The ephemeral-liveness gate, executed by ClickHouse rather than reimplemented
// in Go. Every unit test of the finding lifecycle sweep runs against a fake that
// reproduces this arithmetic, so this is the only place the REAL condition is
// proven to do what the sweep believes it does — and the sweep resolves findings
// on the strength of it.
//
// Requires `docker compose up` and applied migrations (graph migrate).
func TestCHRepo_LiveIDsAppliesEphemeralLiveness(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	p := "it-live-" + time.Now().Format("150405.000000") + "-"
	now := time.Now().Truncate(time.Second)

	// The high-water mark for the WHOLE k8s_pod type is a global max over the
	// table, so this run's pods are judged against whatever the freshest pod in the
	// database is. Seeding one pod at `now` makes this run self-contained: it
	// becomes the high-water mark unless the database already holds a fresher one,
	// and a fresher one only moves the cutoff forward, which the fixtures below are
	// spaced to tolerate.
	fresh, graceEdge, dead, nonEphemeral := p+"fresh", p+"grace", p+"dead", p+"role"
	deadContainer, deadJob := p+"dead-container", p+"dead-job"
	assets := []Asset{
		{ID: fresh, Name: "fresh", Type: "k8s_pod", Provider: ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now},
		// Inside the 72h grace window: missed a couple of collection ticks, still live.
		{ID: graceEdge, Name: "grace", Type: "k8s_pod", Provider: ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now.Add(-60 * time.Hour)},
		// Well past it: a corpse.
		{ID: dead, Name: "dead", Type: "k8s_pod", Provider: ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now.Add(-30 * 24 * time.Hour)},
		// container and k8s_job share k8s_pod's high-water anchor:
		// a corpse of either, this far behind, must be gone too — before that fix
		// neither had any liveness gate at all.
		{ID: deadContainer, Name: "dead-container", Type: "container", Provider: ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now.Add(-30 * 24 * time.Hour)},
		{ID: deadJob, Name: "dead-job", Type: "k8s_job", Provider: ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now.Add(-30 * 24 * time.Hour)},
		// A non-ephemeral type that is FAR staler than the dead pod. It must stay
		// live: for an IAM role "not collected recently" means slow collection, not
		// deletion — most assets are older than 72h and filtering them would
		// delete most of the graph.
		//
		// 150 days, not 200: the assets table is `TTL last_seen + INTERVAL 180 DAY`
		// and ClickHouse drops expired rows on MERGE, which is nondeterministic. A
		// fixture past the TTL therefore survives or vanishes depending on whether
		// a merge happened to land between the insert and the read, and this test
		// failed in CI exactly that way. Any age well past the 72h pod window
		// proves the same property.
		{ID: nonEphemeral, Name: "role", Type: "iam_role", Provider: ProviderAWS,
			DiscoveredAt: now, LastSeen: now.Add(-150 * 24 * time.Hour)},
	}
	require.NoError(t, svc.Ingest(ctx, assets, nil))
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id LIKE ?", p+"%")
	})

	live, err := svc.LiveIDs(ctx, []string{fresh, graceEdge, dead, nonEphemeral, deadContainer, deadJob, p + "never-existed"})
	require.NoError(t, err)

	require.Contains(t, live, fresh)
	require.Contains(t, live, graceEdge,
		"a pod inside the 72h grace window has merely missed a tick — resolving its findings "+
			"would flap a live alert")
	require.Contains(t, live, nonEphemeral,
		"EphemeralLivenessCond short-circuits to true for a non-ephemeral type, however stale")
	require.NotContains(t, live, dead,
		"a pod 30 days behind the type's high-water mark is gone")
	require.NotContains(t, live, deadContainer,
		"container shares the pod high-water anchor and must be judged gone the same way")
	require.NotContains(t, live, deadJob,
		"k8s_job shares the pod high-water anchor and must be judged gone the same way")
	require.NotContains(t, live, p+"never-existed",
		"an id with no row at all is gone")
}

// TestCHRepo_VerifyExpiredEphemeralChunksLargeBatches is the guard for a
// failure mode: VerifyExpiredEphemeral's candidate ids are long k8s
// pod/container paths ("example-connector-cluster/pod/<ns>/<name>/container/<name>"), and
// ClickHouse's ?-placeholder binding substitutes them into the query TEXT
// client-side (there is no true bind-parameter form for a plain IN list over
// CH's native/HTTP protocol, unlike Postgres). One unchunked query over a
// couple of thousand such ids exceeds max_query_size (262,144 bytes) with a
// syntax error, and every ladybug_rebuild attempt then fails identically — the
// Ladybug graph never refreshes, because the whole rebuild aborts on this one
// query.
//
// This seeds two real dead pods on opposite sides of a >1,000-id candidate
// batch (verifyExpiredEphemeralChunk) and confirms both are still found —
// chunking must not silently drop or misattribute either half.
func TestCHRepo_VerifyExpiredEphemeralChunksLargeBatches(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	p := "it-chunk-" + time.Now().Format("150405.000000") + "-"
	now := time.Now().Truncate(time.Second)
	longPath := func(n int) string {
		return fmt.Sprintf("%sexample-connector-cluster/pod/some-namespace/some-fairly-long-deployment-name-%09d/container/main", p, n)
	}
	firstDead, lastDead, freshAnchor := longPath(0), longPath(2499), p+"fresh-anchor"

	require.NoError(t, svc.Ingest(ctx, []Asset{
		// Anchors the type's high-water mark at `now`, the same role `fresh` plays
		// in TestCHRepo_LiveIDsAppliesEphemeralLiveness above — without a fresher
		// pod in the table, each dead pod below would BE the high-water mark (its
		// own last_seen), which correctly reads as live, and this test
		// would prove nothing about chunking.
		{ID: freshAnchor, Name: "anchor", Type: "k8s_pod", Provider: ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now},
		{ID: firstDead, Name: "first", Type: "k8s_pod", Provider: ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now.Add(-30 * 24 * time.Hour)},
		{ID: lastDead, Name: "last", Type: "k8s_pod", Provider: ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now.Add(-30 * 24 * time.Hour)},
	}, nil))
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id LIKE ?", p+"%")
	})

	// 2,500 candidates spans three chunks at verifyExpiredEphemeralChunk (1,000);
	// the two real dead pods sit at index 0 and 2,499 — first and last chunk.
	candidates := make([]string, 2500)
	for i := range candidates {
		candidates[i] = longPath(i)
	}
	expired, err := svc.VerifyExpiredEphemeral(ctx, candidates)
	require.NoError(t, err, "a multi-thousand-id batch must not hit max_query_size")
	require.True(t, expired[firstDead], "the dead pod in the first chunk must be verified expired")
	require.True(t, expired[lastDead], "the dead pod in the last chunk must be verified expired")
	require.Len(t, expired, 2, "only the two seeded corpses exist; the other 2,498 candidates never had a row")
}

// The cutoff must move with the TYPE's own high-water mark, not with wall-clock
// time. This is the property the whole sweep rests on: if collection of the
// type stops everywhere, the high-water freezes, the cutoff stops advancing,
// and nothing further is judged gone. The mark is per type, not per
// connector: if one cluster's collection breaks while another keeps reporting
// pods, the mark keeps moving and the broken cluster's pods are judged gone.
//
// Proven by moving the high-water mark itself: the SAME pod, at the SAME
// last_seen, flips from gone to live when a fresher pod is removed from the type.
func TestCHRepo_LiveIDsAnchorsToTypeHighWaterNotWallClock(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	svc := NewService(NewCHRepo(ch))

	// This test owns the k8s_pod high-water mark, so it must be the only pod data
	// in the table. Skip rather than corrupt a database that already has pods.
	var existing uint64
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			if scanErr := rows.Scan(&existing); scanErr != nil {
				return scanErr
			}
		}
		return rows.Err()
	}, "SELECT count() FROM assets WHERE type = 'k8s_pod'"))
	if existing > 0 {
		t.Skip("k8s_pod rows already present; this test must own the type's high-water mark")
	}

	p := "it-hw-" + time.Now().Format("150405.000000") + "-"
	now := time.Now().Truncate(time.Second)
	old, newer := p+"old", p+"newer"
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id LIKE ?", p+"%")
	})

	// Both pods are stale by wall-clock. Only their relationship to each other
	// decides liveness.
	require.NoError(t, svc.Ingest(ctx, []Asset{
		{ID: old, Type: "k8s_pod", Provider: ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now.Add(-20 * 24 * time.Hour)},
		{ID: newer, Type: "k8s_pod", Provider: ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now.Add(-1 * time.Hour)},
	}, nil))

	live, err := svc.LiveIDs(ctx, []string{old, newer})
	require.NoError(t, err)
	require.NotContains(t, live, old, "20 days behind the freshest pod is gone")

	// Remove the fresher pod: the high-water mark falls back to `old` itself, and
	// the very same row is now live — because collection for this type has, from
	// the data's point of view, stopped. Under a wall-clock cutoff it would stay
	// gone, which is precisely how an outage turns into mass resolution.
	require.NoError(t, ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id = ?", newer))
	require.Eventually(t, func() bool {
		live, err = svc.LiveIDs(ctx, []string{old})
		return err == nil && len(live) == 1
	}, 30*time.Second, time.Second,
		"with the high-water mark frozen at its own last_seen, the pod must read as live")
}
