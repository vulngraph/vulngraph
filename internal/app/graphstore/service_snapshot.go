package graphstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// LoadFromSnapshot attempts to bootstrap the graph from the PVC snapshot file,
// avoiding a full ClickHouse read on startup. Returns nil on success (graph is
// ready and synced=true). Returns ErrSnapshotMissing or ErrSnapshotStale when
// the snapshot is absent or from another schema — callers should fall through to
// SyncFromSources.
//
// A successful load also seeds the load-digest gate from the snapshot header, so
// the follow-up sync a warm start always schedules can take the cheap path when
// ClickHouse still holds what the snapshot holds — without this, every restart
// forced a full rebuild regardless of whether anything had actually changed.
func (s *Service) LoadFromSnapshot(ctx context.Context, signals SignalSource) error {
	if s.snapshotPath == "" {
		return ErrSnapshotMissing
	}
	logger := log.FromContext(ctx)
	start := time.Now()

	// Case 4: restore a pending fidelity-gate refusal that a worker crash
	// wiped from memory before it could reach minRepeatAge, along with its decline
	// streak. Independent of whether the snapshot itself is usable below — a
	// refusal's shape and clock have no SchemaVersion or loading-set dependency, see
	// fidelity_persist.go — and must run before any publishedShape call in this
	// function, which deliberately clears this same state for a FRESH decision.
	if rec, ok := readRefusalRecord(refusalRecordPath(s.snapshotPath)); ok {
		s.fidelity.rearmRefusal(rec)
	}

	snap, err := ReadSnapshot(s.snapshotPath, SchemaVersion)
	if err != nil {
		// Case 1: a SchemaVersion bump makes ReadSnapshot reject the file
		// (ErrSnapshotStale). Layer 2 must still get a baseline here, or the very
		// first post-deploy build — exactly the moment a producer regression is
		// most likely — would go unchecked. The snapshot cannot seed the GRAPH across a version bump (no
		// in-place Ladybug migration), but its shape is still a fine Layer-2 baseline:
		// a version bump gates Ladybug's DDL/loading set, not the ClickHouse row counts
		// Layer 2 compares. See ReadSnapshotShapeAnyVersion.
		if errors.Is(err, ErrSnapshotStale) {
			if shape, ok := ReadSnapshotShapeAnyVersion(s.snapshotPath); ok {
				s.fidelity.seedBaseline(shape)
				logger.Info().Msg("graphstore: snapshot schema-stale — armed the fidelity baseline from its shape anyway (case 1)")
			}
		}
		return err // ErrSnapshotMissing or ErrSnapshotStale — caller falls through
	}
	if age := time.Since(snap.BuiltAt); snap.BuiltAt.IsZero() || age > snapshotMaxAge {
		// Serving a days-old topology as if current is worse than a cold rebuild:
		// every consumer reads LastBuiltAt as "how fresh is this graph". Its shape
		// is still the last published one, so it arms the fidelity baseline (as
		// in case 1 above).
		s.fidelity.seedBaseline(shapeOf(snap.Assets, snap.Edges))
		return fmt.Errorf("LoadFromSnapshot: %w: built %s ago (max %s)", ErrSnapshotStale, age.Round(time.Second), snapshotMaxAge)
	}

	// Re-query signals — they change frequently and aren't stored in the snapshot.
	// A failed rollup fails the warm start rather than loading every node with
	// zero signals: that graph would read as KEV-free everywhere, and the caller's
	// fallback (a full sync, retried until it succeeds) is the honest alternative.
	var sigByResource map[string]NodeSignals
	if signals != nil {
		sigByResource, err = signals.SignalsByResource(ctx)
		if err != nil {
			return fmt.Errorf("LoadFromSnapshot: signal rollup: %w", err)
		}
	}

	snap.Assets = filterLadybugAssets(snap.Assets, snap.Edges)
	ov := newReachOverlay(snap.Edges)

	newDB, err := openAndInit(s.bufferMB, s.poolSize, s.queryThreads)
	if err != nil {
		return fmt.Errorf("LoadFromSnapshot: %w", err)
	}
	wc, err := newDB.newWriteConn()
	if err != nil {
		newDB.close()
		return fmt.Errorf("LoadFromSnapshot: write conn: %w", err)
	}
	s.reachComplete.Store(snap.ReachComplete)
	// verifyExpired is nil here on purpose: the fast-boot path from a PVC snapshot
	// deliberately avoids a ClickHouse round trip, and any endpoint misclassified
	// as endpoint_absent instead of endpoint_expired for this one load is corrected
	// within seconds by the background refresh that runs after warm start.
	loadStats, err := bulkSyncCopy(ctx, wc, snap.Assets, snap.Edges, ov, sigByResource, snap.ReachComplete, s.resolveLoadThreads(), nil)
	if err != nil {
		wc.Close()
		newDB.close()
		return fmt.Errorf("LoadFromSnapshot: bulkSyncCopy: %w", err)
	}
	s.storeLoadStats(ctx, loadStats)
	wc.Close()

	boosted, scoresApplied, bfsErr := propagateRisk(ctx, newDB, snap.Assets, snap.Edges)
	if bfsErr != nil {
		newDB.close()
		return fmt.Errorf("LoadFromSnapshot: %w", bfsErr)
	}
	// Stash ONLY what the graph actually holds. A failed BFS write means the live
	// scores are un-boosted, so recording the boosts would make every later sweep
	// no-op against a wrong value that refreshScores' diff then refuses to correct.
	// Leaving the stash and the digest unset falls open into a full rebuild.
	if scoresApplied {
		finals := finalRiskScores(snap.Assets, boosted)
		s.lastScores.Store(&finals)
	} else {
		logger.Warn().Msg("graphstore: bfs scores not fully applied — score stash withheld, next sync rebuilds")
	}

	s.mu.Lock()
	old := s.db
	s.db = newDB
	s.publishNodeTableRows(ctx, loadStats.nodeTableRows)
	s.mu.Unlock()
	if old != nil {
		old.close()
	}

	// Seed the load-digest gate from the header so the follow-up sync can skip
	// its rebuild. The Topo half is verified against a recompute over the loaded
	// content: a mismatch means the digest algorithm changed since the snapshot
	// was written (or the header lies), and seeding it would let the gate skip a
	// rebuild it owes — so seed nothing and let the first sync rebuild (fail open).
	// Scores/Signals come from the recompute: signals are re-queried fresh above,
	// not stored in the snapshot.
	// scoresApplied gates this for the same reason it gates the stash: a seeded digest
	// with un-boosted scores in the graph lets the follow-up sync skip the repair.
	if snap.TopoDigest != 0 && scoresApplied {
		if dig, digErr := computeLoadDigest(snap.Assets, snap.Edges, ov, sigByResource, snap.ReachComplete); digErr == nil && dig.Topo == snap.TopoDigest {
			s.lastDigest.Store(&dig)
		} else {
			logger.Info().Err(digErr).Msg("graphstore: snapshot digest mismatch — first sync will do a full rebuild")
		}
	}

	s.identityZeroHop.Store(int64(ov.identityDropped))
	s.setLastHops(ov, snap.ReachComplete, assetIDs(snap.Assets))
	s.prewarmSignalCache(sigByResource)
	s.blastAdj.Store(buildBlastAdjacency(snap.Assets, snap.Edges))

	// Record count + build time BEFORE flipping synced, so a concurrent Ready()
	// never observes synced=true with a zero node count.
	s.nodeCount.Store(int64(len(snap.Assets)))
	// The graph is as old as the build that produced the snapshot, not the load.
	s.lastBuiltAt.Store(snap.BuiltAt.UnixNano())
	s.synced.Store(true)
	// Arm the fidelity gate from the snapshot. Without this every restart would
	// leave the gate with no baseline and fail its first sync open — precisely
	// the window a degraded rebuild would slip through. The snapshot IS the last
	// published graph, so its own shape is the correct baseline.
	//
	// edgeFetchComplete is replayed from the record, not assumed: a cold pod can
	// publish (and snapshot) a partial fetch on repeat (checkFidelity), and a
	// snapshot that predates the field reads false — the safe value. The same
	// holds for assetFetchComplete.
	s.edgeFetchComplete.Store(snap.EdgeFetchComplete)
	s.assetFetchComplete.Store(snap.AssetFetchComplete)
	// seedBaseline, not publishedShape: this arms Layer 2's comparison point only.
	// publishedShape would also clear any refusal rearmed above (case 4), but a
	// snapshot load is not a fresh gate decision — a still-open refusal must
	// survive it untouched.
	s.fidelity.seedBaseline(shapeOf(snap.Assets, snap.Edges))
	logger.Info().
		Dur("elapsed", time.Since(start)).
		Int("assets", len(snap.Assets)).
		Int("edges", len(snap.Edges)).
		Int("boosted", len(boosted)).
		Str("snapshot_built_at", snap.BuiltAt.Format(time.RFC3339)).
		Msg("graphstore: loaded from snapshot (skipped ClickHouse read)")
	return nil
}

// LastTopologyVersion returns the topology version used in the last full rebuild.
// Zero means no full sync has completed yet.
func (s *Service) LastTopologyVersion() uint64 { return s.lastTopoVersion.Load() }

// SetLastTopologyVersion records the topology version after a successful full
// rebuild. It has no production caller: SyncFromSources stores the version itself.
func (s *Service) SetLastTopologyVersion(v uint64) { s.lastTopoVersion.Store(v) }
