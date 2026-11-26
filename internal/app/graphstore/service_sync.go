package graphstore

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// SyncFromSources rebuilds the Ladybug graph from ClickHouse and swaps it in.
// Called post-correlate when topology has changed (new/removed edges or assets).
// signals is optional (nil → no finding source is wired, and asset nodes keep
// zero-valued signal props). A wired source that FAILS fails the sync: see below.
//
// The new graph is built in a fresh in-memory database off to the side; the live
// graph keeps serving reads throughout. Only the final swap takes the write lock,
// so callers never observe an empty or half-built graph.
//
// topoVersion is the topology_version from sync_state at the time the caller
// decided to do a full rebuild; stored so the next sync call can skip a full rebuild
// if the version hasn't changed. Pass 0 to disable version tracking.
func (s *Service) SyncFromSources(ctx context.Context, topoVersion uint64, assets AssetSource, edges EdgeSource, signals SignalSource) error {
	logger := log.FromContext(ctx)
	start := time.Now()
	phases := newSyncPhases(s.syncRecorder, start)

	// The three loads are independent ClickHouse reads — run them concurrently to
	// shorten the critical rebuild path. A signal rollup failure aborts the sync
	// like the other two: publishing without it would load every node with
	// has_kev=0/exploitable=0 and pre-warm the cache with the same zeros, so one
	// ClickHouse timeout would show the whole estate as KEV-free. Missing signals
	// are unknown, not clean — the previous graph keeps serving and the next sweep
	// retries.
	var (
		assetRes      asset.AssetSyncResult
		edgeRes       asset.EdgeSyncResult
		sigByResource map[string]NodeSignals
	)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		assetRes, err = assets.ListAll(gctx, SyncProjection())
		if err != nil {
			return fmt.Errorf("list assets: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		edgeRes, err = edges.AllEdges(gctx, SyncProjection())
		if err != nil {
			return fmt.Errorf("list edges: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		if signals == nil {
			return nil
		}
		var err error
		sigByResource, err = signals.SignalsByResource(gctx)
		if err != nil {
			return fmt.Errorf("signal rollup: %w", err)
		}
		return nil
	})
	if err := g.Wait(); err != nil {
		return fmt.Errorf("SyncFromSources: %w", err)
	}
	phases.mark(phaseLoad)

	allAssets := assetRes.Assets
	allEdges := edgeRes.Edges
	// reachComplete gates ReachNone: when any attacker-movement edge type was
	// truncated or the whole bulk pass failed, a not-reached node gets
	// ReachUnknown (fail-open) instead — asserting "no attack path" off an
	// incomplete edge set silently demotes real must-fix findings.
	// A truncated asset load can drop a hop of a real path just as a truncated
	// edge type can, so it degrades reach the same way.
	reachComplete := edgeRes.ReachComplete() && !assetRes.Truncated
	s.reachComplete.Store(reachComplete)
	trunc := make([]string, 0, len(edgeRes.TruncatedTypes))
	for et := range edgeRes.TruncatedTypes {
		trunc = append(trunc, et)
	}
	sortStrings(trunc)
	s.truncatedTypes.Store(trunc)
	if !reachComplete {
		logger.Warn().Msg("graphstore: reach edge set incomplete — internet_hops degrades to ReachUnknown this rebuild")
	}

	// Filter out zero-value assets that add no graph utility: score=0, no edges,
	// and not a security-sensitive type. Cuts a large share of assets (k8s_configmap,
	// orphaned subnets, placeholder records) without losing any attack-path data.
	allAssets = filterLadybugAssets(allAssets, allEdges)
	phases.mark(phaseFilter)
	logger.Info().
		Int("assets", len(allAssets)).
		Int("edges", len(allEdges)).
		Msg("graphstore: asset set ready for Ladybug sync")

	// ── The fidelity gate ────────────────────────────────────────────────────
	//
	// Ahead of the digest gate and everything after it, because a degraded load set
	// must not be able to take ANY path: not the full rebuild, not the cheap signal
	// refresh, not the no-op. Abandoning here also means a refusal costs only the
	// ClickHouse read rather than the read plus COPY, BFS and snapshot.
	//
	// Nothing below this point runs on a refusal, which is the property that matters:
	// no swap, no lastBuiltAt, no digest latched, no snapshot written, no signal-cache
	// prewarm. The graph the pod is serving is untouched.
	s.edgeFetchComplete.Store(edgeRes.FetchComplete())
	s.assetFetchComplete.Store(!assetRes.Truncated)
	// A truncated asset load is a self-reported partial fetch, like a truncated
	// edge type: the gate refuses it rather than publishing a graph missing assets.
	fetchComplete := edgeRes.FetchComplete() && !assetRes.Truncated
	fetchDetail := edgeRes.Detail()
	if assetRes.Truncated {
		if fetchDetail != "" {
			fetchDetail += "; "
		}
		fetchDetail += "assets truncated at the sync row cap"
	}
	cand := shapeOf(allAssets, allEdges)
	now := time.Now()
	baseline, refusal := s.fidelity.snapshotState(now)
	// Case 2: a cold pod (nothing being served yet) is a different risk
	// profile than a warm one — refusing forever there trades a real outage for a
	// possibly-stale-but-live graph, whereas a warm pod that refuses keeps serving
	// its last good graph and loses nothing by refusing indefinitely. noGraphServed
	// is exactly "is anything currently being protected by this refusal".
	noGraphServed := !s.synced.Load()
	verdict := checkFidelity(cand, baseline, fetchComplete, fetchDetail, refusal, noGraphServed)
	switch {
	case verdict.Refuse:
		rec := s.fidelity.recordRefusal(cand, verdict.Reason, now.Unix())
		if p := refusalRecordPath(s.snapshotPath); p != "" {
			if perr := writeRefusalRecord(p, rec); perr != nil {
				logger.Warn().Err(perr).Msg("graphstore: failed to persist the fidelity-gate refusal — a crash before the next sweep would restart the repeat clock (case 4)")
			}
		}
		logger.Error().
			Str("reason", verdict.Reason).
			Int("candidate_assets", cand.Assets).
			Int("candidate_edges", cand.TotalEdges).
			Int("baseline_assets", baseline.Assets).
			Int("baseline_edges", baseline.TotalEdges).
			Msg("graphstore: REBUILD ABANDONED — candidate graph failed the fidelity gate; the previous graph is still serving. If this shape is a real estate change, the next sweep publishes it (see fidelity.go acceptOnRepeat)")
		return fmt.Errorf("SyncFromSources: %w: %s", ErrRebuildRefused, verdict.Reason)
	case verdict.Reason != "":
		// acceptOnRepeat: a second sweep produced the same shape, so this is reality
		// rather than a transient. Publish it, and say so at Error level — the whole
		// point is that nobody discovers a large step by reading a dashboard later.
		s.fidelity.recordRepeatPublish(verdict.RepeatCategory)
		logger.Error().
			Str("reason", verdict.Reason).
			Str("repeat_category", verdict.RepeatCategory).
			Int("assets", cand.Assets).
			Int("edges", cand.TotalEdges).
			Msg("graphstore: publishing a graph that failed the fidelity gate because the SAME shape arrived twice — confirm this is an intended estate change (purge/prune/connector removal) and not a persistent degradation")
	}

	// Exposure set and attacker-movement hop counts, derived ONCE for the whole
	// sweep: the digest walk below, the loader, and the post-swap signal-cache
	// prewarm all need the same pair, so none derives its own.
	ov := newReachOverlay(allEdges)
	phases.mark(phaseReach)

	// The load-digest gate. Computed here — after filterLadybugAssets, which drops
	// a large share of assets and depends on the edge set — so it fingerprints exactly what
	// bulkSyncCopy is about to load.
	//
	// Topo match means the rebuilt graph would be identical in every column the
	// cheap paths cannot rewrite; only the signal columns (applySignals) and the
	// risk-score columns (refreshScores) could differ, and each moved half gets its
	// in-place writer. All three matching means the rebuild is a provable no-op.
	// Either way the ClickHouse read above is still paid every sweep; what this
	// skips is the larger cost of COPY + BFS + snapshot.
	dig, digErr := computeLoadDigest(allAssets, allEdges, ov, sigByResource, reachComplete)
	phases.mark(phaseDigest)
	if digErr != nil {
		// Fail OPEN: a digest we could not compute must mean "rebuild", never "skip".
		logger.Warn().Err(digErr).Msg("graphstore: load digest failed — falling through to full rebuild")
	} else if prev := s.lastDigest.Load(); prev != nil && s.synced.Load() && prev.Topo == dig.Topo {
		if prev.Signals == dig.Signals && prev.Scores == dig.Scores {
			// Nothing to do. lastBuiltAt IS stamped: a correctly-skipped sweep means
			// the graph is current, and the freshness gauge must not read as stale.
			s.prewarmSignalCache(sigByResource)
			s.lastBuiltAt.Store(time.Now().UnixNano())
			s.emptyConfirmed.Store(s.nodeCount.Load() == 0)
			// The live graph holds this shape (topo digest matched), so it is a valid
			// baseline. Recording it on the cheap paths too is what keeps the gate armed
			// after a warm start, where the snapshot seeds a digest that then matches and
			// no full rebuild ever runs to set the baseline.
			s.fidelity.publishedShape(cand)
			clearRefusalRecord(refusalRecordPath(s.snapshotPath))
			s.recordSyncPath(syncPathNoop, time.Since(start))
			logger.Info().Uint64("topo_digest", dig.Topo).Dur("elapsed", time.Since(start)).
				Msg("graphstore: load set unchanged — rebuild skipped")
			return nil
		}
		refreshed := true
		if prev.Signals != dig.Signals {
			if sErr := s.applySignals(ctx, sigByResource); sErr != nil {
				logger.Warn().Err(sErr).Msg("graphstore: signal refresh failed — falling through to full rebuild")
				refreshed = false
			}
		} else {
			// Score-only refresh still re-warms the cache: the rollup is unchanged
			// but this sweep's copy is the one enrich reads next.
			s.prewarmSignalCache(sigByResource)
		}
		if refreshed && prev.Scores != dig.Scores {
			if scErr := s.refreshScores(ctx, allAssets, allEdges); scErr != nil {
				logger.Warn().Err(scErr).Msg("graphstore: score refresh failed — falling through to full rebuild")
				refreshed = false
			}
		}
		if refreshed {
			s.lastDigest.Store(&dig)
			s.lastBuiltAt.Store(time.Now().UnixNano())
			s.fidelity.publishedShape(cand)
			clearRefusalRecord(refusalRecordPath(s.snapshotPath))
			s.recordSyncPath(syncPathSignals, time.Since(start))
			return nil
		}
	}

	// Build the replacement graph in a fresh in-memory database.
	newDB, err := openAndInit(s.bufferMB, s.poolSize, s.queryThreads)
	if err != nil {
		return fmt.Errorf("SyncFromSources: %w", err)
	}
	wc, err := newDB.newWriteConn()
	if err != nil {
		newDB.close()
		return fmt.Errorf("SyncFromSources: write conn: %w", err)
	}
	loadStats, err := bulkSyncCopy(ctx, wc, allAssets, allEdges, ov, sigByResource, reachComplete, s.resolveLoadThreads(), edges.VerifyExpiredEphemeral)
	if err != nil {
		wc.Close()
		newDB.close()
		return fmt.Errorf("SyncFromSources: %w", err)
	}
	s.storeLoadStats(ctx, loadStats)
	// Close the write connection before propagation. Ladybug is single-writer: if it
	// stays open, every BFS score update fails to acquire a write connection.
	wc.Close()
	phases.mark(phaseCopy)

	// Propagate risk scores via BFS using the edges already in memory — no extra
	// Ladybug reads. Returns which nodes the BFS boosted, purely as an observability
	// signal on the rebuild log line: the post-BFS score itself lives in Ladybug,
	// which is what serves it. The second return says whether every score reached
	// the graph — see propagateRisk.
	boosted, scoresApplied, bfsErr := propagateRisk(ctx, newDB, allAssets, allEdges)
	if bfsErr != nil {
		// Publishing would serve base scores for every node the BFS never
		// reached. Abandon the candidate; the live graph keeps its scores.
		newDB.close()
		return fmt.Errorf("SyncFromSources: %w", bfsErr)
	}
	// Stash what the graph now holds per score-bearing node, so a later Scores-half
	// change can diff-and-write in place instead of rebuilding — but ONLY when every
	// score actually landed. See propagateRisk's second return.
	if scoresApplied {
		finals := finalRiskScores(allAssets, boosted)
		s.lastScores.Store(&finals)
	} else {
		logger.Warn().Msg("graphstore: bfs scores not fully applied — score stash withheld, next sync rebuilds")
	}
	phases.mark(phaseBFS)

	// Swap the new graph in. The write lock waits for in-flight reads to drain, so
	// the old database has no readers by the time we close it.
	s.mu.Lock()
	old := s.db
	s.db = newDB
	s.publishNodeTableRows(loadStats.nodeTableRows)
	s.mu.Unlock()
	if old != nil {
		old.close()
	}

	// Evict the old NodeSignals cache entries, then immediately pre-populate EVERY
	// loaded node (sigByResource's finding-bearing entries plus every other node in
	// allAssets — already loaded from CH above, zero extra ClickHouse cost). This
	// prevents a burst of Ladybug pool acquisitions when enrich workers run after
	// correlate: without pre-population every job cache-misses into several
	// serialised Ladybug queries and the pool saturates.
	s.identityZeroHop.Store(int64(ov.identityDropped))
	s.setLastHops(ov, reachComplete, assetIDs(allAssets))
	s.prewarmSignalCache(sigByResource)
	s.blastAdj.Store(buildBlastAdjacency(allAssets, allEdges))
	logger.Debug().Int("finding_bearing", len(sigByResource)).Int("nodes_loaded", len(allAssets)).
		Msg("graphstore: nodeSignalsCache pre-warmed for every loaded node")

	if topoVersion != 0 {
		s.lastTopoVersion.Store(topoVersion)
	}
	phases.mark(phaseSwap)

	// Write topology snapshot to PVC for fast restarts. Best-effort — failure
	// is logged but does not abort the sync (graph is already live).
	if s.snapshotPath != "" {
		// TopoDigest carries the gate baseline across a restart: LoadFromSnapshot
		// verifies it against a recompute and seeds lastDigest, so a warm-started
		// pod's first sync can skip its rebuild. Zero (digest failed) seeds nothing
		// — the first sync then rebuilds, which is the fail-open default.
		var topoDigest uint64
		if digErr == nil && scoresApplied {
			topoDigest = dig.Topo
		}
		snap := GraphSnapshot{
			SchemaVersion:      SchemaVersion,
			TopoDigest:         topoDigest,
			BuiltAt:            time.Now().UTC(),
			Assets:             allAssets,
			Edges:              allEdges,
			ReachComplete:      reachComplete,
			EdgeFetchComplete:  edgeRes.FetchComplete(),
			AssetFetchComplete: !assetRes.Truncated,
		}
		if snapErr := WriteSnapshot(s.snapshotPath, snap); snapErr != nil {
			logger.Warn().Err(snapErr).Msg("graphstore: snapshot write failed")
		} else {
			logger.Debug().Str("path", s.snapshotPath).Msg("graphstore: snapshot written")
		}
		phases.mark(phaseSnapshot)
	}

	// Record count + build time BEFORE flipping synced (see Ready()).
	s.nodeCount.Store(int64(len(allAssets)))
	s.emptyConfirmed.Store(false)
	s.lastBuiltAt.Store(time.Now().UnixNano())
	s.synced.Store(true)
	// The swap succeeded, so THIS is what the next candidate is measured against —
	// and any pending refusal is now resolved. Recorded after the swap for the same
	// reason the digest is: a baseline for a graph that never went live would let the
	// gate compare against something nobody is serving.
	s.fidelity.publishedShape(cand)
	clearRefusalRecord(refusalRecordPath(s.snapshotPath))
	// Store the digest only now, after the swap succeeded — a failed rebuild must
	// retry, not latch a digest for a graph it never loaded. Skipped when the digest
	// could not be computed, so the next sweep rebuilds rather than comparing against
	// a stale value.
	//
	// Also skipped when the BFS scores did not all land. Withholding the score stash
	// is NOT sufficient on its own: the Scores half is computed from the assets
	// ClickHouse returned, not from the stash, so an unchanged corpus would match it
	// next sweep and the cheap path would skip the refresh that repairs the graph.
	// Latching nothing is what actually forces the rebuild.
	if digErr == nil && scoresApplied {
		s.lastDigest.Store(&dig)
	}
	s.recordSyncPath(syncPathFull, time.Since(start))
	// A build that produced zero nodes is a red flag (transient ClickHouse blip,
	// filter misconfig). Ready() stays false so serve won't route to it, but log
	// loudly so the empty graph is visible rather than silently "synced".
	if len(allAssets) == 0 {
		logger.Error().Uint64("topo_version", topoVersion).
			Msg("graphstore: sync produced ZERO nodes — graph stays not-ready; check ClickHouse/filters")
	}
	busyHits := newDB.poolBusyHits.Load()
	queryCount := newDB.queryCount.Load()
	elapsed := time.Since(start)
	phases.warnIfUnattributed(logger, elapsed)
	phases.logTo(logger.Info().
		Dur("elapsed", elapsed).
		Int("assets", len(allAssets)).
		Int("edges", len(allEdges)).
		Int("boosted", len(boosted)).
		Uint64("topo_version", topoVersion).
		Int64("pool_busy_hits", busyHits).
		Int64("pool_queries", queryCount)).
		Msg("graphstore: sync complete")
	return nil
}
