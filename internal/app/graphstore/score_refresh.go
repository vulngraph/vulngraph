package graphstore

// score_refresh.go — the in-place risk-score writer behind the load-digest gate.
//
// The `score` column on the bfsScoreLabels holds asset.RiskScore plus the BFS
// boost. RiskScore is rewritten between sweeps by construction (collector base
// scorer, CIEM ScoredAssets, correlate's scoreAssetsFromFindings), so it lives in
// the digest's Scores half, not Topo — otherwise the gate never fires. That is
// only sound because THIS path exists: a Scores-half change re-runs the same
// in-memory BFS over the assets/edges the sync already read and rewrites the
// changed score columns on the live graph, so skipping the rebuild loses nothing.

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// maxScoreRefreshRows caps how large a diff is worth applying in place. Above it the
// in-place path is the WORSE option: the SET holds the reader-blocking swap lock for
// its full duration, and the row maps are a large transient allocation on a
// memory-constrained worker. The off-side full rebuild has neither property — it builds
// a replacement graph and swaps once. 25,000 is a chosen ceiling, not a
// measured one; the lock_held warning below (over 200ms) is what shows whether
// a refresh of that size holds the lock too long.
const maxScoreRefreshRows = 25_000

// CarriesRiskScore reports whether the Ladybug `score` column of an asset of this
// type holds its post-BFS risk score. Package's holds a finding severity, so a
// reader taking node.score as a risk score must check this first.
func CarriesRiskScore(assetType string) bool {
	_, ok := riskScoreColIdx[NodeLabelFor(assetType)]
	return ok
}

// finalRiskScores is the post-BFS score per node for the labels whose score
// column holds asset.RiskScore: the base score overlaid with the BFS boost.
// This is exactly what a full rebuild leaves in the graph (COPY loads the base,
// propagateRisk raises the boosted ones), computed without touching Ladybug.
// Deduped first-occurrence-wins to mirror streamNodeRows: the loader emits one
// node per id, so the stash must too.
func finalRiskScores(assets []asset.Asset, boosted map[string]uint8) map[string]uint8 {
	finals := make(map[string]uint8, len(assets))
	for i := range assets {
		a := &assets[i]
		if _, ok := riskScoreColIdx[NodeLabelFor(a.Type)]; !ok {
			continue // Package et al: score column is not asset.RiskScore
		}
		if _, dup := finals[a.ID]; dup {
			continue
		}
		if b, ok := boosted[a.ID]; ok {
			finals[a.ID] = b
		} else {
			finals[a.ID] = a.RiskScore
		}
	}
	return finals
}

// scoreSetQuery is the only statement that writes a risk-score column. Both writers
// use it so the two cannot drift.
func scoreSetQuery(label string) string {
	return fmt.Sprintf(`UNWIND $rows AS r MATCH (n:%s {id: r.id}) SET n.score = r.score`, label)
}

// scoreRowsByLabel partitions score-write rows by the Ladybug label the LOADER gives
// each asset, so every row is MATCHed exactly once instead of once per label.
//
// The label rule is NodeLabelFor(a.Type) restricted to riskScoreColIdx (the labels
// whose `score` column holds asset.RiskScore — Package's holds a finding severity),
// with first-occurrence-wins dedup. That is streamNodeRows' rule verbatim, which is
// what makes the routing safe: a row can only be sent to the label the node was
// actually loaded under.
//
// rowFor decides whether a node needs a row and what value it carries: the BFS
// writer asks for every boosted node, the in-place refresh asks only for nodes whose
// score differs from the stash.
//
// maxRows > 0 aborts as soon as the row count exceeds it, BEFORE materialising the
// rest. That ordering is load-bearing for refreshScores: the diff is unbounded (a
// cold stash makes it the whole corpus), the rows are a map per node, and this runs
// on a memory-constrained worker. Pass 0 for no cap — the off-side BFS
// writer is bounded by the boost set and holds no reader lock.
func scoreRowsByLabel(assets []asset.Asset, rowFor func(id string) (int32, bool), maxRows int) (map[string][]map[string]any, int, error) {
	rows := make(map[string][]map[string]any, len(bfsScoreLabels))
	seen := make(map[string]bool, len(assets))
	total := 0
	for i := range assets {
		a := &assets[i]
		label := NodeLabelFor(a.Type)
		if _, ok := riskScoreColIdx[label]; !ok || seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		v, want := rowFor(a.ID)
		if !want {
			continue
		}
		rows[label] = append(rows[label], map[string]any{"id": a.ID, "score": v})
		total++
		if maxRows > 0 && total > maxRows {
			return nil, total, fmt.Errorf("scoreRowsByLabel: %d+ rows exceeds cap (%d)", total, maxRows)
		}
	}
	return rows, total, nil
}

// refreshScores rewrites the risk-score columns of the LIVE graph in place: it
// recomputes every node's post-BFS score from the assets/edges this sync already
// read, diffs against the stash of what the live graph currently holds
// (lastScores), and UNWIND-SETs only the changed rows per label. Called by the
// SyncFromSources gate when the Topo half matched but the Scores half moved.
//
// Any failure — missing stash, write-conn or UNWIND error — returns an error and
// the caller falls through to a full rebuild (fail open, same discipline as the
// digest itself). The stash is updated only after every write succeeded, so a
// partial failure can never latch scores the graph does not hold; the rebuild
// (or the next diff against the untouched stash) repairs the partial writes.
func (s *Service) refreshScores(ctx context.Context, assets []asset.Asset, edges []asset.Edge) error {
	prev := s.lastScores.Load()
	if prev == nil {
		return fmt.Errorf("refreshScores: no score stash — full rebuild required")
	}

	// An incomplete BFS writes nothing and leaves the stash alone: the live graph
	// keeps its previous scores, and the caller's fall-through rebuild refuses to
	// publish for the same reason.
	boosted, err := computeBoostedScores(ctx, assets, edges)
	if err != nil {
		return fmt.Errorf("refreshScores: %w", err)
	}
	finals := finalRiskScores(assets, boosted)

	// Only the nodes whose score actually moved, capped at maxScoreRefreshRows. Past
	// the cap the in-place path is the WORSE option — the UNWIND SET runs under s.mu
	// and blocks every reader for its whole duration, and the rows are a map per node
	// on a memory-constrained worker — so scoreRowsByLabel aborts
	// and the caller falls through to the off-side full rebuild, which holds the read
	// lock only for the pointer swap.
	rowsByLabel, pending, capErr := scoreRowsByLabel(assets, func(id string) (int32, bool) {
		f := finals[id]
		if old, ok := (*prev)[id]; ok && old == f {
			return 0, false
		}
		return int32(f), true
	}, maxScoreRefreshRows)
	if capErr != nil {
		return fmt.Errorf("refreshScores: %d+ changed scores exceeds maxScoreRefreshRows (%d) — full rebuild is cheaper",
			pending, maxScoreRefreshRows)
	}

	changed := 0
	if len(rowsByLabel) > 0 {
		lockStart := time.Now()
		s.mu.Lock()
		if s.db == nil {
			s.mu.Unlock()
			return ErrLadybugUnavailable
		}
		wc, err := s.db.newWriteConn()
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("refreshScores: write conn: %w", err)
		}
		for _, label := range bfsScoreLabels {
			rows := rowsByLabel[label]
			if len(rows) == 0 {
				continue
			}
			if _, uErr := unwindInsert(wc, scoreSetQuery(label), rows); uErr != nil {
				wc.Close()
				s.mu.Unlock()
				return fmt.Errorf("refreshScores: %s: %w", label, uErr)
			}
			changed += len(rows)
		}
		wc.Close()
		lockElapsed := time.Since(lockStart)
		s.mu.Unlock()
		if lockElapsed > 200*time.Millisecond {
			log.FromContext(ctx).Warn().Dur("lock_held", lockElapsed).
				Msg("graphstore: refreshScores write lock held longer than expected")
		}
	}

	s.lastScores.Store(&finals)
	log.FromContext(ctx).Info().Int("changed", changed).Int("nodes", len(finals)).
		Msg("graphstore: risk scores refreshed (no topology rebuild)")
	return nil
}
