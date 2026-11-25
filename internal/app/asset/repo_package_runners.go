package asset

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// The departure evidence for packages that left the live set. These are the
// one deliberately historical package read: the LAPSED edges are the subject —
// which runners used to ship the package, and whether each runner's producer
// read it again afterwards — not topology anything traverses. So, unlike every
// other graph_edges reader, they are not freshness-gated; this file is listed
// in graphschema's freshnessExempt with that reason. The edge TTL (30 days)
// bounds how far back they see.

// runnerIDChunk bounds one IN list. Query text grows with the ids (an image
// runner id is ~80 bytes), and a package upgraded across a fleet has thousands
// of runners inside the TTL: one unchunked list exceeds max_query_size.
const runnerIDChunk = 500

const (
	// packageRunnerEdges: every runner with an edge into the packages, with
	// that edge's newest stamp. dst_id is key position 3; the idx_dst_id bloom
	// index prunes the granules. %s is filled by db.CHIn. The explicit 30-day
	// bound is graph_edges' TTL: TTL merges run when
	// they run, so without it the window would depend on merge timing. The
	// departure job's graphEdgeTTL mirrors it.
	packageRunnerEdges = `SELECT dst_id, src_id, src_type, edge_type, max(synced_at)
		FROM graph_edges
		WHERE dst_id IN (%s) AND dst_type = 'package' AND edge_type IN ('runs_package', 'depends_on')
		  AND synced_at >= now() - INTERVAL 30 DAY
		GROUP BY dst_id, src_id, src_type, edge_type`

	// runnerInventoryStamps: each runner's newest package-edge stamp per edge
	// type — when its producer last read its inventory. src_id leads the sort
	// key.
	runnerInventoryStamps = `SELECT src_id, edge_type, max(synced_at)
		FROM graph_edges
		WHERE src_id IN (%s) AND edge_type IN ('runs_package', 'depends_on')
		GROUP BY src_id, edge_type`
)

// PackageRunners returns every runner with an edge into packageIDs inside the
// edge TTL, each with its edge's newest stamp and its latest inventory stamp.
// Both reads are chunked (runnerIDChunk); any chunk failing fails the call, so
// a caller never judges a package on a partial runner list.
func (r *CHRepo) PackageRunners(ctx context.Context, packageIDs []string) ([]PackageRunner, error) {
	var runners []PackageRunner
	for start := 0; start < len(packageIDs); start += runnerIDChunk {
		chunk, err := r.packageRunnerEdges(ctx, packageIDs[start:min(start+runnerIDChunk, len(packageIDs))])
		if err != nil {
			return nil, fmt.Errorf("PackageRunners: %w", err)
		}
		runners = append(runners, chunk...)
	}
	if len(runners) == 0 {
		return nil, nil
	}

	seen := map[string]bool{}
	var srcIDs []string
	for _, p := range runners {
		if !seen[p.RunnerID] {
			seen[p.RunnerID] = true
			srcIDs = append(srcIDs, p.RunnerID)
		}
	}
	stamps := map[runnerStampKey]time.Time{}
	for start := 0; start < len(srcIDs); start += runnerIDChunk {
		if err := r.runnerInventoryStamps(ctx, srcIDs[start:min(start+runnerIDChunk, len(srcIDs))], stamps); err != nil {
			return nil, fmt.Errorf("PackageRunners: %w", err)
		}
	}
	for i := range runners {
		runners[i].InventoryAt = stamps[runnerStampKey{runners[i].RunnerID, runners[i].EdgeType}]
	}
	return runners, nil
}

type runnerStampKey struct{ src, edgeType string }

func (r *CHRepo) packageRunnerEdges(ctx context.Context, packageIDs []string) ([]PackageRunner, error) {
	qCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	placeholders, args := dbutil.CHIn(packageIDs)
	var out []PackageRunner
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var p PackageRunner
			if err := rows.Scan(&p.PackageID, &p.RunnerID, &p.RunnerType, &p.EdgeType, &p.EdgeAt); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, p)
		}
		return nil
	}, fmt.Sprintf(packageRunnerEdges, placeholders), args...)
	if err != nil {
		return nil, fmt.Errorf("packageRunnerEdges: %w", err)
	}
	return out, nil
}

func (r *CHRepo) runnerInventoryStamps(ctx context.Context, srcIDs []string, into map[runnerStampKey]time.Time) error {
	qCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	placeholders, args := dbutil.CHIn(srcIDs)
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				k  runnerStampKey
				at time.Time
			)
			if err := rows.Scan(&k.src, &k.edgeType, &at); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			into[k] = at
		}
		return nil
	}, fmt.Sprintf(runnerInventoryStamps, placeholders), args...)
	if err != nil {
		return fmt.Errorf("runnerInventoryStamps: %w", err)
	}
	return nil
}
