package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// packagePageSize is the per-page id count of the package keyset walk — small
// enough that each page's hydration stays well under the per-query memory limit.
const packagePageSize = 5000

const (
	// livePackageIDs is package liveness: a package is live while at least one
	// FRESH edge says something ships or depends on it. Every producer of package
	// nodes writes one with the node and re-stamps it each time it re-observes
	// the package — runs_package from the image scanner and the VM OS-inventory
	// collectors; depends_on from the GitHub SBOM —
	// so a package nothing has re-observed inside the freshness window is no
	// longer installed anywhere we can see. The edge types are pinned to the
	// registry's rels into a Package node by TestLivePackageIDsMatchRegistry.
	//
	// graph_edges is ORDER BY (src_id, edge_type, dst_id), so this filter has no
	// key prefix and scans four narrow columns of the whole table. A package
	// pass reads it ONCE (LivePackageIDs) — never per page: a per-page read
	// re-derives the window against a moving now() and costs a full scan each.
	livePackageIDs = `SELECT DISTINCT dst_id FROM graph_edges
				WHERE edge_type IN ('runs_package', 'depends_on') AND dst_type = 'package'
				  AND ` + graphschema.EdgeFreshnessCond

	// packageCoordsAfter is one keyset page of package rows: the next
	// packagePageSize ids after the cursor, then their argMax metadata and type.
	// assets is ORDER BY (type, id), so the inner select is a
	// primary-key range read in order that stops at the LIMIT; the ids travel
	// server-side as a subquery, so query text stays two small parameters
	// whatever the ids' length (a literal IN list of long module purls exceeds
	// max_query_size). The outer read is over every row of those ids, so the
	// latest type decides — an id whose newest row is not a package is dropped
	// by the caller. Keyset, not OFFSET: the set may grow during the pass, and
	// an offset over a growing prefix skips rows.
	packageCoordsAfter = `SELECT id, argMax(metadata, synced_at), argMax(type, synced_at), ` + firstDiscoveredAtAgg + `
		FROM assets
		WHERE id IN (
			SELECT id FROM assets
			WHERE type = 'package' AND id > ?
			ORDER BY id LIMIT ?
		)
		GROUP BY id`

	// packageCount counts LIVE packages (livePackageIDs) deduplicated with an
	// argMax(type) HAVING — the OSV scan-staleness gauge's denominator. The
	// liveness IN shrinks the GROUP BY to live ids before it aggregates.
	packageCount = `SELECT count() FROM (
	SELECT id FROM assets
	WHERE id IN (` + livePackageIDs + `)
	GROUP BY id
	HAVING argMax(type, synced_at) = 'package'
)`
)

// PackageCoord is the minimal package representation the advisory feeds need.
type PackageCoord struct {
	ID       string
	Metadata map[string]string
	// FirstSeen is when the package node was first written (the pinned
	// first_discovered_at). Zero means unknown, never 1970.
	FirstSeen time.Time
}

// LivePackageIDs returns every package id a fresh edge points at, read once.
func (r *CHRepo) LivePackageIDs(ctx context.Context) (map[string]bool, error) {
	qCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	live := map[string]bool{}
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			live[id] = true
		}
		return nil
	}, livePackageIDs)
	if err != nil {
		return nil, fmt.Errorf("LivePackageIDs: %w", err)
	}
	return live, nil
}

// PackageCoordsAfter returns the package rows of the next keyset page after
// `after` and the cursor for the page following it. next is "" once the walk
// is past the last package id.
func (r *CHRepo) PackageCoordsAfter(ctx context.Context, after string) (coords []PackageCoord, next string, err error) {
	qCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	err = r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				id, raw, typ string
				first        time.Time
			)
			if err := rows.Scan(&id, &raw, &typ, &first); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			if id > next {
				next = id
			}
			if typ != "package" {
				continue
			}
			// An unreadable metadata blob leaves the coordinate without an
			// ecosystem, which every caller skips as unqueryable while still
			// counting the id live — one bad row must not abort the pass.
			var m map[string]string
			_ = json.Unmarshal([]byte(raw), &m)
			if first.Unix() <= 0 {
				first = time.Time{}
			}
			coords = append(coords, PackageCoord{ID: id, Metadata: m, FirstSeen: first})
		}
		return nil
	}, packageCoordsAfter, after, packagePageSize)
	if err != nil {
		return nil, "", fmt.Errorf("PackageCoordsAfter: %w", err)
	}
	return coords, next, nil
}

// CountPackages returns the current count of LIVE package assets — the denominator
// for the OSV scan-staleness gauge's "never scanned" ratio
// (internal/obs/metrics.go, internal/jobs.OSVScanStaleness).
func (r *CHRepo) CountPackages(ctx context.Context) (int64, error) {
	qCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var count uint64
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		if rows.Next() {
			return rows.Scan(&count)
		}
		return nil
	}, packageCount)
	if err != nil {
		return 0, fmt.Errorf("CountPackages: %w", err)
	}
	return int64(count), nil
}
