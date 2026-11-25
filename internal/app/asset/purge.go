package asset

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// purgeEdgeChunk caps how many asset IDs go into one ALTER TABLE ... DELETE's
// IN list at a time — one enormous mutation for a large account's ID list is
// unnecessary risk for no benefit, and chunking keeps each mutation small and
// fast regardless of account size.
//
// 500, not a larger round number: this package's ids are not uniformly short
// (AWS ARNs and k8s paths both land here), and each DELETE below embeds TWO
// copies of one chunk (src_id IN (...) OR dst_id IN (...)). ClickHouse's
// ?-placeholder binding substitutes values into the query TEXT client-side, so
// a larger chunk risks exceeding max_query_size. 500 matches the convention
// used elsewhere in this package (optimize.go, explore.idChunkSize).
const purgeEdgeChunk = 500

// purgeAccountCount counts the distinct asset ids one provider+account holds.
const purgeAccountCount = `SELECT count() FROM (
	SELECT id FROM assets WHERE provider = ? AND account_id = ? GROUP BY id
)`

// purgeAccountDelete hard-deletes every asset row for one provider+account.
const purgeAccountDelete = `ALTER TABLE assets DELETE WHERE provider = ? AND account_id = ?`

// assetIDsByAccount lists the distinct asset ids one provider+account holds.
const assetIDsByAccount = `SELECT id FROM assets
	WHERE provider = ? AND account_id = ? GROUP BY id`

// PurgeAccount hard-deletes every asset for one provider+account — the
// explicit, deliberate counterpart to the staleness-based lifecycle sweep
// (jobs/dangling.go), which will NEVER touch cloud resource types no matter
// how stale they get: "not re-collected" is deliberately read as "collection
// paused", not "deleted" (a real outage would otherwise erase the graph).
// That default leaves a genuinely decommissioned account's assets with no
// path to ever leaving the graph on their own, which is what this exists to
// fix.
//
// This is therefore a NAMED admin action, never run automatically: the caller
// (connector.Service.PurgeAndDelete) is invoked one connector at a time,
// through an admin-gated HTTP endpoint, after a human has confirmed the
// account is actually gone — never inferred from staleness alone.
//
// Counts before deleting because ClickHouse's ALTER TABLE ... DELETE is an
// asynchronous mutation with no synchronous affected-row count; the count
// reflects how many assets existed a moment ago, which is what the caller
// needs to report, not a guess at how many the mutation will eventually touch.
func (r *CHRepo) PurgeAccount(ctx context.Context, provider, accountID string) (int, error) {
	if provider == "" || accountID == "" {
		return 0, fmt.Errorf("PurgeAccount: provider and accountID are required")
	}
	qCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var count uint64
	if err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		if rows.Next() {
			return rows.Scan(&count)
		}
		return nil
	}, purgeAccountCount, provider, accountID); err != nil {
		return 0, fmt.Errorf("PurgeAccount: count: %w", err)
	}
	if count == 0 {
		return 0, nil
	}

	execCtx, execCancel := context.WithTimeout(ctx, assetWriteBudget)
	defer execCancel()
	if err := r.ch.Exec(execCtx, purgeAccountDelete, provider, accountID); err != nil {
		return 0, fmt.Errorf("PurgeAccount: delete: %w", err)
	}
	return int(count), nil
}

// AssetIDsByAccount returns every asset ID for one provider+account, unbounded
// — the id list PurgeAccount's caller needs to resolve findings BEFORE the
// assets themselves are deleted (asset.Service.PurgeAccount only returns a
// count, since ALTER TABLE ... DELETE never touches individual rows in Go).
//
// GROUP BY id, not FINAL: FINAL disables skip-index use on a filtered lookup
// and forces a full-table scan (see CLAUDE.md). id is invariant across
// versions of a row, so grouping by it is just a dedup, not a real
// aggregation choice.
func (r *CHRepo) AssetIDsByAccount(ctx context.Context, provider, accountID string) ([]string, error) {
	if provider == "" || accountID == "" {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var ids []string
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}, assetIDsByAccount, provider, accountID)
	if err != nil {
		return nil, fmt.Errorf("AssetIDsByAccount: %w", err)
	}
	return ids, nil
}

// PurgeEdgesForAssets hard-deletes every graph_edges row that touches any of
// the given asset IDs, on either end (src_id or dst_id).
//
// PurgeAccount only ever deleted the assets table, and graph_edges rows are
// never deleted anywhere else in the codebase either — only re-stamped on
// each sync. An account whose connector is gone will never sync again, so
// nothing will ever re-stamp its edges; they simply sit in ClickHouse for the
// full edge TTL, presenting phantom attack paths (secret access, role
// assumption, security-group adjacency, internet exposure) for an account a
// human explicitly confirmed was gone. This method exists to remove them too.
//
// ids should be the account's asset ID list fetched BEFORE PurgeAccount runs
// — by the time assets are gone there is no other way to know which edges
// were theirs.
//
// Counted entirely BEFORE any deletion starts, not interleaved chunk-by-chunk
// with the deletes below: ClickHouse's ALTER TABLE ... DELETE is an async
// mutation with no synchronous completion guarantee, so counting after an
// earlier chunk's delete has been issued can double-count an edge whose two
// endpoints land in different chunks. The count queries are chunked the same
// as the deletes (same max_query_size risk as an unchunked DELETE), and their
// results are deduped by (src_id, dst_id, edge_type) in a Go set rather than
// summed, for the same cross-chunk-double-count reason.
func (r *CHRepo) PurgeEdgesForAssets(ctx context.Context, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	type edgeKey struct{ src, dst, edgeType string }
	seen := make(map[edgeKey]struct{})
	qCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	for start := 0; start < len(ids); start += purgeEdgeChunk {
		end := min(start+purgeEdgeChunk, len(ids))
		placeholders, args := dbutil.CHIn(ids[start:end])
		countArgs := append(append([]any{}, args...), args...)
		err := r.ch.Select(qCtx, func(rows driver.Rows) error {
			for rows.Next() {
				var k edgeKey
				if err := rows.Scan(&k.src, &k.dst, &k.edgeType); err != nil {
					return fmt.Errorf("scan: %w", err)
				}
				seen[k] = struct{}{}
			}
			return nil
		}, fmt.Sprintf(`SELECT src_id, dst_id, edge_type FROM graph_edges
			WHERE src_id IN (%s) OR dst_id IN (%s)
			GROUP BY src_id, dst_id, edge_type`, placeholders, placeholders), countArgs...)
		if err != nil {
			cancel()
			return 0, fmt.Errorf("PurgeEdgesForAssets: count: %w", err)
		}
	}
	cancel()
	count := uint64(len(seen))
	if count == 0 {
		return 0, nil
	}

	for start := 0; start < len(ids); start += purgeEdgeChunk {
		end := min(start+purgeEdgeChunk, len(ids))
		chunk := ids[start:end]
		placeholders, args := dbutil.CHIn(chunk)
		// Both src_id and dst_id get their own IN list — an edge only needs one
		// endpoint in this account to be this account's dangling topology.
		deleteArgs := append(append([]any{}, args...), args...)

		execCtx, execCancel := context.WithTimeout(ctx, assetWriteBudget)
		err := r.ch.Exec(execCtx,
			fmt.Sprintf(`ALTER TABLE graph_edges DELETE WHERE src_id IN (%s) OR dst_id IN (%s)`, placeholders, placeholders),
			deleteArgs...)
		execCancel()
		if err != nil {
			return int(count), fmt.Errorf("PurgeEdgesForAssets: delete: %w", err)
		}
	}
	return int(count), nil
}
