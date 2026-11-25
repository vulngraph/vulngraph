package asset

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// This file is a size split of repo.go (CLAUDE.md's 800-line cap), not a new
// layer — it is still the repo.go role (storage adapters, the only place that
// may query ClickHouse for this domain) and stays subject to the same rules:
// query strings are package-level consts named for what they fetch, per-query
// context.WithTimeout, FINAL only for full-table aggregate reads.

// structurallyStaleTypes are asset types whose rows are RETAINED long after
// the real resource stops existing, by design elsewhere in this codebase —
// so a high staleness fraction for these means "the resource churned or
// terminated and we correctly kept its history", not "the collector stopped
// running". Mixing them into assetStalenessByProvider's ratio makes a
// healthy collector look broken.
//
//   - EphemeralTypes (k8s_pod, container, k8s_job): churn constantly and are
//     never deleted — see optimize.go.
//   - ec2_instance / gce_instance: terminated/preemptible instances are
//     retained by design (an ec2_instance carve-out; gce_instance is
//     the same shape on GCP, not yet documented there but identical in kind).
var structurallyStaleTypes = append(append([]string{}, EphemeralTypes...), "ec2_instance", "gce_instance")

// assetStalenessByProvider aggregates, per provider, how many assets there are
// and how many have been seen within the staleness margin of THAT PROVIDER'S
// OWN high-water mark (same fail-safe reasoning as providerHighWater — never
// wall-clock, or a collector outage would look like mass deletion); the stale
// count is the difference. structurallyStaleTypes is excluded — see that var's
// doc — so the ratio answers "is the collector still running", not "how much
// history has this provider retained by design".
//
// Assets are counted by distinct id, never by row: `assets` is ORDER BY
// (type, id), so an asset whose type changed keeps a second row whose
// last_seen is frozen. Counting the ids seen recently, instead of the rows that
// are stale, keeps that frozen row out of the stale count. inventoryReadCond
// keeps IaC declarations out of both counts; its liveness half drops only
// ephemeral types, which structurallyStaleTypes already excludes, so it hides
// no stale row this query measures.
//
// The window function computes the per-provider high water in the same pass
// as the row scan, so this stays a single full-table read; FINAL is the
// documented exemption for a full-table aggregate (not a filtered lookup).
var assetStalenessByProvider = `
		SELECT provider, uniqExact(id) AS total,
		       uniqExactIf(id, last_seen >= high_water - INTERVAL ? SECOND) AS fresh
		FROM (
			SELECT provider, id, last_seen,
			       max(last_seen) OVER (PARTITION BY provider) AS high_water
			FROM assets FINAL
			WHERE type NOT IN (%s) AND ` + inventoryReadCond + `
		)
		GROUP BY provider`

const (
	// assetProviderDimensions counts, per provider, the distinct region and
	// account_id values seen in current assets — the observable half of an
	// "expected vs configured connectors" check (the other half, enabled
	// connector counts, lives in the connector domain and is joined at the obs
	// Sources callback, not here). uniqExactIf skips the empty string a
	// provider without that dimension always reports, plus two known
	// non-connector artifacts that would otherwise inflate the count: package
	// rows carry the literal string "global" as a region placeholder (not a
	// real per-connector region), and aws_scp_set is a one-row-per-member-account
	// org-enumeration artifact, not a connector's own account.
	assetProviderDimensions = `
		SELECT provider,
		       uniqExactIf(region, region != '' AND type != 'package') AS regions,
		       uniqExactIf(account_id, account_id != '' AND type != 'aws_scp_set') AS accounts
		FROM assets FINAL
		GROUP BY provider`
)

// ProviderStaleness is one provider's asset count and how many have fallen
// stale relative to that provider's OWN high-water mark (see the
// assetStalenessByProvider query doc for why never wall-clock).
type ProviderStaleness struct {
	Provider string
	Total    int
	Stale    int
}

// ProviderStaleness reports, per provider, total assets and how many haven't
// had a last_seen within marginSeconds of that provider's own most recent
// collection. Feeds the obs asset-staleness gauges (dangling-sweep
// observability) — the same anchoring discipline as ProviderHighWater, so an
// outage of every collector for a provider freezes the mark rather than
// marking the whole estate stale. One connector's outage among several of the
// same provider does show its assets as stale: the others keep the mark moving.
func (r *CHRepo) ProviderStaleness(ctx context.Context, marginSeconds int) ([]ProviderStaleness, error) {
	qCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	placeholders, typeArgs := dbutil.CHIn(structurallyStaleTypes)
	query := fmt.Sprintf(assetStalenessByProvider, placeholders)
	// Positional args follow the query TEXT order: marginSeconds' ? comes
	// before the WHERE clause's %s-expanded type list.
	args := append([]any{marginSeconds}, typeArgs...)

	var out []ProviderStaleness
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				provider     string
				total, fresh uint64
			)
			if err := rows.Scan(&provider, &total, &fresh); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, ProviderStaleness{Provider: provider, Total: int(total), Stale: int(total - fresh)})
		}
		return rows.Err()
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ProviderStaleness: %w", err)
	}
	return out, nil
}

// ProviderDimensions is one provider's distinct region/account_id cardinality
// — the dimension counts the connector coverage-gap check compares against
// configured connector counts (see internal/obs ConnectorCoverageStat).
type ProviderDimensions struct {
	Provider string
	Regions  int
	Accounts int
}

// ProviderDimensionCounts returns, per provider, the distinct region and
// account_id values seen across current assets.
func (r *CHRepo) ProviderDimensionCounts(ctx context.Context) ([]ProviderDimensions, error) {
	qCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var out []ProviderDimensions
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				provider          string
				regions, accounts uint64
			)
			if err := rows.Scan(&provider, &regions, &accounts); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, ProviderDimensions{Provider: provider, Regions: int(regions), Accounts: int(accounts)})
		}
		return rows.Err()
	}, assetProviderDimensions)
	if err != nil {
		return nil, fmt.Errorf("ProviderDimensionCounts: %w", err)
	}
	return out, nil
}

// scopeStalenessByRegionType is the population read behind the deletion
// decision: per (region, type) for ONE connector, how many asset rows
// exist, how many this sweep did not re-observe, and how many have been
// unobserved for longer than the confirmation window.
//
// It reads deliberately NON-live rows — that is the entire measurement — so it
// is exempt from the liveness gate rather than in breach of it.
//
// Three properties matter and none is incidental:
//
//   - The connector filter is metadata.prov_connector_id, stamped by
//     jobs.stampProvenance. Attributing a stored row to a connector by guessing
//     from account_id or region would be a guess, and this is the one query
//     whose wrong answer would be a deletion.
//   - Absence is read from last_seen, not from a set difference against the
//     collected ids. Sync re-stamps last_seen for EVERY collected asset
//     (restampLastSeen), so the diff is a comparison of two timestamps instead
//     of a set intersection, and it needs no ids over the wire.
//   - GROUP BY (type, id), never GROUP BY (provider, type, id): `assets` is
//     ORDER BY (type, id) — `provider` is not part of the row's identity,
//     so grouping by a three-column tuple would silently manufacture a fork
//     (a package discovered under two providers would count as two rows). `type` stays in the GROUP BY because it is this
//     query's own output dimension (`t`), not because it is load-bearing for
//     dedupe. Filtered lookup, so argMax rather than FINAL (CLAUDE.md).
const scopeStalenessByRegionType = `
	SELECT reg, t, count() AS stored,
	       countIf(ls < ?) AS absent,
	       countIf(ls < ?) AS confirmed
	FROM (
		SELECT id, type AS t, argMax(region, synced_at) AS reg, max(last_seen) AS ls
		FROM assets
		WHERE type IN (%s)
		  AND JSONExtractString(metadata, 'prov_connector_id') = ?
		GROUP BY t, id
	)
	GROUP BY reg, t`

// ScopeStaleness is one (region, type) population for a single connector.
// Region is whatever the stored rows carry, which for some types is an
// availability zone rather than a region — the caller decides whether that can
// be attributed to a scope, this only reports it.
type ScopeStaleness struct {
	Region    string
	Type      string
	Stored    int
	Absent    int
	Confirmed int
}

// ScopeStaleness reports, for one connector and one set of asset types, the
// stored population per (region, type) split by how far behind this sweep each
// row's last_seen sits. absentBefore is this sweep's cutoff (rows not
// re-observed by it) and confirmedBefore the older confirmation cutoff.
//
// Types must be a bounded, audited list (forget.EnforceableTypes) — this is not
// a general inventory read and must never be given the whole type vocabulary.
func (r *CHRepo) ScopeStaleness(ctx context.Context, connectorID string, types []string, absentBefore, confirmedBefore time.Time) ([]ScopeStaleness, error) {
	if connectorID == "" || len(types) == 0 {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	placeholders, typeArgs := dbutil.CHIn(types)
	query := fmt.Sprintf(scopeStalenessByRegionType, placeholders)
	// Positional args follow the query TEXT order: the two countIf cutoffs come
	// before the subquery's type list and connector id.
	args := []any{absentBefore, confirmedBefore}
	args = append(args, typeArgs...)
	args = append(args, connectorID)

	var out []ScopeStaleness
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				region, assetType         string
				stored, absent, confirmed uint64
			)
			if err := rows.Scan(&region, &assetType, &stored, &absent, &confirmed); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, ScopeStaleness{
				Region: region, Type: assetType,
				Stored: int(stored), Absent: int(absent), Confirmed: int(confirmed),
			})
		}
		return rows.Err()
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ScopeStaleness: %w", err)
	}
	return out, nil
}

// scopeCandidateIDs lists the confirmed-absent ids of ONE (type, region) for a
// connector — the ids a tombstone would name. Same non-live-by-design read as
// scopeStalenessByRegionType and exempt for the same reason.
//
// GROUP BY id, never GROUP BY (provider, type, id): `assets` is ORDER BY
// (type, id) — `provider` is not part of the row's identity, and `type`
// is already pinned to a single value by the WHERE clause above, so neither
// belongs in the GROUP BY. This is the one query whose wrong answer is a
// deletion (the forget mechanism): grouping on that tuple would manufacture
// a fork — a provider-changed asset would surface as two "confirmed absent"
// ids instead of one, tombstoning a resource still present under its other
// provider. See TestCHRepo_ScopeCandidateIDsNoForkOnProviderChange.
//
// The region predicate is applied by the caller through the `%s` slot so that a
// non-region-scoped family (GCP's aggregatedList covers every zone) passes an
// empty condition rather than a wildcard match. Ordered and limited so a
// caller's bound is honoured deterministically rather than by whatever the
// scan happened to return first.
const scopeCandidateIDs = `
	SELECT id, ls FROM (
		SELECT id, argMax(region, synced_at) AS reg, max(last_seen) AS ls
		FROM assets
		WHERE type = ?
		  AND JSONExtractString(metadata, 'prov_connector_id') = ?
		GROUP BY id
	)
	WHERE ls < ? %s
	ORDER BY ls, id
	LIMIT ?`

// ForgetCandidate is one confirmed-absent asset id and the last time anything
// observed it.
type ForgetCandidate struct {
	ID       string
	LastSeen time.Time
}

// ScopeCandidateIDs returns up to limit confirmed-absent ids for one connector,
// asset type and (optionally) region. region == "" means every region, which is
// only correct for a family whose enumeration genuinely covers all of them.
func (r *CHRepo) ScopeCandidateIDs(ctx context.Context, connectorID, assetType, region string, confirmedBefore time.Time, limit int) ([]ForgetCandidate, error) {
	if connectorID == "" || assetType == "" || limit <= 0 {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	regionCond := ""
	args := []any{assetType, connectorID, confirmedBefore}
	if region != "" {
		regionCond = "AND reg = ?"
		args = append(args, region)
	}
	args = append(args, limit)

	var out []ForgetCandidate
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var c ForgetCandidate
			if err := rows.Scan(&c.ID, &c.LastSeen); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, c)
		}
		return rows.Err()
	}, fmt.Sprintf(scopeCandidateIDs, regionCond), args...)
	if err != nil {
		return nil, fmt.Errorf("ScopeCandidateIDs: %w", err)
	}
	return out, nil
}
