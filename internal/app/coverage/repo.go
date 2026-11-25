package coverage

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// AssetFreshness is the window inside which a collected asset counts as still
// existing, anchored to high_water (each provider's own most recent
// last_seen, computed by the window function in the subquery below) — never
// now(), the same fail-safe reasoning asset.ProviderStaleness anchors on
// (see that file's doc): a collector outage must read as "this provider's
// data is stale" (the staleness gauge's job), not as "every one of this
// provider's assets quietly aged out of the coverage report" against a wall
// clock the collector has no control over. A now() anchor with the SAME 10-day
// margin asset.ProviderStaleness uses would hide the divergence: the two
// anchors agree exactly when a provider's collector is healthy, and disagree
// in exactly the scenario (an outage) either one exists to catch.
const AssetFreshness = "last_seen > high_water - INTERVAL 10 DAY"

// queryTimeout bounds each measurement. These are full-table group-bys run once
// by a CLI, not request-path queries — generous, but never unbounded, so a
// pathological scan cannot hold a chMaxConcurrent slot forever.
const queryTimeout = 5 * time.Minute

// maxExecutionSeconds is the server-side ceiling. A Go context deadline only
// cancels the client wait; this stops ClickHouse itself.
const maxExecutionSeconds = 300

// Every count below dedups with argMax … GROUP BY, never FINAL: assets and
// findings by argMax(col, synced_at) per id, finding_enrichment by
// argMax(col, enriched_at) per id, and graph_edges per (src_id, edge_type,
// dst_id) with max(synced_at). namedQueries in repo_test.go lists every query
// here, and the tests over it hold both rules.

// qFreshAssetsByType counts deduped, still-fresh assets per provider and type.
// high_water is computed in the same pass as the dedup (one full-table read),
// per provider — see AssetFreshness's doc for why never now().
const qFreshAssetsByType = `
SELECT provider, type, count() AS n
FROM (
    SELECT provider, type, last_seen,
           max(last_seen) OVER (PARTITION BY provider) AS high_water
    FROM (
        SELECT id,
               argMax(provider, synced_at)  AS provider,
               argMax(type, synced_at)      AS type,
               argMax(last_seen, synced_at) AS last_seen
        FROM assets
        GROUP BY id
    )
)
WHERE ` + AssetFreshness + `
GROUP BY provider, type`

// qFreshAssetMetadataKeys counts, per provider and type, how many fresh assets
// carry each metadata key. One measurement serves both the evidence axis (is a
// check's RequiredKey present?) and the check axis (does any check read this
// key?), so the two can never be computed from different populations.
const qFreshAssetMetadataKeys = `
SELECT provider, type, mkey, count() AS n
FROM (
    SELECT provider, type, metadata, last_seen,
           max(last_seen) OVER (PARTITION BY provider) AS high_water
    FROM (
        SELECT id,
               argMax(provider, synced_at)  AS provider,
               argMax(type, synced_at)      AS type,
               argMax(metadata, synced_at)  AS metadata,
               argMax(last_seen, synced_at) AS last_seen
        FROM assets
        GROUP BY id
    )
)
ARRAY JOIN JSONExtractKeys(metadata) AS mkey
WHERE ` + AssetFreshness + `
GROUP BY provider, type, mkey`

// qOpenFindingBands is the per-category open count and band split. Open is
// resolved_at = toDateTime(0), the platform's own definition.
//
// blank_n and routine_n are two different questions and both are needed.
// blank_n means only "no verdict at all" (never enriched, or an enrichment that
// failed open), and routine_n carries the "weighed, nothing urgent" verdict.
// Keeping only blank_n would leave the covered-category rule advising a product
// decision about what is really an enrich backlog.
//
// must_fix_class/score_band come from finding_enrichment
// via a LEFT JOIN, unscoped (no id/resource_id restriction) — unlike
// finding.RiskByResource, this is intentional here: this whole file's queries
// are, by its own top-of-file doc comment, "full-table group-bys run once by
// a CLI, not request-path queries", so an unconditional aggregation of
// finding_enrichment matches the file's design.
const qOpenFindingBands = `
SELECT source, type,
       count()                              AS open_n,
       countIf(must_fix_class = '')         AS blank_n,
       countIf(must_fix_class = 'routine')  AS routine_n,
       countIf(score_band = ?)              AS page_n,
       countIf(score_band = ?)              AS high_n
FROM (
    SELECT id,
           argMax(source, synced_at)      AS source,
           argMax(type, synced_at)        AS type,
           argMax(resolved_at, synced_at) AS resolved_at
    FROM findings
    GROUP BY id
) legacy
LEFT JOIN (
    SELECT id,
        argMax(must_fix_class, enriched_at) AS must_fix_class,
        argMax(score_band, enriched_at)     AS score_band
    FROM finding_enrichment GROUP BY id
) fe ON legacy.id = fe.id
WHERE resolved_at = toDateTime(0)
GROUP BY source, type`

// qOpenFindingResourceTypes is which resource types carry each category's open
// findings — the join that lets a finding category be tested against the asset,
// evidence and edge measurements.
const qOpenFindingResourceTypes = `
SELECT source, type, resource_type, count() AS open_n
FROM (
    SELECT id,
           argMax(source, synced_at)        AS source,
           argMax(type, synced_at)          AS type,
           argMax(resource_type, synced_at) AS resource_type,
           argMax(resolved_at, synced_at)   AS resolved_at
    FROM findings
    GROUP BY id
)
WHERE resolved_at = toDateTime(0) AND resource_type != ''
GROUP BY source, type, resource_type`

// qFindingSourceLiveness is per-source volume and the last time the source
// produced anything. A declared source with no row here has never fired.
const qFindingSourceLiveness = `
SELECT source,
       count()                                     AS total_n,
       countIf(resolved_at = toDateTime(0))        AS open_n,
       max(detected_at)                            AS last_detected
FROM (
    SELECT id,
           argMax(source, synced_at)      AS source,
           argMax(detected_at, synced_at) AS detected_at,
           argMax(resolved_at, synced_at) AS resolved_at
    FROM findings
    GROUP BY id
)
GROUP BY source`

// qOpenFindingsByCheck attributes open findings to the check that emitted them.
const qOpenFindingsByCheck = `
SELECT check_id, count() AS open_n
FROM (
    SELECT id,
           argMax(check_id, synced_at)    AS check_id,
           argMax(resolved_at, synced_at) AS resolved_at
    FROM findings
    GROUP BY id
)
WHERE resolved_at = toDateTime(0) AND check_id != ''
GROUP BY check_id`

// qOpenFindingChecksByCategory is which check_ids produced each category's open
// findings. Without it the evidence axis reached for any check sharing a
// resource type with the category, which put "the collector must emit
// branch_protection" under `iac_terraform / unreadable_tf_state`.
const qOpenFindingChecksByCategory = `
SELECT source, type, check_id, count() AS open_n
FROM (
    SELECT id,
           argMax(source, synced_at)      AS source,
           argMax(type, synced_at)        AS type,
           argMax(check_id, synced_at)    AS check_id,
           argMax(resolved_at, synced_at) AS resolved_at
    FROM findings
    GROUP BY id
)
WHERE resolved_at = toDateTime(0) AND check_id != ''
GROUP BY source, type, check_id`

// qFreshEdgesBySrc and qFreshEdgesByDst are the deduped, fresh edge volumes per
// endpoint type. graph_edges is never deleted, only re-stamped, so every reader
// applies graphschema.EdgeFreshnessCond — without it this document
// would report topology that no longer exists.
// The dedup aggregate is projected through a middle SELECT that renames
// last_sync to synced_at. Applying the freshness condition directly to
// `max(synced_at) AS synced_at` is rejected by ClickHouse — the alias shadows
// the column and the predicate is pushed back inside the aggregation
// (ILLEGAL_AGGREGATION, code 184). Renaming instead of inlining a different condition keeps
// EdgeFreshnessCond as the single source of truth.
var qFreshEdgesBySrc = `
SELECT edge_type, src_type, count() AS rows_n, uniqExact(src_id) AS distinct_n
FROM (
    SELECT src_id, edge_type, src_type, last_sync AS synced_at
    FROM (
        SELECT src_id, edge_type, dst_id,
               argMax(src_type, synced_at) AS src_type,
               max(synced_at)              AS last_sync
        FROM graph_edges
        GROUP BY src_id, edge_type, dst_id
    )
)
WHERE ` + graphschema.EdgeFreshnessCond + `
GROUP BY edge_type, src_type`

var qFreshEdgesByDst = `
SELECT edge_type, dst_type, count() AS rows_n, uniqExact(dst_id) AS distinct_n
FROM (
    SELECT dst_id, edge_type, dst_type, last_sync AS synced_at
    FROM (
        SELECT src_id, edge_type, dst_id,
               argMax(dst_type, synced_at) AS dst_type,
               max(synced_at)              AS last_sync
        FROM graph_edges
        GROUP BY src_id, edge_type, dst_id
    )
)
WHERE ` + graphschema.EdgeFreshnessCond + `
GROUP BY edge_type, dst_type`

// qFreshAssetMetaValues splits fresh assets of the given types by one metadata
// key's value — the known-ness stamps (package_inventory) a lineage stage reads.
// The deduped type is aliased cur_type, not type: an alias named like the column
// shadows it in the pre-aggregation WHERE (ILLEGAL_AGGREGATION, code 184).
// The type filter is applied before the dedup GROUP BY so the aggregation holds
// only these types' rows (a VM never changes type), and again after it in case
// one did. high_water is therefore each provider's newest VM, not newest asset:
// the same anchor, measured on the population being counted.
const qFreshAssetMetaValues = `
SELECT cur_type, JSONExtractString(metadata, ?) AS v, count() AS n
FROM (
    SELECT cur_type, metadata, last_seen,
           max(last_seen) OVER (PARTITION BY provider) AS high_water
    FROM (
        SELECT id,
               argMax(provider, synced_at)  AS provider,
               argMax(type, synced_at)      AS cur_type,
               argMax(metadata, synced_at)  AS metadata,
               argMax(last_seen, synced_at) AS last_seen
        FROM assets
        WHERE type IN (%[1]s)
        GROUP BY id
    )
)
WHERE ` + AssetFreshness + ` AND cur_type IN (%[1]s)
GROUP BY cur_type, v`

// Repo reads the live measurements from ClickHouse. It decides nothing: every
// threshold, rule and axis assignment lives in service.go.
type Repo struct {
	ch *db.CH
}

// NewRepo returns a Repo over an open ClickHouse client.
func NewRepo(ch *db.CH) *Repo { return &Repo{ch: ch} }

// Facts runs every measurement. A single failing query is recorded in
// LiveFacts.QueryErrors rather than aborting the run: a document missing one
// section beats no document, and the reader is told which section is missing.
func (r *Repo) Facts(ctx context.Context) (LiveFacts, error) {
	f := LiveFacts{MeasuredAt: time.Now().UTC(), CheckOpen: map[string]uint64{}, EdgeTotals: map[string]uint64{}}

	steps := []struct {
		name string
		run  func(context.Context, *LiveFacts) error
	}{
		{"fresh assets", r.assets},
		{"asset metadata keys", r.keys},
		{"finding bands", r.bands},
		{"finding resource types", r.resources},
		{"source liveness", r.sources},
		{"open findings by check", r.checkOpen},
		{"open findings by category and check", r.categoryChecks},
		{"fresh edges", r.edges},
		{stepMetaValues, r.metaValues},
	}
	for _, s := range steps {
		if err := s.run(ctx, &f); err != nil {
			f.Failed = append(f.Failed, s.name)
			f.QueryErrors = append(f.QueryErrors, fmt.Sprintf("%s: %v", s.name, err))
		}
	}
	if len(f.QueryErrors) == len(steps) {
		return f, fmt.Errorf("Facts: every measurement failed: %v", f.QueryErrors)
	}
	return f, nil
}

// query wraps one measurement in its own deadline and server-side execution
// cap, per CLAUDE.md.
func (r *Repo) query(ctx context.Context, scan func(driver.Rows) error, q string, args ...any) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	ctx = r.ch.WithQuerySettings(ctx, map[string]any{"max_execution_time": maxExecutionSeconds})
	return r.ch.Select(ctx, scan, q, args...)
}

func (r *Repo) assets(ctx context.Context, f *LiveFacts) error {
	err := r.query(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var t TypeCount
			var n uint64
			if err := rows.Scan(&t.Provider, &t.AssetType, &n); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			t.Count = n
			f.Assets = append(f.Assets, t)
		}
		return rows.Err()
	}, qFreshAssetsByType)
	if err != nil {
		return fmt.Errorf("assets: %w", err)
	}
	return nil
}

func (r *Repo) keys(ctx context.Context, f *LiveFacts) error {
	err := r.query(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var k KeyPresence
			if err := rows.Scan(&k.Provider, &k.AssetType, &k.Key, &k.Assets); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			f.Keys = append(f.Keys, k)
		}
		return rows.Err()
	}, qFreshAssetMetadataKeys)
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	return nil
}

func (r *Repo) bands(ctx context.Context, f *LiveFacts) error {
	err := r.query(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var b BandSplit
			if err := rows.Scan(&b.Source, &b.Type, &b.Open, &b.Blank, &b.Routine, &b.Page, &b.High); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			f.Bands = append(f.Bands, b)
		}
		return rows.Err()
	}, qOpenFindingBands, string(enrich.BandPage), string(enrich.BandHigh))
	if err != nil {
		return fmt.Errorf("bands: %w", err)
	}
	return nil
}

func (r *Repo) resources(ctx context.Context, f *LiveFacts) error {
	err := r.query(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var rc ResourceTypeCount
			if err := rows.Scan(&rc.Source, &rc.Type, &rc.ResourceType, &rc.Open); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			f.Resources = append(f.Resources, rc)
		}
		return rows.Err()
	}, qOpenFindingResourceTypes)
	if err != nil {
		return fmt.Errorf("resources: %w", err)
	}
	return nil
}

func (r *Repo) sources(ctx context.Context, f *LiveFacts) error {
	err := r.query(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var s SourceFact
			var last time.Time
			if err := rows.Scan(&s.Source, &s.Total, &s.Open, &last); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			if last.Unix() > 0 {
				s.LastDetected = last.UTC()
			}
			f.Sources = append(f.Sources, s)
		}
		return rows.Err()
	}, qFindingSourceLiveness)
	if err != nil {
		return fmt.Errorf("sources: %w", err)
	}
	return nil
}

func (r *Repo) checkOpen(ctx context.Context, f *LiveFacts) error {
	err := r.query(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			var n uint64
			if err := rows.Scan(&id, &n); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			f.CheckOpen[id] = n
		}
		return rows.Err()
	}, qOpenFindingsByCheck)
	if err != nil {
		return fmt.Errorf("checkOpen: %w", err)
	}
	return nil
}

func (r *Repo) categoryChecks(ctx context.Context, f *LiveFacts) error {
	err := r.query(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var cc CategoryCheck
			if err := rows.Scan(&cc.Source, &cc.Type, &cc.CheckID, &cc.Open); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			f.CategoryChecks = append(f.CategoryChecks, cc)
		}
		return rows.Err()
	}, qOpenFindingChecksByCategory)
	if err != nil {
		return fmt.Errorf("categoryChecks: %w", err)
	}
	return nil
}

func (r *Repo) edges(ctx context.Context, f *LiveFacts) error {
	scan := func(into *[]EdgeEndpointCount) func(driver.Rows) error {
		return func(rows driver.Rows) error {
			for rows.Next() {
				var e EdgeEndpointCount
				if err := rows.Scan(&e.EdgeType, &e.EndpointType, &e.Rows, &e.Distinct); err != nil {
					return fmt.Errorf("scan: %w", err)
				}
				*into = append(*into, e)
			}
			return rows.Err()
		}
	}
	if err := r.query(ctx, scan(&f.EdgesBySrc), qFreshEdgesBySrc); err != nil {
		return fmt.Errorf("edges by src: %w", err)
	}
	for _, e := range f.EdgesBySrc {
		f.EdgeTotals[e.EdgeType] += e.Rows
	}
	if err := r.query(ctx, scan(&f.EdgesByDst), qFreshEdgesByDst); err != nil {
		return fmt.Errorf("edges by dst: %w", err)
	}
	return nil
}

// metaValues measures every metadata split (metaMeasures) over its types.
func (r *Repo) metaValues(ctx context.Context, f *LiveFacts) error {
	for _, st := range metaMeasures() {
		placeholders, typeArgs := dbutil.CHIn(st.Types)
		args := append(append([]any{st.Key}, typeArgs...), typeArgs...)
		err := r.query(ctx, func(rows driver.Rows) error {
			for rows.Next() {
				mv := MetaValueCount{Key: st.Key}
				if err := rows.Scan(&mv.AssetType, &mv.Value, &mv.Count); err != nil {
					return fmt.Errorf("scan: %w", err)
				}
				f.MetaValues = append(f.MetaValues, mv)
			}
			return rows.Err()
		}, fmt.Sprintf(qFreshAssetMetaValues, placeholders), args...)
		if err != nil {
			return fmt.Errorf("metaValues %s: %w", st.Key, err)
		}
	}
	return nil
}
