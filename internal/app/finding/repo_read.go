package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// findingEnrichmentJoinCols is the LEFT JOIN subquery's column list shared by
// selectFindingsArgMax and selectFindingByID: each of the ten enrich:"output"
// columns via argMax(col, enriched_at), plus the version column itself
// aliased enr_at (never enriched_at — see selectFindingByID's comment for
// why that alias choice is load-bearing, not cosmetic).
const findingEnrichmentJoinCols = `
			argMax(score, enriched_at)           AS score,
			argMax(score_band, enriched_at)      AS score_band,
			argMax(known_exploited, enriched_at) AS known_exploited,
			argMax(dependents, enriched_at)       AS dependents,
			argMax(unused, enriched_at)           AS unused,
			argMax(safety_class, enriched_at)     AS safety_class,
			argMax(fix_target, enriched_at)       AS fix_target,
			argMax(must_fix_class, enriched_at)   AS must_fix_class,
			argMax(must_fix_reason, enriched_at)  AS must_fix_reason,
			argMax(owner_team, enriched_at)       AS owner_team,
			argMax(owner_source, enriched_at)     AS owner_source,
			argMax(owner_confidence, enriched_at) AS owner_confidence,
			argMax(environment, enriched_at)      AS environment,
			max(enriched_at)                      AS enr_at`

// findingEnrichmentGroupBy is the GROUP BY suffix every selectFindingsArgMax/
// selectFindingByID caller must append: fe is already grouped 1:1 by id
// inside its own subquery, so grouping by these again is a no-op
// aggregation-wise, but ClickHouse's checker requires every bare-selected
// non-aggregate column (all of fe.*, alongside f.id) to appear here.
const findingEnrichmentGroupBy = "f.id, fe.score, fe.score_band, fe.enr_at, fe.known_exploited, " +
	"fe.dependents, fe.unused, fe.safety_class, fe.fix_target, fe.must_fix_class, fe.must_fix_reason, " +
	"fe.owner_team, fe.owner_source, fe.owner_confidence, fe.environment"

const (
	// selectFindingsArgMax is the shared non-FINAL read form: argMax(col,
	// synced_at) GROUP BY id collapses ReplacingMergeTree versions per id —
	// identical to a FINAL read's result but without FINAL's whole-table merge
	// (mirrors selectFindingByID; skip indexes don't apply under FINAL, so a
	// filtered FINAL would full-scan the table instead of pruning to the
	// matching granules). Each caller splits its filters two ways: a
	// pre-aggregation WHERE for columns baked into the finding's deterministic
	// ID (source, resource_id, check_id, id itself) that cannot differ across
	// versions of the same id, and a post-aggregation HAVING (referencing these
	// SELECT aliases) for every enrichment/lifecycle column that can: score,
	// severity, enriched_at, safety_class, must_fix_class, resolved_at and
	// detected_at all change on re-enrich/re-observe. source/resource_id/
	// check_id are deliberately left unaliased (bare argMax(...), no "AS"):
	// ClickHouse resolves a bare identifier against a SELECT-list alias of the
	// same name even inside WHERE, so aliasing them would make a
	// pre-aggregation `resource_id = ?` predicate resolve to the aggregate
	// expression instead of the raw column and fail with "Aggregate function
	// ... is found in WHERE".
	//
	// Mirrors selectFindingByID's flip to finding_enrichment (see its comment
	// for the aliasing/GROUP BY rationale, unrepeated here). Unlike
	// selectFindingByID, this is a %s-templated prefix — ByIDs and
	// ByResourceIDs scope fe's subquery differently (an id list vs a
	// resource_id-derived id list), so each caller supplies its own predicate,
	// same pattern as costAtRiskFrom's two %s sites. Every caller's outer
	// WHERE + GROUP BY must add findingEnrichmentGroupBy.
	selectFindingsArgMax = `SELECT f.id,
		argMax(f.source, f.synced_at), argMax(f.type, f.synced_at) AS type,
		argMax(f.severity, f.synced_at) AS severity, argMax(f.title, f.synced_at) AS title,
		argMax(f.description, f.synced_at) AS description, argMax(f.resource_type, f.synced_at) AS resource_type,
		argMax(f.resource_id, f.synced_at), argMax(f.resource_name, f.synced_at) AS resource_name,
		argMax(f.region, f.synced_at) AS region, argMax(f.check_id, f.synced_at),
		argMax(f.remediation, f.synced_at) AS remediation, argMax(f.detected_at, f.synced_at) AS detected_at,
		` + firstDetectedAtAgg + ` AS first_detected_at,
		fe.score, fe.score_band, fe.enr_at,
		fe.known_exploited, argMax(f.tags, f.synced_at) AS tags,
		fe.dependents, fe.unused, fe.safety_class,
		fe.fix_target,
		fe.must_fix_class, fe.must_fix_reason,
		argMax(f.last_observed_at, f.synced_at) AS last_observed_at, argMax(f.resolved_at, f.synced_at) AS resolved_at,
		argMax(f.resolution_reason, f.synced_at) AS resolution_reason,
		fe.owner_team, fe.owner_source, fe.owner_confidence, fe.environment
		FROM findings f
		LEFT JOIN (
			SELECT id,` + findingEnrichmentJoinCols + `
			FROM finding_enrichment WHERE %s
			GROUP BY id
		) fe ON fe.id = f.id`

	// selectFindingByID is the point-lookup (single id) form of the same
	// argMax pattern as selectFindingsArgMax. findings is ORDER BY (source,
	// id), so id-only lookups can't use the primary key; the idx_id bloom
	// index prunes to the few granules holding the id instead of a full-table
	// FINAL scan. Column order matches selectFindingsArgMax's scan. This is a
	// hot path (finding.Get runs per enrich job).
	//
	// The ten enrich:"output" columns come from finding_enrichment via a LEFT
	// JOIN scoped to this id (fe's own `WHERE id = ?`) — unscoped would
	// full-scan finding_enrichment on every call. `id` binds TWICE (fe's scope,
	// then the outer WHERE) — costAtRiskArgs' discipline.
	//
	// fe aliases its version column enr_at, not enriched_at: a sibling
	// aggregate here (argMax(score, enriched_at)) bare-references
	// enriched_at as ITS version arg, and aliasing another aggregate
	// enriched_at too triggers ClickHouse's ILLEGAL_AGGREGATION hazard.
	// GROUP BY (findingEnrichmentGroupBy) lists every bare fe.* column beside
	// f.id — a no-op (fe is 1:1-by-id already) ClickHouse's checker requires.
	selectFindingByID = `SELECT f.id,
		argMax(f.source, f.synced_at), argMax(f.type, f.synced_at), argMax(f.severity, f.synced_at),
		argMax(f.title, f.synced_at), argMax(f.description, f.synced_at), argMax(f.resource_type, f.synced_at),
		argMax(f.resource_id, f.synced_at), argMax(f.resource_name, f.synced_at), argMax(f.region, f.synced_at),
		argMax(f.check_id, f.synced_at), argMax(f.remediation, f.synced_at), argMax(f.detected_at, f.synced_at),
		` + firstDetectedAtAgg + `,
		fe.score, fe.score_band, fe.enr_at,
		fe.known_exploited, argMax(f.tags, f.synced_at),
		fe.dependents, fe.unused, fe.safety_class,
		fe.fix_target,
		fe.must_fix_class, fe.must_fix_reason,
		argMax(f.last_observed_at, f.synced_at), argMax(f.resolved_at, f.synced_at),
		argMax(f.resolution_reason, f.synced_at),
		fe.owner_team, fe.owner_source, fe.owner_confidence, fe.environment
		FROM findings f
		LEFT JOIN (
			SELECT id,` + findingEnrichmentJoinCols + `
			FROM finding_enrichment WHERE id = ?
			GROUP BY id
		) fe ON fe.id = f.id
		WHERE f.id = ?
		GROUP BY ` + findingEnrichmentGroupBy

	// byResourceIDsMaxRows is an OOM guard, NOT a result cap. A bare `LIMIT`
	// with no `ORDER BY` over a parallel `GROUP BY` returns an arbitrary
	// subset with no guarantee of ever rotating through the rest, so silently
	// truncating here would silently UNDER-resolve: fixed findings would stay
	// open on the densest resources, and on the one-shot deleted-asset and
	// account-purge paths it would orphan open findings on resources that no
	// longer exist. Hitting this bound is therefore an ERROR (ErrResultTooLarge),
	// not a truncation: the caller skips the batch and leaves its findings
	// open, rather than reasoning about a partial set that looks complete.
	byResourceIDsMaxRows = 50_000
)

// openKeysByConnectorQ selects the open findings of one source last emitted by
// one connector, as narrow keys: id, region and type only. A caller resolves a
// small subset of them and hydrates just those through ByIDs, so carrying the
// wide columns here would build aggregation state for every row of the source
// for nothing (CLAUDE.md: LIMIT bounds a result set, not an aggregation).
//
// source is a pre-aggregation WHERE (it is baked into the deterministic id and
// leads the (source, id) primary key, so it prunes); the connector tag, region,
// type and resolved_at can all differ between versions of one id and are
// filtered only after the argMax collapse. The aliases differ from the column
// names so no aggregate argument resolves to its own alias.
//
// The LIMIT is an OOM guard, not a result cap: OpenKeysByConnector errors past
// it (see openKeysMaxRows).
const openKeysByConnectorQ = `SELECT id, rgn, typ FROM (
	SELECT id,
		argMax(region, synced_at)                                       AS rgn,
		argMax(type, synced_at)                                         AS typ,
		argMax(tags['` + ProvenanceConnectorKey + `'], synced_at) AS conn,
		argMax(resolved_at, synced_at)                                  AS res
	FROM findings
	WHERE source = ?
	GROUP BY id
)
WHERE conn = ? AND res < toDateTime('2000-01-01 00:00:00')
LIMIT ?`

// openKeysMaxRows bounds OpenKeysByConnector's result. Hitting it is an
// ERROR, never a truncation: a lifecycle caller handed an arbitrary subset
// would read the missing keys as "not stored" and act on a partial set that
// looks complete (same rule as byResourceIDsMaxRows).
const openKeysMaxRows = 100_000

// OpenKeysByConnector returns the open findings of source whose latest version
// was emitted by the listing connectorID names (ProvenanceConnectorKey: a
// connector id, or a connector-less feed's scope). Rows that carry no
// provenance tag are never returned — they cannot be
// attributed to a listing, so no listing may close them.
func (r *CHRepo) OpenKeysByConnector(ctx context.Context, source, connectorID string) ([]OpenKey, error) {
	if source == "" || connectorID == "" {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, batchReadTimeout)
	defer cancel()

	var out []OpenKey
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var k OpenKey
			if err := rows.Scan(&k.ID, &k.Region, &k.Type); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, k)
		}
		return rows.Err()
	}, openKeysByConnectorQ, source, connectorID, openKeysMaxRows+1)
	if err != nil {
		return nil, fmt.Errorf("OpenKeysByConnector: %w", err)
	}
	if len(out) > openKeysMaxRows {
		return nil, fmt.Errorf("OpenKeysByConnector: %w: more than %d open %s findings for connector %s",
			ErrResultTooLarge, openKeysMaxRows, source, connectorID)
	}
	return out, nil
}

// ByIDs returns the current rows for the given finding ids. id is the finding's
// deterministic identity key (dbutil.DeterministicID) so it's identical across
// every ReplacingMergeTree version of a row — filtering it pre-aggregation is
// correct, same reasoning as source/resource_id/check_id in List() (see
// selectFindingsArgMax's doc comment) — and it is what keeps the lookup
// cheap: a pre-aggregation `id IN (...)` can use the (source, id) primary key
// and idx_id bloom index,
// which a post-aggregation/FINAL predicate cannot. Service.pinFirstDetectedAt
// (this package's service.go) calls this inside every RecordObserved to fetch
// existing stored versions before overwriting them — it must see each id's
// CURRENT FirstDetectedAt/Severity/KnownExploited, not whatever stale version
// a filtered FINAL scan happened to still have on disk. Missing ids are simply
// absent; order is unspecified. Used by the governor queue to resolve
// decision targets.
//
// The id placeholder list appears TWICE in the query text — fe's own scope
// (`id IN (...)`, textually first) and the outer `WHERE f.id IN (...)` — so
// args bind [ids..., ids...], same discipline as selectFindingByID/
// costAtRiskArgs.
func (r *CHRepo) ByIDs(ctx context.Context, ids []string) ([]Finding, error) {
	batches, err := dbutil.CHStringBatches(ids)
	if err != nil {
		return nil, fmt.Errorf("ByIDs: %w", err)
	}
	var out []Finding
	for _, batch := range batches {
		rows, err := r.byIDsBatch(ctx, batch)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

func (r *CHRepo) byIDsBatch(ctx context.Context, ids []string) ([]Finding, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, batchReadTimeout)
	defer cancel()
	if len(ids) <= 10 {
		qCtx = r.ch.WithQuerySettings(qCtx, map[string]any{"max_threads": 1})
	}

	placeholders, idArgs := dbutil.CHIn(ids)
	args := append(append([]any{}, idArgs...), idArgs...)
	query := fmt.Sprintf(selectFindingsArgMax, "id IN ("+placeholders+")") +
		" WHERE f.id IN (" + placeholders + ") GROUP BY " + findingEnrichmentGroupBy

	var out []Finding
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			fnd, err := scanFinding(rows)
			if err != nil {
				return err
			}
			out = append(out, fnd)
		}
		// rows.Err() is mandatory (CLAUDE.md): without it a mid-stream ClickHouse
		// failure returns partial rows with a nil error — List's hydrate phase would
		// then silently drop the missing ids instead of surfacing the failure.
		return rows.Err()
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ByIDs: %w", err)
	}
	return out, nil
}

// ByResourceIDs returns findings whose resource_id is in the given list.
// resource_id is baked into the finding's deterministic id (dbutil.DeterministicID)
// so, like id itself, it's identical across every version of a row — a
// pre-aggregation `resource_id IN (...)` WHERE is correct and, unlike a
// filtered FINAL, can use the resource_id bloom index instead of a full-table
// scan. Used by the post-correlate invalidation path to find findings on
// assets whose exposure edges changed.
//
// Returns ErrResultTooLarge past byResourceIDsMaxRows — see that const.
//
// fe's subquery is scoped by `id IN (SELECT id FROM findings WHERE
// resource_id IN (...))` — the same nested-subquery scoping pattern
// costAtRiskFrom established, since finding_enrichment carries no
// resource_id column of its own to filter on directly. The resource_id
// placeholder list therefore appears TWICE in the query text (fe's nested
// subquery, then the outer WHERE), binding [ids..., ids...]. This does mean
// findings gets scanned twice for the same resource_id predicate, but both
// scans use the resource_id bloom index, so it's index-probe cost, not a
// full scan. Revisit if byResourceIDsMaxRows batches grow large enough for
// that doubling to matter.
func (r *CHRepo) ByResourceIDs(ctx context.Context, ids []string) ([]Finding, error) {
	batches, err := dbutil.CHStringBatches(ids)
	if err != nil {
		return nil, fmt.Errorf("ByResourceIDs: %w", err)
	}
	var out []Finding
	for _, batch := range batches {
		rows, err := r.byResourceIDsBatch(ctx, batch)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
		if len(out) > byResourceIDsMaxRows {
			return nil, fmt.Errorf("ByResourceIDs: %w", ErrResultTooLarge)
		}
	}
	return out, nil
}

func (r *CHRepo) byResourceIDsBatch(ctx context.Context, ids []string) ([]Finding, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, batchReadTimeout)
	defer cancel()

	placeholders, idArgs := dbutil.CHIn(ids)
	args := append(append([]any{}, idArgs...), idArgs...)
	// +1 so exceeding the guard is detectable rather than indistinguishable from
	// a result that happens to land exactly on it.
	query := fmt.Sprintf(selectFindingsArgMax, "id IN (SELECT id FROM findings WHERE resource_id IN ("+placeholders+"))") +
		" WHERE f.resource_id IN (" + placeholders + ") GROUP BY " + findingEnrichmentGroupBy +
		fmt.Sprintf(" LIMIT %d", byResourceIDsMaxRows+1)

	var out []Finding
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			fnd, err := scanFinding(rows)
			if err != nil {
				return err
			}
			out = append(out, fnd)
		}
		// rows.Err() is mandatory (CLAUDE.md): without it a mid-stream ClickHouse
		// failure returns partial rows with a nil error — a silent partial read
		// here reads as "resolved/absent" to a caller like
		// ResolveGoneByResourceIDs, which then wrongly resolves findings it
		// never actually saw.
		return rows.Err()
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ByResourceIDs: %w", err)
	}
	if len(out) > byResourceIDsMaxRows {
		return nil, fmt.Errorf("ByResourceIDs: %w: %d resource ids returned more than %d findings",
			ErrResultTooLarge, len(ids), byResourceIDsMaxRows)
	}
	return out, nil
}

// Get returns one finding by ID (argMax collapses ReplacingMergeTree versions
// without FINAL), or ErrNotFound.
func (r *CHRepo) Get(ctx context.Context, id string) (Finding, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	qCtx = r.ch.WithQuerySettings(qCtx, map[string]any{"max_threads": 1})

	var (
		fnd   Finding
		found bool
	)
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var err error
			if fnd, err = scanFinding(rows); err != nil {
				return err
			}
			found = true
		}
		return rows.Err()
	}, selectFindingByID, id, id) // id binds twice: fe's scope, then the outer WHERE — text order
	if err != nil {
		return Finding{}, fmt.Errorf("Get: %w", err)
	}
	if !found {
		return Finding{}, ErrNotFound
	}
	return fnd, nil
}

// scanFinding reads one row of selectFindingsArgMax/selectFindingByID — the
// two share a column order, so every hydrating reader scans through here.
func scanFinding(rows driver.Rows) (Finding, error) {
	var (
		fnd            Finding
		severity       string
		resolution     string
		knownExploited uint8
		unused         uint8
	)
	if err := rows.Scan(
		&fnd.ID, &fnd.Source, &fnd.Type, &severity, &fnd.Title, &fnd.Description,
		&fnd.ResourceType, &fnd.ResourceID, &fnd.ResourceName, &fnd.Region,
		&fnd.CheckID, &fnd.Remediation, &fnd.DetectedAt, &fnd.FirstDetectedAt,
		&fnd.Score, &fnd.ScoreBand, &fnd.EnrichedAt, &knownExploited, &fnd.Metadata,
		&fnd.Dependents, &unused, &fnd.SafetyClass, &fnd.FixTarget,
		&fnd.MustFixClass, &fnd.MustFixReason,
		&fnd.LastObservedAt, &fnd.ResolvedAt, &resolution,
		&fnd.OwnerTeam, &fnd.OwnerSource, &fnd.OwnerConfidence, &fnd.Environment,
	); err != nil {
		return Finding{}, fmt.Errorf("scan: %w", err)
	}
	fnd.Severity = Severity(severity)
	fnd.ResolutionReason = ResolutionReason(resolution)
	fnd.KnownExploited = knownExploited != 0
	fnd.Unused = unused != 0
	return fnd, nil
}
