package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// batchReadTimeout bounds List/ByIDs/ByResourceIDs — sweep/batch reads that can
// legitimately scan hundreds of thousands of rows (a high-volume check_id like
// k8s-container-runs-as-root), unlike the per-finding hot-path queries (Get,
// CountByCheckID), which must fail fast under load rather than wait longer.
//
// Sized generously enough to absorb legitimate ClickHouse contention from
// other heavy queries sharing the same instance (e.g. correlate's
// LoadViewForTypes), not just this package's own query cost. Every background
// job caller (enrich_sweep, KEV, correlate, OSV, dangling, sync's lifecycle
// reconcile) has its own job Timeout well above this constant, so it is a
// small fraction of any of their budgets.
//
// The one caller class this does NOT comfortably fit is the HTTP request path
// (finding/handler.go's List, respond's ByIDs, mcp/chat/govern/scan's List):
// httpsrv's WriteTimeout is the same order of magnitude as this constant, so a
// slow query here could otherwise blow the wire-level write deadline mid
// response. httpsrv's withDeadline middleware (server.go) closes this by
// capping every request's context at a value comfortably under WriteTimeout,
// so a handler calling into finding.List/ByIDs/ByResourceIDs always gets a
// clean cancellation and a proper RFC 9457 timeout response instead.
const batchReadTimeout = 60 * time.Second

// BatchReadTimeout exports batchReadTimeout for callers (dangling.go's own
// worst-case-arithmetic test) that need to pin their own timing budget against
// its actual value instead of duplicating the number and risking silent drift.
const BatchReadTimeout = batchReadTimeout

const (
	// insertFindings deliberately carries NONE of the ten enrich:"output"
	// columns (score, score_band, enriched_at, known_exploited, dependents,
	// unused, safety_class, fix_target, must_fix_class, must_fix_reason) —
	// finding_enrichment (RecordEnrichment/UpsertEnrichment, repo_enrichment.go)
	// is their only writer, and those columns do not exist on `findings` at
	// all. TestInsertFindingsOmitsEnrichmentColumns (repo_test.go) pins this
	// column list so a future edit can't reintroduce one of the ten by habit
	// (e.g. "just also insert the score while I'm here") — it would fail at
	// the ClickHouse driver instead of silently resurrecting a stale value.
	insertFindings = `INSERT INTO findings
		(id, source, type, severity, title, description, resource_type, resource_id,
		 resource_name, region, check_id, template_id, tags, remediation, detected_at, first_detected_at, synced_at,
		 last_observed_at, resolved_at, resolution_reason)`

	// firstDetectedAtAgg reads the finding's first observation as the MINIMUM
	// non-zero first_detected_at across the id's surviving row versions —
	// deliberately not argMax like every other column here.
	//
	// argMax answers "what does the newest row say", which is exactly the
	// property that made detected_at wrong: a producer re-emitting a
	// months-old finding stamps `now` and the newest row wins. min cannot be
	// moved forward by any writer, so the value is immutable under
	// re-observation at the READ level as well as the write level
	// (Service.RecordObserved pins it) — two independent mechanisms, because
	// the write-side pin is a best-effort lookup that skips on a read error.
	//
	// The nonzero filter matters: a row written by a producer that never
	// learned about this column carries 0,
	// and a plain min() would then report 1970 for every finding it touched —
	// an infinitely old finding, demoted forever. Zero is "unknown"; unknown
	// contributes nothing (absence of evidence never demotes). If
	// EVERY version is zero the result is zero, which the age source reads as
	// unknown and skips.
	//
	// This mirrors assetArgMaxSelect's min(discovered_at)/max(last_seen)
	// (internal/app/asset/repo.go): a monotonic fact about a row's whole
	// history, not the newest row's opinion.
	firstDetectedAtAgg = `minIf(first_detected_at, first_detected_at > toDateTime(0))`

	// selectFindingsArgMax and selectFindingByID (the shared argMax read form
	// and its point-lookup twin, both joining finding_enrichment) live in
	// repo_read.go, alongside the ByIDs/ByResourceIDs/Get methods that use them.

	// selectFindingKeysArgMax is List()'s page-selection form: the SAME
	// argMax/GROUP BY collapse as selectFindingsArgMax, but carrying ONLY the
	// seven columns List can filter or sort on. It exists because `LIMIT 200`
	// bounds a result set, not an aggregation.
	//
	// List's filters are almost all post-aggregation HAVINGs (see List), so
	// ClickHouse must build argMax state for EVERY id in `findings` before any
	// of them can prune — and with the full column set that state carries every
	// long String column (title, description, remediation, tags,
	// must_fix_reason) for every id in the table. Narrowing to the seven
	// columns List actually filters/sorts on is what keeps that unavoidable
	// full-table aggregation inside ClickHouse's per-query memory limit even
	// at the client semaphore's full concurrency.
	//
	// Same aliasing rule as selectFindingsArgMax: these ARE aliased because every
	// one of them is referenced post-aggregation (HAVING/ORDER BY) and none is
	// ever a pre-aggregation WHERE predicate — the inverse of source/resource_id/
	// check_id, which are deliberately left unaliased there.
	//
	// score/safety_class/must_fix_class/enriched_at come from finding_enrichment,
	// keeping List's filter (this query) and its hydration (ByIDs) reading the
	// same source — otherwise a page could return a finding whose hydrated
	// Score/MustFixClass contradicts the filter that selected it.
	//
	// %s-templated (costAtRiskFrom's pattern): fe's own WHERE is
	// caller-supplied. listKeysQuery scopes it by resource_id/check_id when
	// either is set — both are near-always highly selective (a single
	// resource or check), so scoping turns the join into a bounded lookup.
	// source alone is deliberately NEVER used to scope fe: it has only a
	// handful of values, each covering a large fraction of the table, so
	// scoping by it makes fe's nested subquery build a huge id list that is
	// SLOWER than leaving fe unscoped — a filter too coarse to prune gains
	// nothing from scoping and pays for building the IN-list anyway. A
	// source-only or no-filter call leaves fe unscoped, which is this query's
	// own known-expensive shape regardless (List's HAVING-based
	// filters can't prune before GROUP BY either way).
	//
	// findingKeysEnrichmentCols (not the shared 10-column
	// findingEnrichmentJoinCols ByIDs/ByResourceIDs/Get use) carries ONLY
	// the four columns this query filters/sorts on — the same "narrow
	// columns, not the full set" principle as this query's own column split,
	// applied to the enrichment side.
	//
	// fe.score/safety_class/must_fix_class ARE explicitly re-aliased here
	// (unlike selectFindingsArgMax/selectFindingByID, which leave them bare)
	// — this query's outer wrapper (listKeysQuery's "SELECT id FROM (...)
	// ORDER BY score") references them by name through an EXTRA layer of
	// subquery, and ClickHouse cannot project a bare qualified reference
	// through that extra layer: `fe.score` unaliased raises "Unknown
	// expression identifier 'score'" from the outer ORDER BY, while `fe.score
	// AS score` resolves fine. Get/ByIDs/ByResourceIDs never hit this because
	// Go's Scan() reads columns positionally, with no SQL layer needing to
	// resolve them by name.
	//
	// Three %s, in order: the join kind, fe's WHERE scope, and fe's HAVING.
	// The owner/environment filters live in fe's HAVING (they are enrichment
	// columns, versioned by enriched_at like every other fe column) and flip
	// the join to INNER, so they prune ids inside fe instead of adding columns
	// to the outer per-id aggregation state — the same narrowing discipline,
	// and the reason they are not in findingKeysEnrichmentCols.
	selectFindingKeysArgMax = `SELECT f.id,
		argMax(f.severity, f.synced_at) AS severity,
		fe.score AS score,
		fe.safety_class AS safety_class,
		fe.must_fix_class AS must_fix_class,
		fe.enr_at AS enriched_at,
		argMax(f.detected_at, f.synced_at) AS detected_at,
		argMax(f.resolved_at, f.synced_at) AS resolved_at
		FROM findings f
		%s JOIN (
			SELECT id,` + findingKeysEnrichmentCols + `
			FROM finding_enrichment WHERE %s
			GROUP BY id%s
		) fe ON fe.id = f.id`
)

// findingKeysEnrichmentCols is selectFindingKeysArgMax's fe subquery column
// list — see that const's comment for why it's narrower than
// findingEnrichmentJoinCols. enr_at, never enriched_at: the same
// ILLEGAL_AGGREGATION aliasing hazard as every other fe subquery
// (sibling argMax(col, enriched_at) aggregates bare-reference
// enriched_at as their version argument).
const findingKeysEnrichmentCols = `
			argMax(score, enriched_at)          AS score,
			argMax(safety_class, enriched_at)   AS safety_class,
			argMax(must_fix_class, enriched_at) AS must_fix_class,
			max(enriched_at)                     AS enr_at`

// findingKeysGroupBy is selectFindingKeysArgMax's GROUP BY suffix: f.id plus
// every bare-selected fe.* column this query actually selects (narrower than
// findingEnrichmentGroupBy, which covers all ten ByIDs/ByResourceIDs/Get
// columns) — fe is already grouped 1:1 by id inside its own subquery, so
// this is a no-op aggregation-wise, but ClickHouse's checker requires it.
const findingKeysGroupBy = "f.id, fe.score, fe.safety_class, fe.must_fix_class, fe.enr_at"

// listWideColumns are the columns List must NOT aggregate while selecting a
// page. They are the long String columns whose argMax state dominated the old
// single-query form's memory (see selectFindingKeysArgMax); ByIDs fetches them
// afterwards for the ≤200 ids that survived, where the pre-aggregation
// `id IN (...)` prunes on the primary key and the idx_id bloom index.
var listWideColumns = []string{"title", "description", "remediation", "tags", "must_fix_reason", "resource_name"}

// DefaultLimit caps a findings page; the handler treats a full page (len ==
// DefaultLimit) as "there may be more" and emits a next cursor.
const DefaultLimit = 200

// CHRepo implements Repo on ClickHouse.
type CHRepo struct {
	ch  *db.CH
	now func() time.Time // synced_at source; injectable for deterministic tests
}

// Option configures a CHRepo.
type Option func(*CHRepo)

// WithClock overrides the synced_at clock. synced_at is the ReplacingMergeTree
// version (one-second granularity), so two Upserts of the same row within one
// second tie and argMax may surface the stale one. Real workloads are unaffected
// (writes to a row are seconds+ apart); tests that re-write rapidly inject an
// advancing clock so the latest write deterministically wins.
func WithClock(now func() time.Time) Option { return func(r *CHRepo) { r.now = now } }

func NewCHRepo(ch *db.CH, opts ...Option) *CHRepo {
	r := &CHRepo{ch: ch, now: time.Now}
	for _, o := range opts {
		o(r)
	}
	return r
}

// findingBatchSize bounds enrichment writes; inventory findings use byte-aware batches.
const findingBatchSize = 500

// findingWriteBudget is the wall-clock an Upsert is guaranteed even when the
// caller's own deadline is already spent (see db.WithWriteBudget) — mirrors
// asset.assetWriteBudget for the same reason: RecordObserved runs at the end
// of a sync job's own budget, so a slow write must not inherit an
// already-exhausted parent deadline and fail before it can even start.
const findingWriteBudget = 5 * time.Minute

// Upsert writes findings. The full PRODUCER row is always written (every
// column insertFindings names), so re-records from a connector/scanner never
// produce a partial row that argMax would merge with a stale title/severity.
//
// The ten enrich:"output" fields on the Finding structs
// passed in here are NOT written — insertFindings' column list omits them,
// so whatever Score/ScoreBand/MustFixClass/etc. a caller's Finding carries is
// silently ignored for this call (`findings` has no enrichment columns at
// all). This is deliberate and
// safe: finding_enrichment (RecordEnrichment/UpsertEnrichment) is the only
// place those ten fields are persisted or read back from (every finding
// reader — Get/ByIDs/ByResourceIDs/List/Summary/Clusters/the risk rollups —
// joins it), so a caller does not need to populate, zero, or carry forward
// any of them before calling Record/RecordObserved/Resolve. enrich
// (internal/app/enrich/service.go) and KEV (internal/jobs/kev.go) write the
// ten through RecordEnrichment only and never call Record.
func (r *CHRepo) Upsert(ctx context.Context, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	ctx, cancel := db.WithWriteBudget(ctx, findingWriteBudget)
	defer cancel()
	now := r.now()
	for start := 0; start < len(findings); {
		end := dbutil.CHWriteBatchEnd(findings, start, findingWriteBytes)
		chunk := findings[start:end]
		err := r.ch.Batch(ctx, insertFindings, func(b driver.Batch) error {
			for _, f := range chunk {
				if err := b.Append(
					f.ID, f.Source, f.Type, string(f.Severity), f.Title, f.Description,
					f.ResourceType, f.ResourceID, f.ResourceName, f.Region, f.CheckID,
					"", metaOrEmpty(f.Metadata), f.Remediation, f.DetectedAt,
					firstDetectedAt(f), now,
					f.LastObservedAt, f.ResolvedAt, string(f.ResolutionReason),
				); err != nil {
					return fmt.Errorf("append finding %s: %w", f.ID, err)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("Upsert: %w", err)
		}
		start = end
	}
	return nil
}

// List returns one page of findings, newest-first by default.
//
// It runs in two phases on purpose. Phase one selects only the page's ids using
// selectFindingKeysArgMax — the narrow column set — because List's filters are
// post-aggregation HAVINGs and so cannot prune before the GROUP BY; phase two
// hydrates those ≤200 ids through ByIDs, whose pre-aggregation `id IN (...)`
// prunes on the primary key and the idx_id bloom index. One query carrying all
// 27 columns through the unprunable aggregation is what blew the ClickHouse
// server memory limit (see selectFindingKeysArgMax).
//
// The two phases are not one snapshot. A finding whose row changes between them
// is returned with its phase-two state, and one that stops matching the filter
// is dropped, so a page can come back shorter than the limit. Both are benign
// here: findings are never deleted (resolved_at is stamped instead), the
// handler treats a short page as the last one, and the enrich sweep's next tick
// re-derives its own cursor from scratch.
func (r *CHRepo) List(ctx context.Context, f Filter) ([]Finding, error) {
	qCtx, cancel := context.WithTimeout(ctx, batchReadTimeout)
	defer cancel()

	query, args, err := listKeysQuery(f)
	if err != nil {
		return nil, err
	}

	var ids []string
	if err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			ids = append(ids, id)
		}
		return nil
	}, query, args...); err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}

	hydrated, err := r.ByIDs(qCtx, ids)
	if err != nil {
		return nil, fmt.Errorf("List: hydrate: %w", err)
	}
	byID := make(map[string]Finding, len(hydrated))
	for _, fnd := range hydrated {
		byID[fnd.ID] = fnd
	}
	// ByIDs' order is unspecified; restore phase one's, which is the sort the
	// caller asked for and the cursor the next page will be built from.
	out := make([]Finding, 0, len(ids))
	for _, id := range ids {
		if fnd, ok := byID[id]; ok {
			out = append(out, fnd)
		}
	}
	return out, nil
}

// listKeysQuery builds List's phase-one page-selection query. It is a pure
// function so the shape it emits — narrow column set, filters split correctly
// across WHERE and HAVING — is directly testable without ClickHouse.
func listKeysQuery(f Filter) (string, []any, error) {
	// Pre-aggregation WHERE: source, resource_id and check_id are baked into a
	// finding's deterministic ID (dbutil.DeterministicID, checks.eval) so they
	// are identical across every ReplacingMergeTree version of a given id —
	// filtering the raw column before GROUP BY is correct, and it's the actual
	// performance fix: it can use the (source, id) primary key and the
	// resource_id/id bloom indexes that FINAL/argMax
	// both block from a post-aggregation predicate.
	var (
		whereConds []string // f.-qualified, for the outer WHERE
		whereArgs  []any
	)
	if f.Source != "" {
		whereConds = append(whereConds, "f.source = ?")
		whereArgs = append(whereArgs, f.Source)
	}
	if f.ResourceID != "" {
		whereConds = append(whereConds, "f.resource_id = ?")
		whereArgs = append(whereArgs, f.ResourceID)
	}
	if f.CheckID != "" {
		whereConds = append(whereConds, "f.check_id = ?")
		whereArgs = append(whereArgs, f.CheckID)
	}
	if len(f.CVEIn) > 0 {
		upper := make([]string, len(f.CVEIn))
		for i, id := range f.CVEIn {
			upper[i] = strings.ToUpper(id)
		}
		checkPh, checkArgs := dbutil.CHIn(upper)
		tagPh, tagArgs := dbutil.CHIn(upper)
		whereConds = append(whereConds,
			"(upper(f.check_id) IN ("+checkPh+") OR upper(f.tags['cve']) IN ("+tagPh+"))")
		whereArgs = append(whereArgs, append(checkArgs, tagArgs...)...)
	}

	// fe's own scope (see selectFindingKeysArgMax's comment for the reasoning
	// behind this): resource_id/check_id, never source. Built
	// separately from whereConds/whereArgs above because fe's nested
	// subquery is bare (unaliased, matching ByResourceIDs' own nested
	// subquery) while the outer WHERE is f.-qualified, and because source
	// must never reach it.
	var (
		feScopeConds []string
		feScopeArgs  []any
	)
	if f.ResourceID != "" {
		feScopeConds = append(feScopeConds, "resource_id = ?")
		feScopeArgs = append(feScopeArgs, f.ResourceID)
	}
	if f.CheckID != "" {
		feScopeConds = append(feScopeConds, "check_id = ?")
		feScopeArgs = append(feScopeArgs, f.CheckID)
	}
	feScope := "1=1"
	if len(feScopeConds) > 0 {
		feScope = "id IN (SELECT id FROM findings WHERE " + strings.Join(feScopeConds, " AND ") + ")"
	}
	feHaving, feHavingArgs := routingHaving(f)
	joinKind := "LEFT"
	if feHaving != "" {
		joinKind = "INNER" // a finding with no enrichment row has no owner/environment to match
	}

	// Post-aggregation HAVING (on the argMax aliases): every other filter field
	// is an enrichment or lifecycle column that a re-observation/re-enrich CAN
	// rewrite — severity included: a re-observation is free to carry a
	// genuinely new severity (Service.pinFirstDetectedAt does not touch
	// severity except for the narrow KEV-oscillation guard). Filtering any of these
	// pre-aggregation would match whichever stale historical version happened to
	// satisfy the predicate instead of the finding's current state.
	var (
		havingConds []string
		havingArgs  []any
	)
	if f.Severity != "" {
		havingConds = append(havingConds, "severity = ?")
		havingArgs = append(havingArgs, string(f.Severity))
	}
	if f.MinScore > 0 {
		havingConds = append(havingConds, "score >= ?")
		havingArgs = append(havingArgs, f.MinScore)
	}
	if f.SafeOnly {
		havingConds = append(havingConds, "safety_class = 'safe'")
	}
	if f.MustFixOnly {
		havingConds = append(havingConds, "must_fix_class = 'must_fix'")
	}
	if f.Unenriched {
		// enriched_at is unset (zero DateTime) until a finding is scored. This
		// selects the never-enriched backlog the enrich sweep backfills.
		havingConds = append(havingConds, "enriched_at < toDateTime('2000-01-01 00:00:00')")
	}
	if f.StaleFirst {
		// The never-enriched backlog is Unenriched's job (score=0 sentinel); StaleFirst
		// only walks findings that HAVE been enriched at least once, oldest first.
		havingConds = append(havingConds, "enriched_at >= toDateTime('2000-01-01 00:00:00')")
	}
	if !f.IncludeResolved {
		// Auto-resolved findings are hidden by default — a fixed issue
		// must not linger in lists/worklists. resolved_at is zero while open.
		havingConds = append(havingConds, "resolved_at < toDateTime('2000-01-01 00:00:00')")
	}
	if !f.DetectedAfter.IsZero() {
		// detected_at is NOT identity-stable: checks.eval stamps `now` on every
		// re-run of a changed asset, and a check-registry backfill
		// re-runs ALL assets, bumping it further — so it belongs in
		// HAVING, not the pre-aggregation WHERE above.
		havingConds = append(havingConds, "detected_at >= ?")
		havingArgs = append(havingArgs, f.DetectedAfter)
	}
	if !f.DetectedBefore.IsZero() {
		havingConds = append(havingConds, "detected_at <= ?")
		havingArgs = append(havingArgs, f.DetectedBefore)
	}

	if f.Cursor != "" {
		switch {
		case f.StaleFirst:
			c, err := decodeStaleCursor(f.Cursor)
			if err != nil {
				return "", nil, err
			}
			// Ascending seek — oldest-enriched-first, so resume strictly after the
			// last page's seek key instead of DESC's "before". enriched_at is a
			// HAVING field (see above), so the seek condition is too.
			//
			// enriched_at is DateTime64(3), but clickhouse-go binds a time.Time
			// as a seconds-precision DateTime: binding it would truncate the
			// cursor's milliseconds, so rows in the same second as the page's
			// last row (ms after it) would compare greater-or-equal and be
			// re-served. The cursor is bound as epoch milliseconds instead.
			havingConds = append(havingConds, "(enriched_at, id) > (fromUnixTimestamp64Milli(toInt64(?)), ?)")
			havingArgs = append(havingArgs, c.ts.UnixMilli(), c.id)
		case f.OldestFirst:
			c, err := decodeCursor(f.Cursor, false)
			if err != nil {
				return "", nil, err
			}
			// Ascending seek — resume strictly AFTER the last page's key, the
			// mirror of the descending default below.
			havingConds = append(havingConds, "(detected_at, id) > (?, ?)")
			havingArgs = append(havingArgs, c.ts, c.id)
		default:
			c, err := decodeCursor(f.Cursor, f.SortByScore)
			if err != nil {
				return "", nil, err
			}
			// Keyset seek against the aggregated (argMax) value — score and
			// detected_at are both HAVING fields.
			if f.SortByScore {
				havingConds = append(havingConds, "(score, id) < (?, ?)")
				havingArgs = append(havingArgs, c.score, c.id)
			} else {
				havingConds = append(havingConds, "(detected_at, id) < (?, ?)")
				havingArgs = append(havingArgs, c.ts, c.id)
			}
		}
	}

	inner := fmt.Sprintf(selectFindingKeysArgMax, joinKind, feScope, feHaving)
	args := append(append(append([]any{}, feScopeArgs...), feHavingArgs...), whereArgs...)
	if len(whereConds) > 0 {
		inner += " WHERE " + strings.Join(whereConds, " AND ")
	}
	inner += " GROUP BY " + findingKeysGroupBy
	if len(havingConds) > 0 {
		inner += " HAVING " + strings.Join(havingConds, " AND ")
		args = append(args, havingArgs...)
	}

	orderCol, orderDir := "detected_at", "DESC"
	switch {
	case f.SortByScore:
		orderCol = "score"
	case f.StaleFirst:
		orderCol, orderDir = "enriched_at", "ASC"
	case f.OldestFirst:
		orderDir = "ASC"
	}

	limit := f.Limit
	if limit <= 0 || limit > DefaultLimit {
		limit = DefaultLimit
	}
	args = append(args, limit)

	// The ORDER BY / LIMIT sit OUTSIDE the aggregation so the sort runs over the
	// rows the HAVING kept, not over one argMax state per id in the table. Only
	// `id` is projected: the seven key columns exist to be filtered and sorted
	// on, never to be returned — ByIDs returns the row.
	return "SELECT id FROM (" + inner + ") ORDER BY " + orderCol + " " + orderDir +
		", id " + orderDir + " LIMIT ?", args, nil
}

// distinctCheckIDs lists unique check_ids with at least one currently OPEN
// finding whose evidence is not PROVABLY GONE, optionally scoped by source.
// This feeds compliance.Service.Compute (a control fails iff one of its
// check_ids appears here) — without the liveness gate below, a control could
// report Failing forever on an open finding whose only asset is a long-dead,
// unpurged k8s_pod/container/k8s_job that deletion reconciliation never
// reaches for that connector.
//
// Inner GROUP BY on (source, id) collapses RMT versions via argMax without
// FINAL (skip indexes are ignored under FINAL — house rule); the resolved_at
// filter excludes findings that have since cleared — otherwise a check_id
// lingers here (and its compliance control stays "failing") forever once
// collapsed.
//
// Liveness gate: reuses asset.EphemeralLivenessCond VERBATIM — the single
// definition of "is this resource still there" — rather than a second,
// subtly different filter. It is embedded the same way
// finding.costAtRiskFrom already embeds asset.InventoryReadCond (risk.go), so
// this is not a new cross-layer dependency. The corpses subquery reproduces
// asset.optimize.go's verifiedExpiredEphemeralIDs shape exactly (argMax
// type/last_seen aliased to asset_type/latest_seen, then RE-PROJECTED as
// type/last_seen immediately before the WHERE that reads them) because
// EphemeralLivenessCond's `type`/`last_seen` references must resolve against
// THAT projection, not any outer scope's same-named columns — the shadowing
// bug documented at asset/repo.go's EphemeralLivenessCond comment.
//
// This must tell three states apart (the "unmeasured is not zero" concern):
//
//  1. Evidence on a LIVE asset, or on any non-gated type (cloud resource types
//     are never gated because a stale row there is far more often broken
//     collection than deletion) — the finding stays in `open_findings`'s
//     result and its check_id fails. Correct: this is real, current evidence.
//  2. Evidence existed but the asset is PROVABLY gone — a matching `assets` row
//     was found AND EphemeralLivenessCond is false for it — excluded via
//     `resource_id NOT IN (verified corpses)`. Its check_id no longer fails
//     on this evidence.
//  3. UNKNOWN liveness — no `assets` row matches resource_id at all (blank
//     resource_id, never synced, or a fully purged account), or the query
//     errors outright. The unknown case is handled by NOT excluding the
//     finding: only a MATCHED, VERIFIED-DEAD row can appear in the corpses
//     subquery, so an unknown asset behaves like a live one — unmeasured
//     evidence can only push a control toward Failing, never silently toward
//     Passing. A query error surfaces as a Go error from DistinctCheckIDs,
//     which compliance.Service.Compute propagates rather than returning a
//     partial []string, reaching the handler as a 500 — never a 200 that
//     quietly cleared a control.
const distinctCheckIDs = openFindingsCTE + `
	SELECT DISTINCT check_id FROM open_findings
	WHERE resource_id = '' OR ` + notVerifiedDead

// openFindingsCTE is the open (check_id, resource_id) set distinctCheckIDs and
// openResourcesByCheck share, so "open" has one definition. The %s is the
// inner WHERE prefix (an optional source or check_id filter ending in AND).
const openFindingsCTE = `WITH open_findings AS (
		SELECT check_id, resource_id FROM (
			SELECT
				argMax(check_id, synced_at) AS check_id,
				argMax(resolved_at, synced_at) AS resolved_at,
				argMax(resource_id, synced_at) AS resource_id
			FROM findings
			%s findings.check_id != ''
			GROUP BY source, id
		)
		WHERE resolved_at < toDateTime('2000-01-01 00:00:00')
	)`

// notVerifiedDead keeps a resource unless a matched assets row proves it
// gone (state 2 above); an unmatched resource stays evidence (state 3).
const notVerifiedDead = `resource_id NOT IN (
		SELECT id FROM (
			SELECT id, asset_type AS type, latest_seen AS last_seen FROM (
				SELECT id, argMax(type, synced_at) AS asset_type, max(last_seen) AS latest_seen
				FROM assets
				WHERE id IN (SELECT resource_id FROM open_findings WHERE resource_id != '')
				GROUP BY id
			)
		) WHERE NOT (` + asset.EphemeralLivenessCond + `)
	)`

// DistinctCheckIDs returns the set of check_ids that have at least one current
// finding. source="" means all sources.
func (r *CHRepo) DistinctCheckIDs(ctx context.Context, source string) ([]string, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	innerWhere := "WHERE"
	var args []any
	if source != "" {
		innerWhere = "WHERE source = ? AND"
		args = append(args, source)
	}
	query := fmt.Sprintf(distinctCheckIDs, innerWhere)

	var ids []string
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			ids = append(ids, id)
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("DistinctCheckIDs: %w", err)
	}
	return ids, nil
}

// countByCheckID counts the distinct resources with an OPEN finding for a
// specific check_id within a source — the CrossCluster enrichment score
// denominator. Inner GROUP BY on (source, id) collapses RMT versions without
// FINAL and keeps only ids whose latest version is unresolved (a fixed finding
// is not evidence the issue is systemic); outer counts distinct non-empty
// resource_ids. res_at, not resolved_at: aliasing an aggregate to its own
// argument's column name is ClickHouse's ILLEGAL_AGGREGATION hazard.
const countByCheckID = `SELECT count(DISTINCT resource_id)
	FROM (
		SELECT resource_id, argMax(resolved_at, synced_at) AS res_at
		FROM findings
		WHERE source = ? AND check_id = ? AND resource_id != ''
		GROUP BY source, id, resource_id
		HAVING res_at < toDateTime('2000-01-01 00:00:00')
	)`

// CountByCheckID returns the number of distinct resources that currently have
// a finding with the given check_id and source. Used by the CrossCluster enrich
// source to detect systemic issues without loading all findings into Go memory.
func (r *CHRepo) CountByCheckID(ctx context.Context, source, checkID string) (int, error) {
	if source == "" || checkID == "" {
		return 0, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var n uint64
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		if rows.Next() {
			return rows.Scan(&n)
		}
		return nil
	}, countByCheckID, source, checkID)
	if err != nil {
		return 0, fmt.Errorf("CountByCheckID: %w", err)
	}
	return int(n), nil
}

// boolToUint8 maps a bool to ClickHouse's UInt8 (it has no native bool).
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// firstDetectedAt is the value written to the first_detected_at column. A
// caller that constructed a Finding without going through Service (a producer
// emitting a brand-new violation, a test, a future feed) leaves it zero; write
// that finding's own DetectedAt instead, never zero. Writing zero would poison
// the min-over-nonzero read for the rest of the finding's life if the nonzero
// filter were ever dropped, and would mean a genuinely-new finding has no
// recorded first observation at all until something else re-writes it.
//
// This is a floor, not the pin: pinning an EXISTING finding's value to what is
// already stored is Service.RecordObserved's job, which knows the prior row.
// The repo cannot — it does not read before it writes.
func firstDetectedAt(f Finding) time.Time {
	if f.FirstDetectedAt.IsZero() {
		return f.DetectedAt
	}
	return f.FirstDetectedAt
}

// metaOrEmpty guarantees a non-nil map for the ClickHouse Map(String,String)
// column — the driver rejects a nil map on Append.
func metaOrEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
