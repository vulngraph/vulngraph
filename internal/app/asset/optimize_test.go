package asset

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// EphemeralTypes and EphemeralLivenessCond must name exactly the same types.
// EphemeralTypes is what the finding lifecycle sweep is allowed to resolve on
// absence; EphemeralLivenessCond is what the graph filters on. If they drift, one
// of two things happens: a type is dropped from the graph while its findings live
// forever, or findings are resolved for a type the graph still trusts.
func TestEphemeralTypesMatchTheLivenessCondition(t *testing.T) {
	// The condition opens with `(type NOT IN ('a','b') OR …`.
	in := regexp.MustCompile(`type NOT IN \(([^)]*)\)`).FindStringSubmatch(EphemeralLivenessCond)
	require.Len(t, in, 2, "EphemeralLivenessCond no longer has a `type NOT IN (…)` clause: %s", EphemeralLivenessCond)

	var inCond []string
	for _, raw := range strings.Split(in[1], ",") {
		if v := strings.Trim(strings.TrimSpace(raw), "'"); v != "" {
			inCond = append(inCond, v)
		}
	}
	require.ElementsMatch(t, EphemeralTypes, inCond,
		"EphemeralTypes and EphemeralLivenessCond must list the same asset types")
}

// The liveness query must EMBED the shared condition rather than restate it —
// the whole point is that there is one definition of "this pod still exists".
func TestLiveAssetIDsAppliesEphemeralLiveness(t *testing.T) {
	require.Contains(t, liveAssetIDs, EphemeralLivenessCond,
		"liveAssetIDs must apply the shared condition, never its own copy of the arithmetic")
	// It reads `type` and `last_seen`, so the inner projection must expose both
	// under exactly those names or the condition silently binds to nothing.
	require.Contains(t, liveAssetIDs, "AS type")
	require.Contains(t, liveAssetIDs, "AS last_seen")
	require.Contains(t, liveAssetIDs, "GROUP BY id",
		"versions must collapse per id the way ExistingIDs does")
}

// The liveness arithmetic itself, pinned. Every Go-level test of the ephemeral
// sweep runs against a fake that reimplements this in Go, so without these the
// two mutations that matter most — shortening the grace window, or anchoring to
// wall-clock instead of the type's own high-water mark — pass every test in the
// repository while resolving findings on live pods.
//
// The behavioural proof against a real ClickHouse is liveness_integration_test.go
// (build tag `integration`); these are the cheap checks that run on every commit.
func TestEphemeralLivenessArithmetic(t *testing.T) {
	c := EphemeralLivenessCond

	require.Contains(t, c, "INTERVAL 72 HOUR",
		"the grace window absorbs missed collection ticks; shortening it resolves findings on pods "+
			"that are merely late, and resourceGoneGrace in internal/jobs is written against this value")

	require.Contains(t, c, "SELECT max(hw.last_seen) FROM assets AS hw WHERE hw.type = 'k8s_pod'",
		"the cutoff MUST anchor to the type's own high-water mark. Against now() a "+
			"collection outage looks identical to mass deletion, and the sweep resolves the estate. "+
			"The table alias is part of the invariant: unqualified, the predicate binds to whatever "+
			"`type` is in scope where the condition is applied, so callers projecting a `type` column "+
			"filter the high-water lookup on their own row and judge every non-pod asset deleted")

	require.NotContains(t, c, "now()",
		"wall-clock anchoring is the failure this design exists to prevent")
	require.NotContains(t, c, "today()")
	require.NotContains(t, c, "MINUTE")
	require.NotContains(t, c, "INTERVAL 72 DAY")

	// The subquery must read the base `assets` table by name, not inherit an outer
	// alias — otherwise it silently measures whatever the caller happened to select.
	//
	// This assertion anticipated the defect correctly and still missed it, because
	// naming the table is not enough: the PREDICATE also has to be qualified.
	// `FROM assets WHERE type = 'k8s_pod'` reads the right table while binding
	// `type` to a caller's projection, which is exactly how a 200-day-old iam_role
	// came back deleted. Both halves are pinned now.
	require.Contains(t, c, "FROM assets AS hw")
	require.Contains(t, c, "WHERE hw.type =")
}

// OPTIMIZE is destructive-adjacent and long-running: the statement must be FINAL
// (ReplacingMergeTree version collapse) and must NOT be DEDUPLICATE, which drops
// rows by full-column equality and would discard legitimately distinct history.
func TestOptimizeStatementShape(t *testing.T) {
	require.Contains(t, optimizeTable, "FINAL")
	require.NotContains(t, optimizeTable, "DEDUPLICATE")
	require.Equal(t, 1, strings.Count(optimizeTable, "%s"),
		"exactly one table placeholder, filled only from OptimizableTables")
}

// Every optimizable table must be a real ReplacingMergeTree this codebase writes.
// A typo would make the job silently error every tick (or, worse, optimize a table
// nobody meant to touch).
func TestOptimizableTablesAreKnownReplacingMergeTrees(t *testing.T) {
	known := map[string]bool{
		"assets": true, "findings": true, "graph_edges": true,
		"beliefs": true, "signals": true,
	}
	seen := map[string]bool{}
	for _, table := range OptimizableTables {
		require.Truef(t, known[table], "%q is not a known ReplacingMergeTree", table)
		require.Falsef(t, seen[table], "%q listed twice", table)
		seen[table] = true
	}
	require.NotEmpty(t, OptimizableTables)
}

// Representative shapes of the `assets` table, so the guard is tested against
// the shape ClickHouse actually reports rather than a number chosen to make it pass.
//
// Feeding the fake a large bytes_on_disk figure for `assets` and asserting a
// skip would pin a fiction: system.parts.bytes_on_disk counts the projection
// stored inside each part, while the base table can be far smaller. Without
// the projection the size guard passes and `OPTIMIZE TABLE assets FINAL` runs
// every two hours, so only the projection count can tell the two apart.
var (
	// assetsWithProjection: a small base under much larger projection parts.
	assetsWithProjection = TableStats{
		BaseBytes: 512 << 20, BaseUncompressedBytes: 4 << 30, ActiveParts: 12, ProjectionParts: 12,
	}
	// assetsWithoutProjection: the same base table with no projection, the
	// second-cheapest merge in the list.
	assetsWithoutProjection = TableStats{
		BaseBytes: 512 << 20, BaseUncompressedBytes: 4 << 30, ActiveParts: 12,
	}
)

// The policy, exhaustively. skipReasonFor is the whole guard.
func TestSkipReasonFor(t *testing.T) {
	cases := []struct {
		name  string
		stats TableStats
		want  string
	}{
		{
			// THE case this guard exists for. With a live projection and
			// deduplicate_merge_projection_mode='rebuild', a merge rebuilds the whole
			// projection. The base bytes are small and would sail through any byte
			// ceiling — only the projection count catches it.
			name:  "tiny base, live projection, must skip",
			stats: assetsWithProjection, want: SkipProjection,
		},
		{
			// The other half: with no projection the skip must CLEAR on its own, or
			// the job silently never does the thing repo.go says it does.
			name:  "same base, no projection: optimized",
			stats: assetsWithoutProjection, want: "",
		},
		{
			name: "findings", stats: TableStats{BaseBytes: 256 << 20, BaseUncompressedBytes: 2 << 30, ActiveParts: 10}, want: "",
		},
		{
			// Fail closed. sum() over no rows is 0, which is indistinguishable from
			// an empty table: wrong session database, renamed table, everything
			// detached. None of those are evidence a merge is safe.
			name: "no active parts fails closed", stats: TableStats{}, want: SkipNoParts,
		},
		{
			name:  "zero bytes but parts present is a real empty table",
			stats: TableStats{ActiveParts: 1}, want: "",
		},
		{
			name:  "at the ceiling",
			stats: TableStats{BaseUncompressedBytes: OptimizeMaxUncompressedBytes, ActiveParts: 3}, want: "",
		},
		{
			name:  "one byte over the ceiling",
			stats: TableStats{BaseUncompressedBytes: OptimizeMaxUncompressedBytes + 1, ActiveParts: 3}, want: SkipTooLarge,
		},
		{
			// THE defect the uncompressed guard exists for. These tables compress
			// 5-10x, so a compressed-bytes ceiling of 4 GiB authorised merges of
			// 20-40 GiB of actual work. Compressed comfortably under the old
			// ceiling, uncompressed far over the real one: must skip.
			name: "compressed under the old ceiling, uncompressed far over",
			stats: TableStats{
				BaseBytes: 4 << 30, BaseUncompressedBytes: 40 << 30, ActiveParts: 12,
			},
			want: SkipTooLarge,
		},
		{
			// The mirror: compression must never be the thing that decides. A large
			// compressed figure with small real content is optimizable.
			name: "compressed bytes alone never trip the guard",
			stats: TableStats{
				BaseBytes: 40 << 30, BaseUncompressedBytes: 1 << 30, ActiveParts: 12,
			},
			want: "",
		},
		{
			// A projection outranks the size check: rebuilding it is the expensive
			// part regardless of how small the base is.
			name:  "projection outranks size",
			stats: TableStats{BaseUncompressedBytes: 1 << 20, ActiveParts: 2, ProjectionParts: 1}, want: SkipProjection,
		},
		{
			// And no-parts outranks everything: there is nothing to measure.
			name:  "no parts outranks a projection",
			stats: TableStats{ProjectionParts: 1}, want: SkipNoParts,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, skipReasonFor(tc.stats))
		})
	}
}

// The base-size query must read data_compressed_bytes, never bytes_on_disk, and
// must return the part count that makes the guard fail closed.
func TestTableStatsQueriesExcludeProjections(t *testing.T) {
	require.Contains(t, tableBaseStats, "data_compressed_bytes",
		"bytes_on_disk counts the projection stored inside each part, which can dwarf the base table")
	require.Contains(t, tableBaseStats, "data_uncompressed_bytes",
		"the size guard applies to uncompressed bytes: that is what a merge decompresses, sorts and rewrites")
	require.NotContains(t, tableBaseStats, "bytes_on_disk")
	require.Contains(t, tableBaseStats, "count()",
		"the guard fails closed on zero active parts, which needs a count alongside the sum")
	require.Contains(t, tableProjectionParts, "system.projection_parts")
	for _, q := range []string{tableBaseStats, tableProjectionParts} {
		require.Contains(t, q, "currentDatabase()")
		require.Contains(t, q, "active")
	}
}

// fakeOptimizeRepo records what Optimize did
type fakeOptimizeRepo struct {
	Repo  // never called; only the two optimize methods are exercised
	stats map[string]TableStats
	// failTable/statsErrTable name the single table whose OptimizeTable/TableStats
	// call fails; empty means none fails.
	failTable     string
	statsErrTable string
	optErr        error
	optimized     []string
}

func (f *fakeOptimizeRepo) TableStats(_ context.Context, table string) (TableStats, error) {
	if f.statsErrTable == table {
		return TableStats{}, errors.New("system.parts unavailable")
	}
	return f.stats[table], nil
}

func (f *fakeOptimizeRepo) OptimizeTable(_ context.Context, table string) error {
	if f.optErr != nil && (f.failTable == "" || f.failTable == table) {
		return f.optErr
	}
	f.optimized = append(f.optimized, table)
	return nil
}

// End to end over realistic table shapes, with and without a projection on
// assets. It feeds the guard numbers shaped like what ClickHouse reports, not
// numbers chosen to make it skip.
func TestOptimizeAgainstRealTableShapes(t *testing.T) {
	base := map[string]TableStats{
		"graph_edges": {BaseBytes: 64 << 20, BaseUncompressedBytes: 512 << 20, ActiveParts: 5},
		"signals":     {BaseBytes: 64 << 20, BaseUncompressedBytes: 512 << 20, ActiveParts: 7},
		"beliefs":     {BaseBytes: 96 << 20, BaseUncompressedBytes: 768 << 20, ActiveParts: 10},
		"findings":    {BaseBytes: 256 << 20, BaseUncompressedBytes: 2 << 30, ActiveParts: 10},
	}

	t.Run("a projection keeps assets out", func(t *testing.T) {
		stats := map[string]TableStats{"assets": assetsWithProjection}
		for k, v := range base {
			stats[k] = v
		}
		repo := &fakeOptimizeRepo{stats: stats}

		results, err := NewService(repo).Optimize(context.Background())
		require.NoError(t, err)

		require.NotContains(t, repo.optimized, "assets",
			"a merge here rebuilds the projection on top of the base merge")
		byTable := resultsByTable(results)
		require.Equal(t, SkipProjection, byTable["assets"].SkipReason)
		require.Len(t, repo.optimized, len(base), "every other table is compacted")
	})

	t.Run("without a projection assets is compacted like any other table", func(t *testing.T) {
		stats := map[string]TableStats{"assets": assetsWithoutProjection}
		for k, v := range base {
			stats[k] = v
		}
		repo := &fakeOptimizeRepo{stats: stats}

		results, err := NewService(repo).Optimize(context.Background())
		require.NoError(t, err)

		require.Contains(t, repo.optimized, "assets",
			"a small base with no projection is the whole point of the job — repo.go has always claimed it runs")
		require.False(t, resultsByTable(results)["assets"].Skipped)
	})
}

func resultsByTable(results []OptimizeResult) map[string]OptimizeResult {
	out := map[string]OptimizeResult{}
	for _, r := range results {
		out[r.Table] = r
	}
	return out
}

// Every table is reported, skipped or not: a skip is a fact the operator needs.
func TestOptimizeReportsEveryTable(t *testing.T) {
	repo := &fakeOptimizeRepo{stats: map[string]TableStats{}} // all zero → all fail closed

	results, err := NewService(repo).Optimize(context.Background())

	require.NoError(t, err)
	require.Len(t, results, len(OptimizableTables))
	require.Empty(t, repo.optimized, "an unmeasurable table is never optimized")
	for _, r := range results {
		require.True(t, r.Skipped)
		require.Equal(t, SkipNoParts, r.SkipReason)
	}
}

// A failure must NOT stop the pass. One permanently unmergeable table used to
// silence every table behind it — combined with the fixed walk order that meant
// the same tail was never compacted, identically, forever.
func TestOptimizeContinuesPastAFailingTable(t *testing.T) {
	stats := map[string]TableStats{}
	for _, tbl := range OptimizableTables {
		stats[tbl] = TableStats{BaseBytes: 1 << 20, BaseUncompressedBytes: 8 << 20, ActiveParts: 2}
	}
	repo := &fakeOptimizeRepo{stats: stats, failTable: "graph_edges", optErr: errors.New("merge failed")}

	results, err := NewService(repo).Optimize(context.Background())

	require.ErrorContains(t, err, "Optimize: graph_edges:")
	require.ErrorContains(t, err, "merge failed")
	require.Len(t, results, len(OptimizableTables), "every table is still reported")
	require.Len(t, repo.optimized, len(OptimizableTables)-1,
		"the other five tables are compacted despite the failure")
	require.NotContains(t, repo.optimized, "graph_edges")

	byTable := resultsByTable(results)
	require.Error(t, byTable["graph_edges"].Err, "the failure is recorded on its own table")
	for _, tbl := range OptimizableTables {
		if tbl != "graph_edges" {
			require.NoError(t, byTable[tbl].Err)
		}
	}
}

// A stats read that fails is the same story: record it, keep walking.
func TestOptimizeContinuesPastAFailingStatsRead(t *testing.T) {
	stats := map[string]TableStats{}
	for _, tbl := range OptimizableTables {
		stats[tbl] = TableStats{BaseBytes: 1 << 20, BaseUncompressedBytes: 8 << 20, ActiveParts: 2}
	}
	repo := &fakeOptimizeRepo{stats: stats, statsErrTable: "beliefs"}

	results, err := NewService(repo).Optimize(context.Background())

	require.ErrorContains(t, err, "Optimize: beliefs:")
	require.Len(t, results, len(OptimizableTables))
	require.Len(t, repo.optimized, len(OptimizableTables)-1)
	require.NotContains(t, repo.optimized, "beliefs")
}

// Both failures are surfaced, not just the first: errors.Join, not first-error.
func TestOptimizeJoinsEveryTableError(t *testing.T) {
	stats := map[string]TableStats{}
	for _, tbl := range OptimizableTables {
		stats[tbl] = TableStats{BaseBytes: 1 << 20, BaseUncompressedBytes: 8 << 20, ActiveParts: 2}
	}
	repo := &fakeOptimizeRepo{
		stats: stats, statsErrTable: "beliefs", failTable: "signals", optErr: errors.New("merge failed"),
	}

	_, err := NewService(repo).Optimize(context.Background())

	require.ErrorContains(t, err, "beliefs")
	require.ErrorContains(t, err, "signals")
}

// An expired pass budget must stop the walk AND say so. A truncated pass that
// returns nil is indistinguishable from a clean one.
func TestOptimizeReportsAnExhaustedBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := NewService(&fakeOptimizeRepo{stats: map[string]TableStats{}}).Optimize(ctx)

	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "budget spent before")
	require.Empty(t, results)
}

// The rotation offset: pure, total, and in range for every input. Without it the
// pass walks a fixed list under a shared budget, so whenever the budget runs
// short the SAME tail is starved on every pass forever — the alphabetical
// starvation this changeset just fixed in bulkEdgesQ, with `assets` at the tail.
func TestRotationOffset(t *testing.T) {
	require.Equal(t, 0, rotationOffset(time.Now(), 0), "n<=0 must not divide by zero")
	require.Equal(t, 0, rotationOffset(time.Now(), -3))

	epoch := time.Unix(0, 0).UTC()
	n := len(OptimizableTables)
	seen := map[int]bool{}
	for i := range n * 2 {
		at := epoch.Add(time.Duration(i) * OptimizeRotationPeriod)
		off := rotationOffset(at, n)
		require.GreaterOrEqual(t, off, 0)
		require.Less(t, off, n)
		seen[off] = true
	}
	require.Len(t, seen, n, "a full rotation must visit every start position")

	// Consecutive periods advance by exactly one; within a period it is stable.
	require.Equal(t, 1, rotationOffset(epoch.Add(OptimizeRotationPeriod), n))
	require.Equal(t, 1, rotationOffset(epoch.Add(OptimizeRotationPeriod+time.Hour), n))

	// Negative (pre-epoch) instants must still land in range, not go negative.
	require.GreaterOrEqual(t, rotationOffset(epoch.Add(-3*OptimizeRotationPeriod), n), 0)
}

// rotate preserves the whole set — a rotation that dropped or duplicated a table
// would silently stop compacting it.
func TestRotate(t *testing.T) {
	require.Nil(t, rotate(nil, 3))
	for off := range len(OptimizableTables) + 2 {
		got := rotate(OptimizableTables, off)
		require.ElementsMatch(t, OptimizableTables, got, "offset %d dropped or duplicated a table", off)
	}
	require.Equal(t, []string{"c", "a", "b"}, rotate([]string{"a", "b", "c"}, 2))
	require.Equal(t, []string{"a", "b", "c"}, rotate([]string{"a", "b", "c"}, 3), "wraps")

	// The input must not be mutated: OptimizableTables is package state read by
	// everything else.
	before := append([]string(nil), OptimizableTables...)
	_ = rotate(OptimizableTables, 4)
	require.Equal(t, before, OptimizableTables)
}

// `assets` is the table the job is NAMED for and it sits last in the list. Under
// a fixed walk order it is the first thing a short budget starves; rotation is
// what stops that from being permanent.
func TestEveryTableEventuallyGoesFirst(t *testing.T) {
	first := map[string]bool{}
	for i := range len(OptimizableTables) {
		order := rotate(OptimizableTables, i)
		first[order[0]] = true
	}
	require.Len(t, first, len(OptimizableTables))
	require.True(t, first["assets"], "the table this job is named for must reach the front")
}

// Every ClickHouse call in this file must carry its OWN deadline (CLAUDE.md).
//
// OptimizeTable was the one method that did not, and it is the one that needed it
// most: none of the optimizable tables has a PARTITION BY, so `OPTIMIZE … FINAL`
// merges the entire table in a single statement with no incremental unit. Its
// only bound used to be the job's whole 30-minute pass budget, shared across six
// tables — so one slow table consumed the pass and the rest were never reached.
//
// Parsed from the AST rather than asserted by hand so a NEW repo method added
// here cannot quietly skip it.
func TestEveryCHRepoMethodInThisFileHasAPerQueryTimeout(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "optimize.go", nil, 0)
	require.NoError(t, err)

	var checked []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if id, ok := star.X.(*ast.Ident); !ok || id.Name != "CHRepo" {
			continue
		}

		var body strings.Builder
		require.NoError(t, printer.Fprint(&body, fset, fn.Body))
		require.Containsf(t, body.String(), "context.WithTimeout",
			"CHRepo.%s issues a ClickHouse query with no deadline of its own", fn.Name.Name)
		checked = append(checked, fn.Name.Name)
	}
	require.Subset(t, checked, []string{"LiveIDs", "TypeHighWater", "TableStats", "OptimizeTable"})
}

// The client-side deadline frees this pod's ClickHouse semaphore slot; it does
// NOT reliably stop the server merging. max_execution_time does, and without it a
// wedged merge keeps burning CPU on a possibly already CPU-constrained instance
// long after the job gave up.
func TestOptimizeTableBoundsTheServerToo(t *testing.T) {
	src, err := os.ReadFile("optimize.go")
	require.NoError(t, err)
	body := string(src)

	start := strings.Index(body, "func (r *CHRepo) OptimizeTable(")
	require.Positive(t, start)
	end := strings.Index(body[start+1:], "\nfunc ")
	require.Positive(t, end)
	fn := body[start : start+1+end]

	require.Contains(t, fn, "max_execution_time",
		"a client-side cancel does not stop a running OPTIMIZE server-side")
	require.Contains(t, fn, "OptimizeTableTimeout",
		"both bounds must come from the same constant or they drift apart")
}

// The size guard, the per-table bound and the ceiling have to agree with each
// other: 8 GiB uncompressed at ~100-300 MB/s of merge throughput is on the order
// of a minute, which OptimizeTableTimeout must cover with headroom.
func TestOptimizeBudgetsAreConsistent(t *testing.T) {
	require.Equal(t, uint64(8<<30), uint64(OptimizeMaxUncompressedBytes))
	require.GreaterOrEqual(t, OptimizeTableTimeout, time.Minute,
		"a merge of the largest permitted table must fit inside its own bound")
	require.Positive(t, OptimizeRotationPeriod)
}

// The merge-cost policy explains why this
// package reads `assets FINAL`, and it has now been WRONG twice in opposite
// directions: first claiming an optimizeAssets job existed when none did, then
// claiming the job "deliberately SKIPS assets" in the same diff that added
// assets to OptimizableTables. Both were plausible prose next to code that said
// otherwise. Pin the one fact the comment must not contradict.
func TestRepoCommentDoesNotContradictOptimizableTables(t *testing.T) {
	src, err := os.ReadFile("repo.go")
	require.NoError(t, err)
	body := string(src)

	optimizesAssets := false
	for _, tbl := range OptimizableTables {
		if tbl == "assets" {
			optimizesAssets = true
		}
	}
	require.True(t, optimizesAssets, "this test is written for the list that includes assets")

	for _, claim := range []string{"SKIPS assets", "skips assets", "never optimizes assets"} {
		require.NotContainsf(t, body, claim,
			"repo.go claims %q while OptimizableTables includes assets", claim)
	}
}
