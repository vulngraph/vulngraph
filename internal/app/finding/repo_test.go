package finding

import (
	"strings"
	"testing"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// enrichmentOutputColumns are the ten columns finding_enrichment owns
// exclusively (RecordEnrichment/UpsertEnrichment,
// repo_enrichment.go). insertFindings (the producer/lifecycle write path —
// Record, RecordObserved, Resolve) must never carry any of them again: a
// column added back here would silently resurrect the
// lost-update race the whole split exists to close, because ClickHouse's
// ReplacingMergeTree would then have two independent full-row writers
// racing over that column's version again.
var enrichmentOutputColumns = []string{
	"score", "score_band", "enriched_at", "known_exploited",
	"dependents", "unused", "safety_class", "fix_target",
	"must_fix_class", "must_fix_reason",
}

// TestInsertFindingsOmitsEnrichmentColumns pins the structural invariant the
// writer cutover depends on: insertFindings' column list contains none of the
// ten enrich:"output" columns. They are not columns of `findings`, so a
// regression fails loudly at the ClickHouse driver; this catches it before
// that. finding_enrichment is the only home for enrichment output, so the
// column list must never gain one of the ten.
func TestInsertFindingsOmitsEnrichmentColumns(t *testing.T) {
	for _, col := range enrichmentOutputColumns {
		if containsWord(insertFindings, col) {
			t.Errorf("insertFindings must not reference enrichment column %q — "+
				"finding_enrichment (UpsertEnrichment) is its only writer, "+
				"and the column no longer exists on findings at all", col)
		}
	}
}

// TestBatchReadTimeoutIsTheDerivedValue guards batchReadTimeout against being
// edited to a number nobody re-derived. 60s comes from the arithmetic in its
// own doc comment (jobs.DanglingSweepWorker's 5-minute Timeout comfortably
// absorbing the documented 27-120s correlate contention windows; the HTTP
// request path's 60s WriteTimeout now closed by httpsrv's withDeadline
// middleware) — a change here needs that arithmetic redone, not a bigger
// round number. jobs.TestDanglingSweep* (internal/jobs/dangling_test.go) pins
// the other half: that this value still fits DanglingSweepWorker's own
// Timeout and page-count budget.
func TestBatchReadTimeoutIsTheDerivedValue(t *testing.T) {
	if batchReadTimeout != 60*time.Second {
		t.Fatalf("batchReadTimeout = %v, want 60s — see its doc comment for the arithmetic "+
			"this value is derived from before changing it", batchReadTimeout)
	}
}

// containsWord reports whether needle appears in haystack as a column-name
// token (surrounded by non-identifier characters), so e.g. "unused" does not
// false-positive match inside a longer identifier.
func containsWord(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] != needle {
			continue
		}
		beforeOK := i == 0 || !isIdentByte(haystack[i-1])
		afterOK := i+len(needle) == len(haystack) || !isIdentByte(haystack[i+len(needle)])
		if beforeOK && afterOK {
			return true
		}
	}
	return false
}

func isIdentByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// TestDistinctCheckIDsEmbedsEphemeralLivenessCond pins that distinctCheckIDs
// reuses asset.EphemeralLivenessCond VERBATIM rather than a second, drifted
// copy of it — the single-definition discipline this design requires. A future
// edit that inlines its own liveness arithmetic instead of importing the
// shared const would compile fine and fail only at runtime, silently.
func TestDistinctCheckIDsEmbedsEphemeralLivenessCond(t *testing.T) {
	if !strings.Contains(distinctCheckIDs, asset.EphemeralLivenessCond) {
		t.Fatal("distinctCheckIDs must embed asset.EphemeralLivenessCond verbatim, not a re-derived condition")
	}
}

// TestDistinctCheckIDsNeverExcludesOnMissingAssetRow pins the
// unmeasured-is-not-zero shape of the query (see distinctCheckIDs' doc comment, state 3): the corpses
// subquery it filters resource_id against can only ever contain ids that
// MATCHED a real assets row — the same "absent from the result, not present as
// false" contract asset.VerifyExpiredEphemeral documents. A query missing this
// property could satisfy a naive smoke test yet still let an id with no assets
// row at all silently drop a check_id.
func TestDistinctCheckIDsNeverExcludesOnMissingAssetRow(t *testing.T) {
	if !strings.Contains(distinctCheckIDs, "resource_id = '' OR resource_id NOT IN") {
		t.Fatal("distinctCheckIDs must keep a finding with no resolvable asset row (blank or unmatched " +
			"resource_id) as evidence — only a MATCHED, verified-dead row may be excluded")
	}
}
