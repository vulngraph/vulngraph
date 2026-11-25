package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// SourceActivity is one finding source's production recency: the newest
// last_observed_at across its findings, in Unix seconds, or 0 for a source
// that is expected to produce but never has. Mirrors obs.SourceActivityStat —
// this is its ClickHouse-side precursor.
type SourceActivity struct {
	Source           string
	LastActivityUnix int64
}

// ExpectedActivitySources are the platform's automated, continuously-producing
// finding sources — the ones it is meaningful to page on if they go dark. This
// is deliberately NOT "every source this tree can declare"
// (coverage.DeclaredSources, an AST scan of .go files that cmd/coverage-gen
// runs offline; the production image ships only the compiled binary, no
// source tree, so it cannot be called from here) and it deliberately excludes
// sources that have no production SLA to alert on, such as
// openvas, qualys, burp and custom (scan.validImportSources): human-triggered
// external-scanner imports. Nobody importing a scan for months is normal, not
// a failure — there is no cadence to be dark against.
//
// A hand-kept list is exactly the artefact internal/app/coverage's own doc
// comment warns drifts silently — TestExpectedActivitySourcesAccountsForEveryDeclaredSource
// (source_activity_coverage_test.go, an external finding_test package: coverage
// transitively imports finding via enrich, so the guard can't live in-package
// without a cycle) keeps this one honest by failing when a source
// coverage.DeclaredSources finds isn't accounted for here one way or the
// other, so adding a new automated producer without a conscious decision here
// breaks the build instead of silently staying invisible to
// GraphFindingSourceDark.
var ExpectedActivitySources = []string{
	"cspm",
	"supply_chain",
	"aws_guardduty",
	"ghas_code_scanning",
	"ghas_secrets",
	"nuclei",
	"gcp_scc",
	"iac",
	"iac_terraform",
	"ci_access",
}

// ExcludedActivitySources is the other half of the conscious-decision pair
// TestExpectedActivitySourcesAccountsForEveryDeclaredSource enforces: every
// source coverage.DeclaredSources finds in the tree must be named in exactly
// one of ExpectedActivitySources or here, with the reason it has no
// darkness-alerting SLA. A source appearing in neither fails that test loudly
// instead of silently never reaching GraphFindingSourceDark. Exported (not
// just used internally) because the guard test that reads it lives in an
// external finding_test package to avoid the coverage->enrich->finding cycle.
var ExcludedActivitySources = map[string]string{
	"openvas": "human-triggered scan import (scan.validImportSources) — no periodicity to be dark against",
	"qualys":  "human-triggered scan import (scan.validImportSources) — no periodicity to be dark against",
	"burp":    "human-triggered scan import (scan.validImportSources) — no periodicity to be dark against",
	"custom":  "human-triggered scan import (scan.validImportSources) — no periodicity to be dark against",
	"vm_vuln": "derived VM fleet CVEs (internal/jobs/vmvuln.go) — silent by construction in any estate with no " +
		"SSM/OS Config inventory or no vulnerable VM package; inventory liveness is the package_inventory stamp's job, not a dark-source alert",
	"base_image": "derived container base-image findings (internal/jobs/baseimage.go) — silent by construction in any estate whose " +
		"running images are all on supported, CVE-free bases; identification coverage is graph_base_image_running_images' job, not a dark-source alert",
}

// sourceActivityQ is the newest last_observed_at per source that has ever
// produced a finding. Unlike mustFixCoverageBySource/checkQualityQ this needs
// no inner argMax-by-id dedup: those pick a field that represents CURRENT
// state (resolved_at, must_fix_class) off the right ReplacingMergeTree row
// version, but an older row-version of a finding can never carry a LARGER
// last_observed_at than its current version — every producer only ever moves
// it forward (Service.RecordObserved stamps `now`) — so a plain MAX across
// every row-version already gives the right answer. No FINAL, no
// filtered-FINAL full scan (CLAUDE.md).
//
// No resolved_at filter either: "is this source still running" doesn't care
// whether the specific finding it last touched is open or resolved — a
// resolved finding's last_observed_at still proves the source was alive then.
//
// Sources with zero findings at all have no row here and are not this
// query's job to report — see ExpectedActivitySources and mergeExpectedSources.
const sourceActivityQ = `SELECT source, max(last_observed_at) AS last_observed
	FROM findings
	GROUP BY source`

// sourceActivityTimeout must stay at or below obs.scrapeBudget (8s): the
// scrape wraps every source's read in one shared context.WithTimeout, and
// nesting keeps the EARLIER deadline, so a longer value here would never
// actually apply — see CheckQualityTimeout's neighboring comment for the
// same constraint.
const sourceActivityTimeout = 8 * time.Second

// SourceActivity returns the newest last_observed_at for every source that has
// ever produced at least one finding. It does NOT include a zero-row expected
// source — merging those in is mergeExpectedSources' job, called from
// Service.SourceActivity below, so this method (like its CHRepo siblings)
// stays a direct reflection of what ClickHouse actually holds.
func (r *CHRepo) SourceActivity(ctx context.Context) ([]SourceActivity, error) {
	qCtx, cancel := context.WithTimeout(ctx, sourceActivityTimeout)
	defer cancel()

	var out []SourceActivity
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				source       string
				lastObserved time.Time
			)
			if err := rows.Scan(&source, &lastObserved); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			// last_observed_at DEFAULT 0 is the ClickHouse DateTime zero value,
			// which IS the Unix epoch — .Unix() already reports 0 for it with no
			// IsZero special-casing needed.
			out = append(out, SourceActivity{Source: source, LastActivityUnix: lastObserved.Unix()})
		}
		return rows.Err()
	}, sourceActivityQ)
	if err != nil {
		return nil, fmt.Errorf("SourceActivity: %w", err)
	}
	return out, nil
}

// mergeExpectedSources is the Go-side "LEFT JOIN" ClickHouse's GROUP BY can't
// express: ZERO IS A FINDING (obs.SourceActivityStat's doc comment) — a source
// that has never produced anything has no row in live to aggregate over, and
// omitting it here is indistinguishable from omitting it because it isn't
// expected at all. Seed a map from expected, overlay live on top, so a
// zero-finding expected source still reports LastActivityUnix: 0 instead of
// vanishing from the series set. Any live source NOT in expected (a check that
// isn't in ExpectedActivitySources yet) is kept too, never dropped — this
// merge only ever adds rows, never hides real activity.
//
// Same shape as internal/app/coverage/service.go's sourceFacts, which solves
// the identical "enumerate every expected X even with zero rows" problem for
// the offline coverage-gen report; this is that pattern's live-metrics twin.
func mergeExpectedSources(live []SourceActivity, expected []string) []SourceActivity {
	bySource := make(map[string]SourceActivity, len(expected)+len(live))
	for _, s := range expected {
		bySource[s] = SourceActivity{Source: s}
	}
	for _, sa := range live {
		bySource[sa.Source] = sa
	}
	out := make([]SourceActivity, 0, len(bySource))
	for _, sa := range bySource {
		out = append(out, sa)
	}
	return out
}

// SourceActivity reports, per expected source (see ExpectedActivitySources),
// the newest last_observed_at across its findings — the direct "did this
// source run?" signal behind graph_source_last_activity_timestamp_seconds and
// the GraphFindingSourceDark alert. A source with zero findings at all reports
// LastActivityUnix: 0, not an omitted row, which is what lets the alert catch
// a source that has NEVER run as loudly as one that stopped.
func (s *Service) SourceActivity(ctx context.Context) ([]SourceActivity, error) {
	live, err := s.repo.SourceActivity(ctx)
	if err != nil {
		return nil, fmt.Errorf("SourceActivity: %w", err)
	}
	return mergeExpectedSources(live, ExpectedActivitySources), nil
}
