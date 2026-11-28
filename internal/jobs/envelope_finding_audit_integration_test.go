//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// This oracle derives its entire expected set from fixture inputs, never from
// completed jobs, observed Enrich calls, or the rows returned by the database.
const envelopeFindingFactorsQ = `SELECT id,argMax(factors,synced_at) FROM signals WHERE id IN (%s) GROUP BY id`

type envelopeFreshnessAudit struct {
	Phase    string    `json:"phase"`
	Wave     int       `json:"wave"`
	At       time.Time `json:"at"`
	Expected int       `json:"expected_active_findings"`
	Matched  int       `json:"matching_static_factors"`
	Missing  int       `json:"missing_signals"`
	Stale    int       `json:"stale_or_invalid_factors"`
	Sample   []string  `json:"missing_or_stale_sample"`
	Queries  int       `json:"source_queries"`
	Complete bool      `json:"audit_complete"`
	Error    string    `json:"error,omitempty"`
}

func envelopeAuditFreshness(ctx context.Context, ch *db.CH, sizes []int, scopes []envelopeScope, wave int, phase string) (audit envelopeFreshnessAudit, resultErr error) {
	audit = envelopeFreshnessAudit{Phase: phase, Wave: wave, At: time.Now().UTC()}
	defer func() {
		if resultErr != nil {
			audit.Error = resultErr.Error()
		}
	}()
	points := 30
	if wave >= 2 {
		points = 40
	}
	ids := make([]string, 0, 500)
	sample := func(id string) {
		if len(audit.Sample) < 20 {
			audit.Sample = append(audit.Sample, id)
		}
	}
	read := func() error {
		wanted := make(map[string]bool, len(ids))
		for _, id := range ids {
			wanted[id] = true
		}
		placeholders, args := dbutil.CHIn(ids)
		qctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		qctx = ch.WithQuerySettings(qctx, map[string]any{"log_comment": "envelope-all-finding-oracle"})
		audit.Queries++
		err := ch.Select(qctx, func(rows driver.Rows) error {
			for rows.Next() {
				var id, factors string
				if err := rows.Scan(&id, &factors); err != nil {
					return err
				}
				if !wanted[id] {
					return fmt.Errorf("unexpected or duplicate signal %q", id)
				}
				delete(wanted, id)
				if envelopeBaseFactorMatches(factors, points) {
					audit.Matched++
				} else {
					audit.Stale++
					sample(id)
				}
			}
			return rows.Err()
		}, fmt.Sprintf(envelopeFindingFactorsQ, placeholders), args...)
		if err != nil {
			return fmt.Errorf("read expected finding factors: %w", err)
		}
		for _, id := range ids {
			if wanted[id] {
				audit.Missing++
				sample(id)
			}
		}
		ids = ids[:0]
		return nil
	}
	for c, n := range sizes {
		for i := 1; i < n; i += 100 {
			// Confirmed retirement resolves this finding; other oracles verify that
			// lifecycle. It is not an active finding awaiting a fresh score.
			if wave == 4 && i == 1 {
				continue
			}
			resource := envelopeID(c, i)
			if scopes[c].Kind == "kubernetes" {
				resource = fmt.Sprintf("synthetic-cluster-%04d/pod/workloads/%s", c, resource)
			}
			ids = append(ids, "finding-"+resource)
			audit.Expected++
			if len(ids) == 500 {
				if err := read(); err != nil {
					return audit, err
				}
			}
		}
	}
	if len(ids) > 0 {
		if err := read(); err != nil {
			return audit, err
		}
	}
	audit.Complete = true
	return audit, nil
}

func envelopeBaseFactorMatches(raw string, points int) bool {
	var factors []enrich.Factor
	if json.Unmarshal([]byte(raw), &factors) != nil {
		return false
	}
	count := 0
	for _, factor := range factors {
		if factor.Source == "base_severity" {
			count++
			if factor.Points != points {
				return false
			}
		}
	}
	return count == 1
}

func envelopeWaitFreshness(ctx context.Context, ch *db.CH, sizes []int, scopes []envelopeScope, wave int, deadline time.Time, report *envelopeReport, trace *envelopeTrace) error {
	// This is a diagnostic wait ceiling, not a claim that the constrained local
	// hardware satisfies any published capacity profile. No accelerated ticks.
	waitCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	started := time.Now()
	for {
		audit, err := envelopeAuditFreshness(waitCtx, ch, sizes, scopes, wave, "periodic_freshness_wait")
		report.Freshness = append(report.Freshness, audit)
		trace.write(map[string]any{"event": "all_finding_freshness", "audit": audit, "wait_seconds": time.Since(started).Seconds(), "diagnostic_deadline": deadline})
		if err != nil {
			return err
		}
		if audit.Expected == audit.Matched {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("ordinary periodic enrichment did not repair all expected findings: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func TestEnvelopeFreshnessRejectsMissingStaleAndDuplicateFactors(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      bool
	}{
		{"current", `[{"source":"base_severity","points":40}]`, true},
		{"stale", `[{"source":"base_severity","points":30}]`, false},
		{"missing", `[{"source":"exposure","points":40}]`, false},
		{"duplicate", `[{"source":"base_severity","points":40},{"source":"base_severity","points":40}]`, false},
		{"malformed", `{`, false},
		{"null", `null`, false},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.want, envelopeBaseFactorMatches(tc.raw, 40)) })
	}
}

func TestEnvelopeFreshnessAuditFindsUnqueuedChangedAndMissingIDs(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("requires disposable envelope databases")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	ch, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	findings := finding.NewService(finding.NewCHRepo(ch))
	scorer := enrich.NewService(findings, enrich.NewSignalCHRepo(ch), []enrich.Source{enrich.BaseSeverity{}})
	sizes := []int{202, 102, 102}
	scopes := []envelopeScope{{Kind: "aws"}, {Kind: "gcp"}, {Kind: "kubernetes"}}
	var rows []finding.Finding
	for c, n := range sizes {
		for i := 1; i < n; i += 100 {
			resource := envelopeID(c, i)
			if scopes[c].Kind == "kubernetes" {
				resource = fmt.Sprintf("synthetic-cluster-%04d/pod/workloads/%s", c, resource)
			}
			rows = append(rows, finding.Finding{ID: "finding-" + resource, ResourceID: resource, Source: "envelope_provider", Severity: finding.SeverityHigh})
		}
	}
	require.Len(t, rows, 7)
	require.NoError(t, findings.RecordObserved(ctx, rows))
	// One expected ID has no enrichment job or signal at all. Six are scored at
	// the old severity, then their observations change without scoring jobs.
	for _, f := range rows[:6] {
		_, err = scorer.Enrich(ctx, f)
		require.NoError(t, err)
	}
	for i := range rows {
		rows[i].Severity = finding.SeverityCritical
	}
	require.NoError(t, findings.RecordObserved(ctx, rows))
	stale, err := envelopeAuditFreshness(ctx, ch, sizes, scopes, 2, "changed_without_jobs")
	require.NoError(t, err)
	require.True(t, stale.Complete)
	require.Equal(t, 7, stale.Expected)
	require.Zero(t, stale.Matched)
	require.Equal(t, 6, stale.Stale)
	require.Equal(t, 1, stale.Missing)
	for _, f := range rows {
		_, err = scorer.Enrich(ctx, f)
		require.NoError(t, err)
	}
	repaired, err := envelopeAuditFreshness(ctx, ch, sizes, scopes, 2, "after_explicit_replay")
	require.NoError(t, err)
	require.Equal(t, 7, repaired.Matched)
	require.Zero(t, repaired.Stale+repaired.Missing)
	retired, err := envelopeAuditFreshness(ctx, ch, sizes, scopes, 4, "confirmed_retirement_expected_set")
	require.NoError(t, err)
	require.Equal(t, 4, retired.Expected)
	require.Equal(t, 4, retired.Matched)
	data, err := json.MarshalIndent(map[string]any{"stale": stale, "repaired": repaired, "retirement_scope": retired, "scope": "oracle replay only; explicit scoring does not measure scheduler freshness"}, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "expected-finding-audit-replay.json"), data, 0600))
}

const envelopeEnrichScheduleQ = `SELECT
 count(*) FILTER (WHERE kind='enrich' AND state IN ('available','pending','running','retryable','scheduled')),
 count(*) FILTER (WHERE kind='enrich_sweep' AND (state='running' OR (state IN ('available','pending','retryable') AND scheduled_at<=now()))),
 min(scheduled_at) FILTER (WHERE kind='enrich_sweep' AND state IN ('available','pending','retryable','scheduled') AND coalesce(args->>'backfill_only','false')='false')
 FROM river_job WHERE kind IN ('enrich','enrich_sweep')`

func envelopeFreshnessFeasibility(ctx context.Context, pool *pgxpool.Pool, progress SweepProgressStore, audit envelopeFreshnessAudit, deadline time.Time) (map[string]any, error) {
	var pending, activeSweeps int
	var next *time.Time
	if err := pool.QueryRow(ctx, envelopeEnrichScheduleQ).Scan(&pending, &activeSweeps, &next); err != nil {
		return nil, err
	}
	checkpoint, err := progress.GetSweepProgress(ctx)
	if err != nil {
		return nil, err
	}
	// Counting every queued scoring job as useful is deliberately optimistic.
	// Missing signals can use backfill; this lower bound uses stale existing ones.
	deferred := max(0, audit.Stale-pending)
	executions := (deferred + enrichSweepMax - 1) / enrichSweepMax
	out := map[string]any{"observed_stale_factors": audit.Stale, "pending_scoring_jobs": pending, "active_sweeps": activeSweeps,
		"optimistic_deferred_existing_findings": deferred, "minimum_future_executions": executions, "next_sweep_scheduled_at": next,
		"enumeration_checkpoint": checkpoint, "diagnostic_deadline": deadline, "continuation_delay_seconds": enrichSweepContinuationDelay.Seconds(),
		"qualification": "lower bound assumes every execution uses its full budget on these stale IDs and may continue; cache hits, backpressure, query and scoring time add delay; updates behind the cursor may need the next ordinary pass"}
	if executions > 0 && next != nil && activeSweeps == 0 {
		earliest := next.Add(time.Duration(executions-1) * enrichSweepContinuationDelay)
		out["optimistic_last_admission_at"] = earliest
		if earliest.After(deadline) {
			return out, fmt.Errorf("enrichment schedule alone exceeds declared diagnostic freshness window: at least %d future executions, last admission no earlier than %s", executions, earliest.Format(time.RFC3339))
		}
	}
	return out, nil
}
