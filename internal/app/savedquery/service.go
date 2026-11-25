package savedquery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"

	"github.com/vulngraph/vulngraph/internal/graphquery"
	"github.com/vulngraph/vulngraph/pkg/cronexpr"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// repo is the storage surface the service depends on.
type repo interface {
	Create(ctx context.Context, q SavedQuery) (SavedQuery, error)
	Update(ctx context.Context, q SavedQuery) (SavedQuery, error)
	Delete(ctx context.Context, id string) error
	Get(ctx context.Context, id string) (SavedQuery, error)
	List(ctx context.Context) ([]SavedQuery, error)
	ListScheduled(ctx context.Context) ([]SavedQuery, error)
	// RecordRun appends run to the history. advanceBaseline also moves the
	// query's last_* summary (the change-detection baseline) to this run.
	RecordRun(ctx context.Context, run Run, advanceBaseline bool) error
	ListRuns(ctx context.Context, queryID string, limit int) ([]Run, error)
}

// QueryResult is the minimal projection the service needs to count + hash a
// Cypher result for change detection — decoupled from explore/graphstore types.
type QueryResult struct {
	NodeIDs  []string
	EdgeKeys []string // "src|edge_type|dst"
	// Rows are the scalar/tabular rows (RETURN count(...)), each in a canonical
	// encoding, so a changed aggregate reads as a changed result.
	Rows []string
	// Truncated: the runner cut the result at its budget; the projection is
	// partial and its hash says nothing about the full result set.
	Truncated bool
	// MultiHopMayBeIncomplete: the graph engine flagged the result
	// (ErrMultiHopMayBeIncomplete).
	MultiHopMayBeIncomplete bool
}

// CypherRunner executes read-only Cypher and returns the result projection.
// An adapter in the worker/serve wires this to graphstore/explore RunCypher.
type CypherRunner interface {
	RunForSavedQuery(ctx context.Context, cypher string) (QueryResult, error)
}

// Alerter delivers a change notification. *notify.Service is adapted to it at
// the call site so savedquery stays decoupled from the notify domain. A non-nil
// error means no channel received the alert; the run then keeps the old
// baseline so the next scheduled run retries — except ErrAlertNoRecipients,
// where routing chose nobody and there is nothing to retry.
type Alerter interface {
	AlertQueryChange(ctx context.Context, q SavedQuery, nodeCount, prevCount int) error
}

// AuditRecorder writes the audit_events row of a change that has taken
// effect (audit.Service).
type AuditRecorder interface {
	Record(ctx context.Context, action, targetType, targetID string, details map[string]any)
}

// Service manages saved queries and executes them (manual or scheduled).
type Service struct {
	repo    repo
	runner  CypherRunner  // nil = execution disabled (CRUD still works)
	alerter Alerter       // nil = no alerting
	ready   func() bool   // nil = always ready; else gates Run on graph readiness
	audit   AuditRecorder // nil = no audit rows (tests, the worker)
}

func NewService(r repo) *Service { return &Service{repo: r} }

// WithAudit records saved-query creates, updates and deletes in audit_events:
// a saved query is a detection, and editing or deleting one silences it.
func (s *Service) WithAudit(a AuditRecorder) *Service { s.audit = a; return s }

func (s *Service) record(ctx context.Context, action, id string, details map[string]any) {
	if s.audit != nil {
		s.audit.Record(ctx, action, AuditTargetSavedQuery, id, details)
	}
}

// auditView is what an audit row keeps of a saved query's definition.
func auditView(q SavedQuery) map[string]any {
	return map[string]any{
		"name": q.Name, "cypher": q.Cypher, "schedule": q.Schedule, "enabled": q.Enabled,
		"alert_on_change": q.AlertOnChange, "alert_severity": q.AlertSeverity, "alert_channel_ids": q.AlertChannelIDs,
	}
}

// WithRunner enables query execution (Run / RunScheduled).
func (s *Service) WithRunner(r CypherRunner) *Service { s.runner = r; return s }

// WithAlerter enables change alerting on scheduled runs.
func (s *Service) WithAlerter(a Alerter) *Service { s.alerter = a; return s }

// WithReadiness gates execution on the graph being ready+non-empty. When the
// graph is rebuilding/empty (deploy window), a saved query would return an empty
// result whose hash differs from the last full result — recording it corrupts the
// baseline and, worse, the recovery run reads as a change and fires a FALSE
// "drift detected" alert. Gating skips the run entirely (no record, no alert) so
// detection-as-code is trustworthy across deploys.
func (s *Service) WithReadiness(fn func() bool) *Service { s.ready = fn; return s }

// ── CRUD ─────────────────────────────────────────────────────────────────────

func (s *Service) Create(ctx context.Context, q SavedQuery) (SavedQuery, error) {
	if strings.TrimSpace(q.Name) == "" {
		return SavedQuery{}, ErrMissingName
	}
	if strings.TrimSpace(q.Cypher) == "" {
		return SavedQuery{}, ErrEmptyCypher
	}
	if !graphquery.IsReadOnly(q.Cypher) {
		return SavedQuery{}, ErrWriteQuery
	}
	if err := ScheduleError(q.Schedule); err != nil {
		return SavedQuery{}, err
	}
	q, err := withSeverity(q)
	if err != nil {
		return SavedQuery{}, err
	}
	created, err := s.repo.Create(ctx, q)
	if err != nil {
		return SavedQuery{}, fmt.Errorf("Create: %w", err)
	}
	s.record(ctx, AuditActionCreate, created.ID, auditView(created))
	return created, nil
}

func (s *Service) Update(ctx context.Context, q SavedQuery) (SavedQuery, error) {
	if strings.TrimSpace(q.Name) == "" {
		return SavedQuery{}, ErrMissingName
	}
	// Reject empty Cypher like Create does, with its own error, before the
	// read-only check — otherwise an Update could blank out a detection's query.
	if strings.TrimSpace(q.Cypher) == "" {
		return SavedQuery{}, ErrEmptyCypher
	}
	if !graphquery.IsReadOnly(q.Cypher) {
		return SavedQuery{}, ErrWriteQuery
	}
	if err := ScheduleError(q.Schedule); err != nil {
		return SavedQuery{}, err
	}
	q, err := withSeverity(q)
	if err != nil {
		return SavedQuery{}, err
	}
	before, err := s.repo.Get(ctx, q.ID)
	if err != nil {
		return SavedQuery{}, fmt.Errorf("Update: %w", err)
	}
	updated, err := s.repo.Update(ctx, q)
	if err != nil {
		return SavedQuery{}, fmt.Errorf("Update: %w", err)
	}
	s.record(ctx, AuditActionUpdate, updated.ID, map[string]any{"before": auditView(before), "after": auditView(updated)})
	return updated, nil
}

// ScheduleError reports why a non-empty schedule can never fire, or nil when
// it is empty (manual only) or a valid cron expression. Validation runs at the
// API, not in the database, so a stored row can still hold an invalid one; the
// API surfaces this error on it rather than letting the detection silently
// never run.
func ScheduleError(schedule string) error {
	if strings.TrimSpace(schedule) == "" {
		return nil
	}
	if err := cronexpr.Validate(schedule); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSchedule, err)
	}
	return nil
}

// withSeverity defaults an empty alert severity and rejects an unknown one.
func withSeverity(q SavedQuery) (SavedQuery, error) {
	if q.AlertSeverity == "" {
		q.AlertSeverity = DefaultAlertSeverity
	}
	if !ValidSeverity(q.AlertSeverity) {
		return SavedQuery{}, ErrInvalidSeverity
	}
	return q, nil
}

// Delete removes a saved query; its audit row keeps the definition the
// delete destroyed.
func (s *Service) Delete(ctx context.Context, id string) error {
	before, err := s.repo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	s.record(ctx, AuditActionDelete, id, auditView(before))
	return nil
}
func (s *Service) Get(ctx context.Context, id string) (SavedQuery, error) {
	return s.repo.Get(ctx, id)
}
func (s *Service) List(ctx context.Context) ([]SavedQuery, error) { return s.repo.List(ctx) }
func (s *Service) ListRuns(ctx context.Context, id string, limit int) ([]Run, error) {
	return s.repo.ListRuns(ctx, id, limit)
}

// ── Execution ────────────────────────────────────────────────────────────────

// Run executes one saved query now and records the run in the history.
// trigger is TriggerManual or TriggerSchedule.
//
// Only a scheduled run moves the change-detection baseline, and only when it
// is a complete measurement whose change alert (if one was due) was delivered:
//   - a runner error or a truncated result is recorded as a failed run and
//     leaves the baseline alone, so the next good run still compares against
//     the last good result;
//   - an undelivered alert keeps the baseline, so the next run re-detects the
//     change and retries the alert;
//   - an alert no channel's routing accepts (ErrAlertNoRecipients) advances the
//     baseline with the reason on the run: retrying cannot reach anyone;
//   - a manual run is history only — it never alerts, so moving the baseline
//     would swallow the change the next scheduled run should have reported.
func (s *Service) Run(ctx context.Context, q SavedQuery, trigger string) (Run, error) {
	if s.runner == nil {
		return Run{}, fmt.Errorf("Run: cypher runner not configured")
	}
	// Skip when the graph isn't ready (deploy/rebuild window). Running against an
	// empty graph would record an empty-result baseline and fire a false drift
	// alert on recovery. No run is recorded — the next scheduled tick picks it up
	// once the graph is back. Treated as a clean skip by RunScheduled.
	if s.ready != nil && !s.ready() {
		return Run{}, ErrGraphNotReady
	}

	run := Run{SavedQueryID: q.ID, Trigger: trigger}
	res, err := s.runner.RunForSavedQuery(ctx, q.Cypher)
	if err != nil {
		run.Error = err.Error()
		return run, s.recordFailed(ctx, run, fmt.Errorf("Run: %w", err))
	}
	run.NodeCount = len(res.NodeIDs)
	run.EdgeCount = len(res.EdgeKeys)
	if res.Truncated {
		run.Error = ErrResultTruncated.Error()
		return run, s.recordFailed(ctx, run, fmt.Errorf("Run: %w", ErrResultTruncated))
	}
	run.ResultHash = hashResult(res)
	if res.MultiHopMayBeIncomplete {
		run.Error = ErrMultiHopMayBeIncomplete.Error()
	}

	if trigger != TriggerSchedule {
		if err := s.repo.RecordRun(ctx, run, false); err != nil {
			return run, fmt.Errorf("Run: record: %w", err)
		}
		return run, nil
	}

	// prevHash == "" is the first complete run — no baseline to compare, so no alert.
	prevHash := q.LastResultHash
	if q.AlertOnChange && s.alerter != nil && prevHash != "" && run.ResultHash != prevHash {
		err := s.alerter.AlertQueryChange(ctx, q, run.NodeCount, q.LastResultCount)
		switch {
		case errors.Is(err, ErrAlertNoRecipients):
			run.Error = appendRunError(run.Error, "change alert reached no channel, baseline advanced: "+err.Error())
			log.FromContext(ctx).Warn().Str("saved_query", q.ID).Str("name", q.Name).
				Msg("savedquery: change alert matched no channel's routing — nobody was told")
		case err != nil:
			run.Error = appendRunError(run.Error, "change alert not delivered, baseline kept: "+err.Error())
			return run, s.recordFailed(ctx, run, fmt.Errorf("Run: alert: %w", err))
		}
	}
	if err := s.repo.RecordRun(ctx, run, true); err != nil {
		return run, fmt.Errorf("Run: record: %w", err)
	}
	return run, nil
}

// recordFailed writes a failed run to the history without touching the
// baseline and returns cause, joined with the record error if that failed too.
func (s *Service) recordFailed(ctx context.Context, run Run, cause error) error {
	if err := s.repo.RecordRun(ctx, run, false); err != nil {
		return errors.Join(cause, fmt.Errorf("Run: record failed run: %w", err))
	}
	return cause
}

// RunScheduled executes every enabled, scheduled saved query that is due.
// dueFn decides whether a query's cron schedule fires at the current tick —
// injected so the cron evaluation lives in the jobs layer (with its scheduler).
// One query's failure never stops the sweep; each is logged with the query id
// (and recorded as a failed run by Run), and the return is how many succeeded.
func (s *Service) RunScheduled(ctx context.Context, dueFn func(schedule string) bool) (int, error) {
	queries, err := s.repo.ListScheduled(ctx)
	if err != nil {
		return 0, fmt.Errorf("RunScheduled: %w", err)
	}
	logger := log.FromContext(ctx)
	ran := 0
	for _, q := range queries {
		if err := ScheduleError(q.Schedule); err != nil {
			logger.Warn().Err(err).Str("saved_query_id", q.ID).Str("name", q.Name).
				Msg("scheduled saved query never runs: invalid schedule")
			continue
		}
		if dueFn != nil && !dueFn(q.Schedule) {
			continue
		}
		if _, err := s.Run(ctx, q, TriggerSchedule); err != nil {
			if errors.Is(err, ErrGraphNotReady) {
				logger.Info().Str("saved_query_id", q.ID).Msg("saved query skipped: graph not ready")
				continue
			}
			logger.Error().Err(err).Str("saved_query_id", q.ID).Str("name", q.Name).
				Msg("scheduled saved query failed")
			continue
		}
		ran++
	}
	return ran, nil
}

// hashResult produces a stable hash of the result set (sorted node IDs, edge
// keys and scalar rows) so re-ordering between runs doesn't read as a change.
// The rows section is written only when there are rows, so a graph-shaped
// result hashes exactly as it did before rows were hashed and existing
// baselines stay comparable.
func hashResult(res QueryResult) string {
	h := sha256.New()
	writeSorted(h, res.NodeIDs)
	h.Write([]byte{1})
	writeSorted(h, res.EdgeKeys)
	if len(res.Rows) > 0 {
		h.Write([]byte{1})
		writeSorted(h, res.Rows)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeSorted(h hash.Hash, vals []string) {
	sorted := append([]string(nil), vals...)
	sort.Strings(sorted)
	for _, v := range sorted {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
}

// appendRunError adds msg to a run's error without losing what is already
// there: an alert failure must not hide that the result may be incomplete.
func appendRunError(prev, msg string) string {
	if prev == "" {
		return msg
	}
	return prev + "; " + msg
}
