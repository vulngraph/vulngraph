package savedquery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordedRun struct {
	run     Run
	advance bool
}

// fakeRepo records what the service writes, and the order of writes and alerts.
type fakeRepo struct {
	recorded  []recordedRun
	scheduled []SavedQuery
	recordErr error
	created   SavedQuery
	events    *[]string
}

func (f *fakeRepo) Create(_ context.Context, q SavedQuery) (SavedQuery, error) {
	f.created = q
	return q, nil
}
func (f *fakeRepo) Update(_ context.Context, q SavedQuery) (SavedQuery, error) { return q, nil }
func (f *fakeRepo) Delete(context.Context, string) error                       { return nil }
func (f *fakeRepo) Get(context.Context, string) (SavedQuery, error)            { return SavedQuery{}, nil }
func (f *fakeRepo) List(context.Context) ([]SavedQuery, error)                 { return nil, nil }
func (f *fakeRepo) ListScheduled(context.Context) ([]SavedQuery, error)        { return f.scheduled, nil }
func (f *fakeRepo) ListRuns(context.Context, string, int) ([]Run, error)       { return nil, nil }
func (f *fakeRepo) RecordRun(_ context.Context, r Run, advance bool) error {
	if f.events != nil {
		*f.events = append(*f.events, "record")
	}
	f.recorded = append(f.recorded, recordedRun{run: r, advance: advance})
	return f.recordErr
}

type fakeRunner struct {
	res    QueryResult
	err    error
	called int
}

func (r *fakeRunner) RunForSavedQuery(context.Context, string) (QueryResult, error) {
	r.called++
	return r.res, r.err
}

type fakeAlerter struct {
	fired  int
	err    error
	events *[]string
}

func (a *fakeAlerter) AlertQueryChange(context.Context, SavedQuery, int, int) error {
	if a.events != nil {
		*a.events = append(*a.events, "alert")
	}
	a.fired++
	return a.err
}

func ready() bool { return true }

// When the graph isn't ready, Run must skip cleanly: no query executed, no run
// recorded, no alert — so a deploy window can't fire a false drift alert or
// corrupt the baseline hash.
func TestRun_SkippedWhenGraphNotReady(t *testing.T) {
	repo := &fakeRepo{}
	runner := &fakeRunner{}
	alerter := &fakeAlerter{}
	svc := NewService(repo).WithRunner(runner).WithAlerter(alerter).
		WithReadiness(func() bool { return false })

	q := SavedQuery{ID: "q1", AlertOnChange: true, LastResultHash: "baseline"}
	_, err := svc.Run(context.Background(), q, TriggerSchedule)

	require.ErrorIs(t, err, ErrGraphNotReady)
	assert.Equal(t, 0, runner.called, "query must not run when graph not ready")
	assert.Empty(t, repo.recorded, "no run recorded → baseline preserved")
	assert.Equal(t, 0, alerter.fired, "no false alert")
}

// A changed result alerts first and only then advances the baseline, so a
// failed delivery can never leave an advanced baseline behind.
func TestRun_AlertsBeforeAdvancingBaseline(t *testing.T) {
	var events []string
	repo := &fakeRepo{events: &events}
	runner := &fakeRunner{res: QueryResult{NodeIDs: []string{"a", "b"}}}
	alerter := &fakeAlerter{events: &events}
	svc := NewService(repo).WithRunner(runner).WithAlerter(alerter).WithReadiness(ready)

	q := SavedQuery{ID: "q1", AlertOnChange: true, LastResultHash: "different-baseline"}
	run, err := svc.Run(context.Background(), q, TriggerSchedule)

	require.NoError(t, err)
	assert.Equal(t, []string{"alert", "record"}, events)
	require.Len(t, repo.recorded, 1)
	assert.True(t, repo.recorded[0].advance)
	assert.Equal(t, 2, run.NodeCount)
}

// An undelivered alert keeps the old baseline (so the next run re-detects the
// change and retries) and records the failure on the run.
func TestRun_UndeliveredAlertKeepsBaseline(t *testing.T) {
	repo := &fakeRepo{}
	runner := &fakeRunner{res: QueryResult{NodeIDs: []string{"a"}}}
	alerter := &fakeAlerter{err: ErrAlertUndelivered}
	svc := NewService(repo).WithRunner(runner).WithAlerter(alerter).WithReadiness(ready)

	q := SavedQuery{ID: "q1", AlertOnChange: true, LastResultHash: "old"}
	run, err := svc.Run(context.Background(), q, TriggerSchedule)

	require.ErrorIs(t, err, ErrAlertUndelivered)
	require.Len(t, repo.recorded, 1)
	assert.False(t, repo.recorded[0].advance, "baseline must not move past an unannounced change")
	assert.NotEmpty(t, run.Error)
}

// An alert no channel's routing accepts cannot be retried into delivery: the
// baseline advances and the run records why nobody was told.
func TestRun_NoRecipientAlertAdvancesBaseline(t *testing.T) {
	repo := &fakeRepo{}
	runner := &fakeRunner{res: QueryResult{NodeIDs: []string{"a"}}}
	alerter := &fakeAlerter{err: fmt.Errorf("AlertQueryChange: %w", ErrAlertNoRecipients)}
	svc := NewService(repo).WithRunner(runner).WithAlerter(alerter).WithReadiness(ready)

	q := SavedQuery{ID: "q1", AlertOnChange: true, LastResultHash: "old"}
	run, err := svc.Run(context.Background(), q, TriggerSchedule)

	require.NoError(t, err)
	require.Len(t, repo.recorded, 1)
	assert.True(t, repo.recorded[0].advance, "nothing to retry, so the baseline moves")
	assert.Contains(t, run.Error, "reached no channel")
	assert.Contains(t, repo.recorded[0].run.Error, "reached no channel")
}

// A runner error is recorded as a failed run without touching the baseline,
// so the next good run still compares against the last good result and alerts.
func TestRun_ErroredRunKeepsBaseline(t *testing.T) {
	repo := &fakeRepo{}
	runner := &fakeRunner{err: errors.New("engine down")}
	alerter := &fakeAlerter{}
	svc := NewService(repo).WithRunner(runner).WithAlerter(alerter).WithReadiness(ready)

	q := SavedQuery{ID: "q1", AlertOnChange: true, LastResultHash: "good"}
	run, err := svc.Run(context.Background(), q, TriggerSchedule)

	require.Error(t, err)
	require.Len(t, repo.recorded, 1)
	assert.False(t, repo.recorded[0].advance)
	assert.Equal(t, "engine down", run.Error)
	assert.Equal(t, 0, alerter.fired)
}

// The failed-run record's own error is surfaced, not discarded.
func TestRun_ErroredRunRecordFailureIsReturned(t *testing.T) {
	recordErr := errors.New("pg down")
	repo := &fakeRepo{recordErr: recordErr}
	runner := &fakeRunner{err: errors.New("engine down")}
	svc := NewService(repo).WithRunner(runner).WithReadiness(ready)

	_, err := svc.Run(context.Background(), SavedQuery{ID: "q1"}, TriggerSchedule)
	require.ErrorIs(t, err, recordErr)
}

// A truncated result is not a measurement of the full result set: no baseline
// change, no alert, and the run says why.
func TestRun_TruncatedResultIsUnknown(t *testing.T) {
	repo := &fakeRepo{}
	runner := &fakeRunner{res: QueryResult{NodeIDs: []string{"a"}, Truncated: true}}
	alerter := &fakeAlerter{}
	svc := NewService(repo).WithRunner(runner).WithAlerter(alerter).WithReadiness(ready)

	q := SavedQuery{ID: "q1", AlertOnChange: true, LastResultHash: "full"}
	run, err := svc.Run(context.Background(), q, TriggerSchedule)

	require.ErrorIs(t, err, ErrResultTruncated)
	require.Len(t, repo.recorded, 1)
	assert.False(t, repo.recorded[0].advance)
	assert.Empty(t, repo.recorded[0].run.ResultHash)
	assert.Equal(t, 0, alerter.fired)
	assert.Equal(t, ErrResultTruncated.Error(), run.Error)
}

// A result the graph engine flagged multi-hop-may-be-incomplete still runs the
// detection (single-hop matches are unaffected), but the run never reads as ok.
func TestRun_MultiHopMayBeIncompleteIsNeverOK(t *testing.T) {
	repo := &fakeRepo{}
	runner := &fakeRunner{res: QueryResult{NodeIDs: []string{"a"}, MultiHopMayBeIncomplete: true}}
	alerter := &fakeAlerter{}
	svc := NewService(repo).WithRunner(runner).WithAlerter(alerter).WithReadiness(ready)

	q := SavedQuery{ID: "q1", AlertOnChange: true, LastResultHash: "old"}
	run, err := svc.Run(context.Background(), q, TriggerSchedule)

	require.NoError(t, err)
	require.Len(t, repo.recorded, 1)
	assert.True(t, repo.recorded[0].advance)
	assert.NotEmpty(t, repo.recorded[0].run.ResultHash)
	assert.Equal(t, 1, alerter.fired)
	assert.Equal(t, RunStatusIncomplete, run.Status())
	assert.Equal(t, RunStatusIncomplete, repo.recorded[0].run.Status())
}

// A manual run is history only: it never alerts, so it must never move the
// baseline the scheduled run compares against.
func TestRun_ManualRunDoesNotAdvanceBaseline(t *testing.T) {
	repo := &fakeRepo{}
	runner := &fakeRunner{res: QueryResult{NodeIDs: []string{"new"}}}
	alerter := &fakeAlerter{}
	svc := NewService(repo).WithRunner(runner).WithAlerter(alerter)

	q := SavedQuery{ID: "q1", AlertOnChange: true, LastResultHash: "old"}
	_, err := svc.Run(context.Background(), q, TriggerManual)

	require.NoError(t, err)
	require.Len(t, repo.recorded, 1)
	assert.False(t, repo.recorded[0].advance)
	assert.Equal(t, 0, alerter.fired)
}

// First run (no baseline) never alerts, even on a non-empty result, and sets
// the baseline.
func TestRun_FirstRunNoAlert(t *testing.T) {
	repo := &fakeRepo{}
	runner := &fakeRunner{res: QueryResult{NodeIDs: []string{"a"}}}
	alerter := &fakeAlerter{}
	svc := NewService(repo).WithRunner(runner).WithAlerter(alerter).WithReadiness(ready)

	q := SavedQuery{ID: "q1", AlertOnChange: true, LastResultHash: ""}
	_, err := svc.Run(context.Background(), q, TriggerSchedule)

	require.NoError(t, err)
	assert.Equal(t, 0, alerter.fired, "no baseline → no alert")
	require.Len(t, repo.recorded, 1)
	assert.True(t, repo.recorded[0].advance)
}

// No readiness func wired → always runs (back-compat).
func TestRun_NoReadinessAlwaysRuns(t *testing.T) {
	repo := &fakeRepo{}
	runner := &fakeRunner{}
	svc := NewService(repo).WithRunner(runner)

	_, err := svc.Run(context.Background(), SavedQuery{ID: "q1"}, TriggerManual)
	require.NoError(t, err)
	assert.Equal(t, 1, runner.called)
}

// One query's failure does not stop the sweep, and only successes count.
func TestRunScheduled_FailureDoesNotStopSweep(t *testing.T) {
	repo := &fakeRepo{scheduled: []SavedQuery{{ID: "bad"}, {ID: "good"}}}
	runner := &fakeRunner{}
	svc := NewService(repo).WithRunner(runner).WithReadiness(ready)

	calls := 0
	n, err := svc.RunScheduled(context.Background(), func(string) bool {
		calls++
		if calls == 1 {
			runner.err = errors.New("boom")
		} else {
			runner.err = nil
		}
		return true
	})
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 2, runner.called)
	require.Len(t, repo.recorded, 2)
	assert.Equal(t, "boom", repo.recorded[0].run.Error, "the failure is recorded as a failed run")
}

// RunScheduled treats a not-ready skip as a clean no-op, not an error.
func TestRunScheduled_SkipNotReadyIsClean(t *testing.T) {
	repo := &fakeRepo{scheduled: []SavedQuery{{ID: "q1"}}}
	svc := NewService(repo).WithRunner(&fakeRunner{}).
		WithReadiness(func() bool { return false })
	n, err := svc.RunScheduled(context.Background(), func(string) bool { return true })
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Empty(t, repo.recorded)
}

// Scalar rows are part of the hash: a changed count must read as a change.
func TestHashResult_IncludesRows(t *testing.T) {
	a := hashResult(QueryResult{Rows: []string{`{"n":1}`}})
	b := hashResult(QueryResult{Rows: []string{`{"n":2}`}})
	assert.NotEqual(t, a, b)
	assert.Equal(t, a, hashResult(QueryResult{Rows: []string{`{"n":1}`}}))
}

// A graph-shaped result hashes exactly as before rows were hashed, so existing
// baselines don't all read as changed (and alert) on the first run after deploy.
func TestHashResult_GraphShapeUnchanged(t *testing.T) {
	h := sha256.New()
	for _, n := range []string{"a", "b"} {
		h.Write([]byte(n))
		h.Write([]byte{0})
	}
	h.Write([]byte{1})
	h.Write([]byte("a|e|b"))
	h.Write([]byte{0})
	legacy := hex.EncodeToString(h.Sum(nil))

	got := hashResult(QueryResult{NodeIDs: []string{"b", "a"}, EdgeKeys: []string{"a|e|b"}})
	assert.Equal(t, legacy, got)
}

func TestCreate_AlertSeverity(t *testing.T) {
	base := SavedQuery{Name: "n", Cypher: "MATCH (n) RETURN n"}
	tests := []struct {
		name string
		sev  string
		want string
		err  error
	}{
		{name: "empty defaults to high", sev: "", want: SeverityHigh},
		{name: "explicit kept", sev: SeverityLow, want: SeverityLow},
		{name: "unknown rejected", sev: "urgent", err: ErrInvalidSeverity},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepo{}
			q := base
			q.AlertSeverity = tc.sev
			_, err := NewService(repo).Create(context.Background(), q)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, repo.created.AlertSeverity)
		})
	}
}

func TestCreateUpdate_Schedule(t *testing.T) {
	tests := []struct {
		name     string
		schedule string
		ok       bool
	}{
		{"manual only", "", true},
		{"blank is manual only", "   ", true},
		{"nightly", "0 2 * * *", true},
		{"step", "*/15 * * * *", true},
		{"four fields", "0 2 * *", false},
		{"out of range", "0 25 * * *", false},
		{"macro", "@daily", false},
		{"garbage", "every night", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := SavedQuery{Name: "n", Cypher: "MATCH (n) RETURN n", Schedule: tc.schedule}
			svc := NewService(&fakeRepo{})
			_, createErr := svc.Create(context.Background(), q)
			_, updateErr := svc.Update(context.Background(), q)
			if tc.ok {
				require.NoError(t, createErr)
				require.NoError(t, updateErr)
				return
			}
			require.ErrorIs(t, createErr, ErrInvalidSchedule)
			require.ErrorIs(t, updateErr, ErrInvalidSchedule)
		})
	}
}

// A stored schedule saved before validation existed must not be silently
// skipped forever: the sweep never runs it, and the API names the problem.
func TestRunScheduled_InvalidScheduleNeverRuns(t *testing.T) {
	repo := &fakeRepo{scheduled: []SavedQuery{{ID: "broken", Schedule: "0 2 * *"}, {ID: "ok", Schedule: "* * * * *"}}}
	runner := &fakeRunner{}
	svc := NewService(repo).WithRunner(runner).WithReadiness(ready)

	var asked []string
	n, err := svc.RunScheduled(context.Background(), func(s string) bool {
		asked = append(asked, s)
		return true
	})
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, []string{"* * * * *"}, asked, "an invalid schedule is never evaluated as due")

	assert.Contains(t, toResponse(SavedQuery{Schedule: "0 2 * *"}).ScheduleError, "invalid schedule")
	assert.Empty(t, toResponse(SavedQuery{Schedule: "0 2 * * *"}).ScheduleError)
	assert.Empty(t, toResponse(SavedQuery{}).ScheduleError)
}

func TestHandler_CreateInvalidSchedule400(t *testing.T) {
	h := NewHandler(NewService(&fakeRepo{}))
	body := `{"name":"n","cypher":"MATCH (n) RETURN n","schedule":"61 * * * *"}`
	for _, tc := range []struct {
		method string
		call   func(http.ResponseWriter, *http.Request)
	}{
		{http.MethodPost, h.Create},
		{http.MethodPut, h.Update},
	} {
		rec := httptest.NewRecorder()
		tc.call(rec, httptest.NewRequest(tc.method, "/api/saved-queries", strings.NewReader(body)))
		require.Equal(t, http.StatusBadRequest, rec.Code, tc.method)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/problem+json", tc.method)
		assert.Contains(t, rec.Body.String(), "minute", tc.method)
	}
}

func TestAppendRunError_KeepsTheIncompleteNote(t *testing.T) {
	got := appendRunError(ErrMultiHopMayBeIncomplete.Error(), "change alert not delivered, baseline kept: smtp down")
	require.Contains(t, got, ErrMultiHopMayBeIncomplete.Error())
	require.Contains(t, got, "smtp down")
	require.Equal(t, "x", appendRunError("", "x"))
}
