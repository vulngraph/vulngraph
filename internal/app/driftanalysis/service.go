package driftanalysis

// Contract for the jobs (chunk B) and HTTP/MCP (chunk C) callers. The verdict
// is advisory; nothing in this package starts a scan.
//
//	New(repo Repo, analyst Analyst, facts FactsSource, opts ...Option) *Service
//	    analyst == nil builds a disabled service: Enabled() is false and the
//	    write-side methods return ErrDisabled. Reads still work.
//	WithModel(string) Option; WithClock(func() time.Time) Option
//
//	(*Service).Enabled() bool
//	(*Service).DiscoverBatches(ctx, enqueue EnqueueFunc) ([]Batch, error)
//	    Cuts a batch per connector with new changes (a connector's first batch
//	    is a baseline: stored, never enqueued). Each pending batch row and
//	    enqueue(ctx, tx, batch) commit in one transaction; tx is the repo's
//	    transaction, which the jobs package asserts to pgx.Tx and passes to
//	    river.InsertTx. Returns the pending batches created. A failing
//	    connector does not stop the others; errors are joined.
//	(*Service).Analyze(ctx, batchID string) error
//	    Idempotent. nil for an unknown, pruned, analysed or baseline batch.
//	    A budget refusal, an LLM error or an ungrounded reply is recorded as
//	    status=unknown and returns nil. Only an error that left no outcome
//	    written (context cancelled, storage or inputs unreadable) is returned.
//	(*Service).Requeue(ctx) ([]Batch, error)
//	    Batches whose job needs re-enqueueing: pending older than 15 minutes,
//	    and unknown with reason budget or llm_error and under 3 attempts.
//	    The caller re-inserts DriftAnalyzeArgs (unique opts dedupe).
//	(*Service).Prune(ctx) (int64, error)       deletes batches older than 90 days
//	(*Service).List(ctx, ListParams) (Listing, error)
//	(*Service).Get(ctx, batchID string) (Batch, error)   ErrNotFound when absent
//
// Reads return Batch with Verdict; Verdict.Recommendation() gives the
// recommended|not_needed|unknown wire value. Facts adapters (FactsSource) are
// wired by the serve/worker composition root.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	// settleDelay keeps discovery away from rows a still-running sync could
	// yet stamp with an older now().
	settleDelay       = time.Minute
	pendingStaleAfter = 15 * time.Minute
	maxAttempts       = 3
	retention         = 90 * 24 * time.Hour
	requeueLimit      = 100
	defaultListLimit  = 50
	maxListLimit      = 200
	defaultListWindow = 30 * 24 * time.Hour
)

// ConnectorState is one connector's drift position: its newest change and the
// window_end of its latest batch (zero when it has none).
type ConnectorState struct {
	ConnectorID string
	Latest      time.Time
	Watermark   time.Time
}

// ChangedAsset is an asset with a drift event and when it happened.
type ChangedAsset struct {
	AssetID string
	At      time.Time
}

// Repo is the storage the service needs.
type Repo interface {
	ConnectorStates(ctx context.Context) ([]ConnectorState, error)
	// ChangedSince lists drift events in (since, until], oldest first.
	ChangedSince(ctx context.Context, connectorID string, since, until time.Time, limit int) ([]ChangedAsset, error)
	Changes(ctx context.Context, connectorID string, assetIDs []string) ([]AssetChange, error)
	// CreateBatch inserts the row and runs enqueue (when non-nil) in the same
	// transaction; created is false when the id already existed.
	CreateBatch(ctx context.Context, b Batch, enqueue EnqueueFunc) (created bool, err error)
	Get(ctx context.Context, id string) (Batch, error)
	List(ctx context.Context, since time.Time, limit int) ([]Batch, error)
	ToRequeue(ctx context.Context, pendingBefore time.Time, maxAttempts, limit int) ([]Batch, error)
	RecordAttempt(ctx context.Context, id string) error
	// Save records an attempt's outcome on a pending or unknown row only.
	Save(ctx context.Context, id, status string, verdict *Verdict, unknownReason string, at time.Time) error
	Prune(ctx context.Context, cutoff time.Time) (int64, error)
}

// Analyst turns a batch and its facts into a verdict. The reason package
// implements it. An error wrapping ErrUngrounded means the reply could not be
// grounded.
type Analyst interface {
	AnalyzeDrift(ctx context.Context, in AnalysisInput) (Verdict, error)
}

// FactsSource supplies the deterministic facts around a batch. Each method
// failing sets the matching Facts.*Known flag false.
type FactsSource interface {
	// Findings returns open finding facts keyed by asset id; assets without
	// findings may be absent.
	Findings(ctx context.Context, assetIDs []string) (map[string]AssetFact, error)
	// Exposure returns, per asset id, whether it is internet-facing now.
	Exposure(ctx context.Context, assetIDs []string) (map[string]bool, error)
}

// Listing is the read envelope: Enabled false means no analysis runs, which
// is not a verdict.
type Listing struct {
	Enabled  bool
	Analyses []Batch
}

// ListParams filters List. Zero Since means the last 30 days; Limit is
// clamped to 1..200 (default 50).
type ListParams struct {
	Since time.Time
	Limit int
}

type Service struct {
	repo    Repo
	analyst Analyst
	facts   FactsSource
	model   string
	now     func() time.Time
}

type Option func(*Service)

// WithModel records the model name stamped on verdicts.
func WithModel(m string) Option { return func(s *Service) { s.model = m } }

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

func New(repo Repo, analyst Analyst, facts FactsSource, opts ...Option) *Service {
	s := &Service{repo: repo, analyst: analyst, facts: facts, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Service) Enabled() bool { return s.analyst != nil }

func (s *Service) DiscoverBatches(ctx context.Context, enqueue EnqueueFunc) ([]Batch, error) {
	if !s.Enabled() {
		return nil, ErrDisabled
	}
	states, err := s.repo.ConnectorStates(ctx)
	if err != nil {
		return nil, fmt.Errorf("DiscoverBatches: %w", err)
	}
	until := s.now().Add(-settleDelay)
	var created []Batch
	var errs []error
	for _, st := range states {
		b, ok, err := s.discoverConnector(ctx, st, until, enqueue)
		if err != nil {
			errs = append(errs, fmt.Errorf("DiscoverBatches: connector %s: %w", st.ConnectorID, err))
			continue
		}
		if ok {
			created = append(created, b)
		}
	}
	return created, errors.Join(errs...)
}

// discoverConnector returns the pending batch it created, if any.
func (s *Service) discoverConnector(ctx context.Context, st ConnectorState, until time.Time, enqueue EnqueueFunc) (Batch, bool, error) {
	if st.Watermark.IsZero() {
		// A connector still being written to is not settled enough to be a baseline.
		if st.Latest.After(until) {
			return Batch{}, false, nil
		}
		base := Batch{
			ID: BatchID(st.ConnectorID, st.Latest), ConnectorID: st.ConnectorID,
			WindowStart: st.Latest, WindowEnd: st.Latest, Status: StatusBaseline,
		}
		if _, err := s.repo.CreateBatch(ctx, base, nil); err != nil {
			return Batch{}, false, err
		}
		return Batch{}, false, nil
	}

	changed, err := s.repo.ChangedSince(ctx, st.ConnectorID, st.Watermark, until, MaxBatchAssets+1)
	if err != nil {
		return Batch{}, false, err
	}
	if len(changed) == 0 {
		return Batch{}, false, nil
	}
	b := Batch{ConnectorID: st.ConnectorID, WindowStart: st.Watermark, Status: StatusPending}
	if len(changed) > MaxBatchAssets {
		b.Truncated = true
		changed = changed[:MaxBatchAssets]
	}
	for _, c := range changed {
		b.AssetIDs = append(b.AssetIDs, c.AssetID)
	}
	b.WindowEnd = changed[len(changed)-1].At
	b.ID = BatchID(b.ConnectorID, b.WindowEnd)
	made, err := s.repo.CreateBatch(ctx, b, enqueue)
	if err != nil {
		return Batch{}, false, err
	}
	return b, made, nil
}

func (s *Service) Analyze(ctx context.Context, batchID string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	b, err := s.repo.Get(ctx, batchID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("Analyze: %w", err)
	}
	if b.Status != StatusPending && b.Status != StatusUnknown {
		return nil
	}
	if err := s.repo.RecordAttempt(ctx, b.ID); err != nil {
		return fmt.Errorf("Analyze: %w", err)
	}

	changes, err := s.repo.Changes(ctx, b.ConnectorID, b.AssetIDs)
	if err != nil {
		return fmt.Errorf("Analyze: %w", err)
	}
	if len(changes) == 0 {
		return s.saveUnknown(ctx, b.ID, ReasonNoChanges)
	}
	in := AnalysisInput{Batch: b, Changes: changes, Facts: s.gatherFacts(ctx, b, changes)}

	v, err := s.analyst.AnalyzeDrift(ctx, in)
	if err == nil {
		v, err = Gate(v, in)
	}
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("Analyze: %w", ctx.Err())
		}
		log.FromContext(ctx).Warn().Err(err).Str("batch_id", b.ID).Msg("driftanalysis: no verdict")
		return s.saveUnknown(ctx, b.ID, unknownReasonFor(err))
	}

	at := s.now()
	v.Model, v.AnalysedAt = s.model, at
	if err := s.repo.Save(ctx, b.ID, StatusAnalysed, &v, "", at); err != nil {
		return fmt.Errorf("Analyze: %w", err)
	}
	return nil
}

// saveUnknown records an outcome with no verdict. It never carries a scan
// recommendation, true or false.
func (s *Service) saveUnknown(ctx context.Context, id, reason string) error {
	if err := s.repo.Save(ctx, id, StatusUnknown, nil, reason, s.now()); err != nil {
		return fmt.Errorf("Analyze: %w", err)
	}
	return nil
}

func unknownReasonFor(err error) string {
	switch {
	case errors.Is(err, ErrUngrounded):
		return ReasonUngrounded
	case errors.Is(err, llm.ErrBudgetExceeded), errors.Is(err, llm.ErrBudgetUnknown):
		return ReasonBudget
	default:
		return ReasonLLMError
	}
}

// gatherFacts never fails: a lookup that errors leaves its Known flag false.
func (s *Service) gatherFacts(ctx context.Context, b Batch, changes []AssetChange) Facts {
	ids := make([]string, len(changes))
	for i, c := range changes {
		ids[i] = c.AssetID
	}
	f := Facts{ExternalChangedIDs: ExternalChanged(changes)}
	logFail := func(what string, err error) {
		log.FromContext(ctx).Warn().Err(err).Str("batch_id", b.ID).Msg("driftanalysis: " + what + " lookup failed")
	}

	findings, ferr := s.facts.Findings(ctx, ids)
	if ferr != nil {
		logFail("findings", ferr)
	}
	exposure, eerr := s.facts.Exposure(ctx, ids)
	if eerr != nil {
		logFail("exposure", eerr)
	}
	f.FindingsKnown, f.ExposureKnown = ferr == nil, eerr == nil

	for _, id := range ids {
		a := AssetFact{AssetID: id}
		if ferr == nil {
			a.OpenFindings, a.MaxScore = findings[id].OpenFindings, findings[id].MaxScore
		}
		if eerr == nil {
			a.InternetFacing = exposure[id]
		}
		f.Assets = append(f.Assets, a)
	}
	return f
}

func (s *Service) Requeue(ctx context.Context) ([]Batch, error) {
	if !s.Enabled() {
		return nil, ErrDisabled
	}
	out, err := s.repo.ToRequeue(ctx, s.now().Add(-pendingStaleAfter), maxAttempts, requeueLimit)
	if err != nil {
		return nil, fmt.Errorf("Requeue: %w", err)
	}
	return out, nil
}

func (s *Service) Prune(ctx context.Context) (int64, error) {
	n, err := s.repo.Prune(ctx, s.now().Add(-retention))
	if err != nil {
		return 0, fmt.Errorf("Prune: %w", err)
	}
	return n, nil
}

func (s *Service) List(ctx context.Context, p ListParams) (Listing, error) {
	if p.Since.IsZero() {
		p.Since = s.now().Add(-defaultListWindow)
	}
	switch {
	case p.Limit <= 0:
		p.Limit = defaultListLimit
	case p.Limit > maxListLimit:
		p.Limit = maxListLimit
	}
	rows, err := s.repo.List(ctx, p.Since, p.Limit)
	if err != nil {
		return Listing{}, fmt.Errorf("List: %w", err)
	}
	return Listing{Enabled: s.Enabled(), Analyses: rows}, nil
}

func (s *Service) Get(ctx context.Context, batchID string) (Batch, error) {
	b, err := s.repo.Get(ctx, batchID)
	if err != nil {
		return Batch{}, fmt.Errorf("Get: %w", err)
	}
	return b, nil
}
