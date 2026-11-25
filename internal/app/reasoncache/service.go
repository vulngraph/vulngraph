package reasoncache

import "context"

// Repo persists reasoning-cache entries. PGRepo implements it.
type Repo interface {
	Get(ctx context.Context, findingID string) (Entry, error)
	// ListPending returns cached decisions awaiting a human governor, capped
	// at limit. actionClass narrows the scan to a single action class server
	// side, ahead of the cap — "" means unfiltered.
	ListPending(ctx context.Context, limit int, actionClass string) ([]Entry, error)
	Upsert(ctx context.Context, e Entry) error
	// IncrementRepeat bumps repeat_count and stamps last_repeated_at = now()
	// for findingID. See respond.RepeatTracker for the caller.
	IncrementRepeat(ctx context.Context, findingID string) error
	// TopEscalatedRepeats returns the escalated entries with the highest
	// repeat count — the live hotspot signal the repeat counter exists to feed.
	TopEscalatedRepeats(ctx context.Context, limit int) ([]Entry, error)
	// DeleteForFindings removes cache entries for the given finding IDs,
	// forcing a cache miss (and a fresh Decide) the next time each is
	// enqueued. Targeted counterpart to PurgeAll; mirrors
	// enrichcache.Repo.DeleteForFindings.
	DeleteForFindings(ctx context.Context, findingIDs []string) error
	// PurgeAll deletes every reasoning-cache entry. See LogicVersion's doc
	// comment and Service.InvalidateAll for why this exists and when to call
	// it — the reconciliation lever for a LogicVersion bump.
	PurgeAll(ctx context.Context) (int64, error)
}

// Service is the read/write seam respond depends on.
type Service struct {
	repo Repo
}

func NewService(repo Repo) *Service { return &Service{repo: repo} }

// Get returns the cached entry for a finding, or ErrNotFound.
func (s *Service) Get(ctx context.Context, findingID string) (Entry, error) {
	return s.repo.Get(ctx, findingID)
}

// Put upserts the entry (keyed by finding ID).
func (s *Service) Put(ctx context.Context, e Entry) error {
	return s.repo.Upsert(ctx, e)
}

// ListPending returns cached decisions awaiting a human governor, newest
// first. actionClass narrows the scan to a single action class server-side,
// ahead of the cap — "" means unfiltered.
func (s *Service) ListPending(ctx context.Context, limit int, actionClass string) ([]Entry, error) {
	return s.repo.ListPending(ctx, limit, actionClass)
}

// IncrementRepeat bumps the repeat counter for findingID. Satisfies
// respond.RepeatTracker structurally, so respond can wire this Service in
// without either package importing the other.
func (s *Service) IncrementRepeat(ctx context.Context, findingID string) error {
	return s.repo.IncrementRepeat(ctx, findingID)
}

// TopEscalatedRepeats returns the escalated entries with the highest repeat
// count, newest-repeated-first isn't guaranteed — ordered by RepeatCount DESC.
func (s *Service) TopEscalatedRepeats(ctx context.Context, limit int) ([]Entry, error) {
	return s.repo.TopEscalatedRepeats(ctx, limit)
}

// DeleteForFindings removes cached entries for specific findings, forcing a
// fresh Decide (and LLM reasoning pass) the next time each is enqueued.
// Mirrors enrichcache.Service.DeleteForFindings (e.g. for a post-correlate
// invalidation caller outside this package to reuse the same lever).
func (s *Service) DeleteForFindings(ctx context.Context, findingIDs []string) error {
	return s.repo.DeleteForFindings(ctx, findingIDs)
}

// InvalidateAll purges every cached reasoning entry, unconditionally. It is
// the reconciliation path for a LogicVersion bump (see that constant's doc
// comment): unlike enrichcache, reasoncache cannot tell a stale-by-version row
// apart from a fresh one by inspecting its stored Fingerprint — it is an
// opaque hash, not a plaintext-versioned value — so there is no selective
// "delete only the stale ones" query to write. A blanket purge is the bounded,
// honest alternative: it is a single DELETE (no unbounded growth, no partial
// state), and every row it removes is safely recomputed from scratch on the
// finding's next Decide.
//
// This is deliberately NOT wired to run automatically on a LogicVersion
// bump — nothing in this package observes deploys or drives a corpus sweep.
// Call it from an operator action, or from a job (owned outside this
// package, in internal/jobs, the same layer that owns
// jobs.TriggerFullPassIfVersionChanged for enrichcache) that lists open
// findings and re-enqueues Decide for each after calling this once.
func (s *Service) InvalidateAll(ctx context.Context) (int64, error) {
	return s.repo.PurgeAll(ctx)
}
