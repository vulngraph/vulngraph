package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// Repo is the finding storage the service needs. CHRepo implements it.
type Repo interface {
	Upsert(ctx context.Context, findings []Finding) error
	UpsertEnrichment(ctx context.Context, enrichments []Enrichment) error
	List(ctx context.Context, f Filter) ([]Finding, error)
	Summary(ctx context.Context, f Filter) (Summary, error)
	Clusters(ctx context.Context, f Filter) ([]Cluster, int, error)
	RiskByResource(ctx context.Context, ids []string) (map[string]Risk, error)
	RiskiestResources(ctx context.Context, limit int) ([]ResourceRisk, error)
	SignalsByResource(ctx context.Context) (map[string]ResourceSignals, error)
	Get(ctx context.Context, id string) (Finding, error)
	ByIDs(ctx context.Context, ids []string) ([]Finding, error)
	ByResourceIDs(ctx context.Context, ids []string) ([]Finding, error)
	OpenKeysByConnector(ctx context.Context, source, connectorID string) ([]OpenKey, error)
	DistinctCheckIDs(ctx context.Context, source string) ([]string, error)
	OpenResourcesByCheck(ctx context.Context, checkIDs []string) (map[string][]string, error)
	CountByCheckID(ctx context.Context, source, checkID string) (int, error)
	UnenrichedCounts(ctx context.Context) ([]SeverityCount, error)
	MustFixCoverage(ctx context.Context) ([]ClassificationCoverage, error)
	AgeIntegrity(ctx context.Context) (AgeIntegrity, error)
	CheckQuality(ctx context.Context) ([]CheckQuality, int, error)
	// OpenIDsBehindCutoff walks the corpus for a full re-enrichment pass, ordered
	// by id from a caller-held cursor (see reenrich.go).
	OpenIDsBehindCutoff(ctx context.Context, cutoff time.Time, afterID string, limit int) ([]string, error)
	SourceActivity(ctx context.Context) ([]SourceActivity, error)
}

type Service struct {
	repo     Repo
	resolved ResolveObserver
	audit    AuditRecorder        // nil: no audit rows (tests)
	agent    func(Finding) string // AgentRefusal; nil refuses every API-key resolve
}

func NewService(repo Repo) *Service { return &Service{repo: repo} }

// ResolveObserver is told which findings a Resolve closed, after the write.
// enrichcache.Service implements it: it ends each finding's alert episode, so a
// regression of the same id alerts again.
type ResolveObserver interface {
	FindingsResolved(ctx context.Context, findingIDs []string) error
}

// WithResolveObserver wires o into every Resolve. Call once at construction.
func (s *Service) WithResolveObserver(o ResolveObserver) *Service { s.resolved = o; return s }

// Record stores a batch of findings exactly as given, with no lifecycle
// stamping. It has no production caller and must not gain one from a
// score-writer: the row it writes carries the caller's copy of resolved_at/
// last_observed_at/severity, so a write built from an earlier read reopens a
// finding resolved since (or re-resolves one reopened since). Enrich and the
// KEV refresh write RecordEnrichment only; producers use RecordObserved.
//
// Upsert's column list does not include the ten enrich:"output" fields, so
// this call never touches them.
func (s *Service) Record(ctx context.Context, findings []Finding) error {
	if err := s.repo.Upsert(ctx, findings); err != nil {
		return fmt.Errorf("Record: %w", err)
	}
	return nil
}

// RecordEnrichment writes enrichment outputs to finding_enrichment.
// This is the ONLY writer of the ten enrich:"output" fields:
// no producer or lifecycle write can reach them (insertFindings, repo.go,
// carries none of the ten columns), and Record/Upsert on `findings` cannot
// touch them either. A producer re-observation therefore PHYSICALLY CANNOT
// clobber enrichment: there is no shared row left to lose an update on.
func (s *Service) RecordEnrichment(ctx context.Context, enrichments []Enrichment) error {
	if err := s.repo.UpsertEnrichment(ctx, enrichments); err != nil {
		return fmt.Errorf("RecordEnrichment: %w", err)
	}
	return nil
}

// RecordObserved stores freshly-observed findings: a check just fired or a
// provider/scanner just reported them. Stamps LastObservedAt and clears any
// prior resolution — a re-observed resolved finding is a regression, reopened
// automatically because the new full row supersedes the old ReplacingMergeTree
// version. Observation producers (sync, scanners, feeds) call this;
// enrichment writers use RecordEnrichment.
//
// Also pins FirstDetectedAt forward
// from the finding's stored version, BEFORE writing — see
// pinFirstDetectedAt's doc. This runs unconditionally for every
// RecordObserved caller: every caller builds a fresh Finding{} that knows
// only the raw facts of this observation, not the finding's actual first-seen
// date, so without the pin a routine re-observation would reset a month-old
// finding's recorded age to "just now" (the FindingAge input).
//
// This does NOT carry forward the ten enrich:"output" fields (score,
// must_fix_class, etc.) — insertFindings (repo.go) does not write those
// columns at all, so there is nothing on the `findings` row for this Upsert
// to reset and nothing to carry. finding_enrichment (RecordEnrichment) is
// their sole store, written only by enrich/KEV, never touched by an
// observation producer.
func (s *Service) RecordObserved(ctx context.Context, findings []Finding) error {
	if err := s.pinFirstDetectedAt(ctx, findings); err != nil {
		return fmt.Errorf("RecordObserved: %w", err)
	}
	now := time.Now()
	for i := range findings {
		findings[i].LastObservedAt = now
		findings[i].ResolvedAt = time.Time{}
	}
	if err := s.repo.Upsert(ctx, findings); err != nil {
		return fmt.Errorf("RecordObserved: %w", err)
	}
	return nil
}

// pinFirstDetectedAt prevents a producer re-confirming an EXISTING finding
// (identical deterministic ID) from resetting its recorded first observation.
// A producer builds a fresh Finding{} per violation with FirstDetectedAt at
// its Go zero value — RecordObserved's Upsert would otherwise make that
// zero-age version the latest ReplacingMergeTree row and a month-old finding
// would read as brand new. Fetches the stored versions of found's IDs and
// pins each one's FirstDetectedAt to the oldest known non-zero timestamp
// across the stored and incoming rows (see earliest's doc) — this is the
// age input and must never move forward on re-observation.
//
// Severity is not carried: it is the producer's raw input, and KEV never
// writes it (kev.Enrich only sets KnownExploited, which lives in
// finding_enrichment). A producer's severity change, up or down, is recorded
// as reported.
//
// A read failure is returned, and RecordObserved then writes nothing: writing
// without the stored versions would make a zero-age row the latest one — a
// month-old finding re-recorded as brand new. The producer's next sweep
// re-observes it.
func (s *Service) pinFirstDetectedAt(ctx context.Context, found []Finding) error {
	if len(found) == 0 {
		return nil
	}
	ids := make([]string, len(found))
	for i, f := range found {
		ids[i] = f.ID
	}
	existing, err := s.repo.ByIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("pinFirstDetectedAt: %w", err)
	}
	byID := make(map[string]Finding, len(existing))
	for _, f := range existing {
		byID[f.ID] = f
	}
	for i, f := range found {
		prev, ok := byID[f.ID]
		if !ok {
			continue
		}
		found[i].FirstDetectedAt = earliest(prev.FirstDetectedAt, prev.DetectedAt, f.FirstDetectedAt, f.DetectedAt)
	}
	return nil
}

// earliest returns the oldest non-zero timestamp, or the zero time if every
// candidate is zero. Zero is "unknown", not "the epoch" — a plain min would let
// one unset field pin a finding's first observation to 1970 and demote it
// forever.
func earliest(ts ...time.Time) time.Time {
	var out time.Time
	for _, t := range ts {
		if t.IsZero() || t.Year() < 2000 {
			continue // zero, or a driver-decoded DateTime(0)
		}
		if out.IsZero() || t.Before(out) {
			out = t
		}
	}
	return out
}

// Resolve marks findings resolved for a declared reason. Rows are re-written with
// ResolvedAt and ResolutionReason set so default readers drop them while history
// stays queryable.
//
// reason is a required parameter rather than a field on Finding on purpose: the
// compiler then rejects an unexplained resolution, and there is no way to forget it
// at a new call site. That matters because "resolved" without "why" makes check
// quality unmeasurable: a check driving real remediation and a check narrating
// cloud churn would produce identical data (see resolution.go). An invalid or
// empty reason is an error, not a silent default.
func (s *Service) Resolve(ctx context.Context, findings []Finding, reason ResolutionReason) error {
	if len(findings) == 0 {
		return nil
	}
	if !reason.Valid() {
		return fmt.Errorf("Resolve: %w: %q is not one of fixed/resource_gone/manual/provider_closed",
			ErrInvalidResolution, reason)
	}
	now := time.Now()
	for i := range findings {
		findings[i].ResolvedAt = now
		findings[i].ResolutionReason = reason
	}
	// The write is built from rows re-read by id, never from the caller's copy:
	// that copy may be minutes old, and writing it back as the newest
	// ReplacingMergeTree version reverts whatever a sync recorded since (a
	// re-observation's metadata, title, last_observed_at, a KEV severity).
	// Only the resolution itself — and the resolution annotations a caller adds
	// (resolved_reason/resolved_by) — come from the caller. A finding the
	// re-read no longer finds is not written: resolving it would create it.
	fresh := make([]Finding, 0, len(findings))
	for start := 0; start < len(findings); start += resourceIDBatchSize {
		chunk := findings[start:min(start+resourceIDBatchSize, len(findings))]
		ids := make([]string, len(chunk))
		byID := make(map[string]Finding, len(chunk))
		for i, f := range chunk {
			ids[i] = f.ID
			byID[f.ID] = f
		}
		stored, err := s.repo.ByIDs(ctx, ids)
		if err != nil {
			return fmt.Errorf("Resolve: re-read: %w", err)
		}
		for _, st := range stored {
			caller := byID[st.ID]
			st.ResolvedAt, st.ResolutionReason = now, reason
			for _, k := range resolutionMetaKeys {
				if v, ok := caller.Metadata[k]; ok {
					if st.Metadata == nil {
						st.Metadata = map[string]string{}
					}
					st.Metadata[k] = v
				}
			}
			fresh = append(fresh, st)
		}
	}
	if missing := len(findings) - len(fresh); missing > 0 {
		log.FromContext(ctx).Warn().Int("missing", missing).Int("requested", len(findings)).Str("reason", string(reason)).
			Msg("finding: resolve skipped findings the re-read no longer finds")
	}
	if err := s.repo.Upsert(ctx, fresh); err != nil {
		return fmt.Errorf("Resolve: %w", err)
	}
	if s.resolved != nil && len(fresh) > 0 {
		ids := make([]string, len(fresh))
		for i, f := range fresh {
			ids[i] = f.ID
		}
		// Best-effort: the resolution is already written. A failure leaves the
		// alert episode open, so a regression of these ids would not re-alert —
		// logged at error so it is visible.
		if err := s.resolved.FindingsResolved(ctx, ids); err != nil {
			log.FromContext(ctx).Error().Err(err).Int("findings", len(ids)).
				Msg("finding: resolve observer failed; a regression of these findings may not re-alert")
		}
	}
	return nil
}

// resolutionMetaKeys are the metadata a resolver records about the resolution
// itself (the manual-resolve handler), carried onto the re-read row.
var resolutionMetaKeys = []string{"resolved_reason", "resolved_by"}

// resourceIDBatchSize bounds the Go-side size of one ByResourceIDs result. A
// purge can span thousands of resource IDs, and a dense resource can carry
// thousands of findings on its own, so an unbatched call would materialise a
// very large []Finding at once.
const resourceIDBatchSize = 500

// ResolveGoneByResourceIDs resolves every OPEN finding on any of the given
// resource IDs with ReasonResourceGone — the counterpart to
// asset.Service.PurgeAccount: an asset that has just been purged because its
// account is confirmed gone leaves its findings behind unless something
// explicitly closes them (findings are never silently orphaned).
// Batches the lookup because a purge can span thousands of resource IDs — see
// resourceIDBatchSize.
func (s *Service) ResolveGoneByResourceIDs(ctx context.Context, ids []string) (int, error) {
	resolved := 0
	for start := 0; start < len(ids); start += resourceIDBatchSize {
		end := min(start+resourceIDBatchSize, len(ids))
		batch, err := s.repo.ByResourceIDs(ctx, ids[start:end])
		if err != nil {
			return resolved, fmt.Errorf("ResolveGoneByResourceIDs: %w", err)
		}
		open := make([]Finding, 0, len(batch))
		for _, f := range batch {
			if !f.Resolved() {
				open = append(open, f)
			}
		}
		if len(open) == 0 {
			continue
		}
		if err := s.Resolve(ctx, open, ReasonResourceGone); err != nil {
			return resolved, fmt.Errorf("ResolveGoneByResourceIDs: %w", err)
		}
		resolved += len(open)
	}
	return resolved, nil
}

// List returns findings matching the filter, newest first.
func (s *Service) List(ctx context.Context, f Filter) ([]Finding, error) {
	out, err := s.repo.List(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	return out, nil
}

// Get returns one finding by ID, or ErrNotFound.
func (s *Service) Get(ctx context.Context, id string) (Finding, error) {
	f, err := s.repo.Get(ctx, id)
	if err != nil {
		return Finding{}, fmt.Errorf("Get: %w", err)
	}
	return f, nil
}

// ByResourceIDs returns findings for the given resource IDs. Used by the
// post-correlate invalidation path and the lifecycle reconcilers. Propagates
// ErrResultTooLarge, which callers must treat as a skipped read, not an empty one.
func (s *Service) ByResourceIDs(ctx context.Context, ids []string) ([]Finding, error) {
	out, err := s.repo.ByResourceIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("ByResourceIDs: %w", err)
	}
	return out, nil
}

// ByIDs returns the current rows for the given finding ids (order unspecified).
func (s *Service) ByIDs(ctx context.Context, ids []string) ([]Finding, error) {
	out, err := s.repo.ByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("ByIDs: %w", err)
	}
	return out, nil
}

// OpenKeysByConnector returns the open findings of source last emitted by
// connectorID. Propagates ErrResultTooLarge, which callers must treat as a
// skipped read, not an empty one.
func (s *Service) OpenKeysByConnector(ctx context.Context, source, connectorID string) ([]OpenKey, error) {
	out, err := s.repo.OpenKeysByConnector(ctx, source, connectorID)
	if err != nil {
		return nil, fmt.Errorf("OpenKeysByConnector: %w", err)
	}
	return out, nil
}

// DistinctCheckIDs returns the set of check_ids that have at least one current
// finding, optionally scoped by source. Used by compliance without pagination.
func (s *Service) DistinctCheckIDs(ctx context.Context, source string) ([]string, error) {
	ids, err := s.repo.DistinctCheckIDs(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("DistinctCheckIDs: %w", err)
	}
	return ids, nil
}

// OpenResourcesByCheck returns, for the given checks, the distinct resources
// with an open finding — the same open-and-alive set DistinctCheckIDs reads.
// Used by the compliance auditor export.
func (s *Service) OpenResourcesByCheck(ctx context.Context, checkIDs []string) (map[string][]string, error) {
	out, err := s.repo.OpenResourcesByCheck(ctx, checkIDs)
	if err != nil {
		return nil, fmt.Errorf("OpenResourcesByCheck: %w", err)
	}
	return out, nil
}

// CountByCheckID returns the number of distinct resources with a finding of the
// given check_id and source. Used by the CrossCluster enrich source to score
// systemic issues without loading all findings into Go memory.
func (s *Service) CountByCheckID(ctx context.Context, source, checkID string) (int, error) {
	n, err := s.repo.CountByCheckID(ctx, source, checkID)
	if err != nil {
		return 0, fmt.Errorf("CountByCheckID: %w", err)
	}
	return n, nil
}
