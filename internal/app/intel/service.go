package intel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// pgStore abstracts the Postgres monitored-domain operations.
type pgStore interface {
	AddDomain(ctx context.Context, domain string) (MonitoredDomain, error)
	RemoveDomain(ctx context.Context, domain string) error
	ListDomains(ctx context.Context) ([]MonitoredDomain, error)
}

// chStore abstracts the ClickHouse phishing-candidate operations.
type chStore interface {
	BulkUpsertCandidates(ctx context.Context, candidates []PhishingCandidate) error
	UpdateStatus(ctx context.Context, id string, status CandidateStatus, by string) error
	ListCandidates(ctx context.Context, status CandidateStatus) ([]PhishingCandidate, int, error)
	GetCandidate(ctx context.Context, id string) (PhishingCandidate, error)
	ExistingCandidateIDs(ctx context.Context) (map[string]bool, error)
}

// alertDispatcher routes a notification to configured channels. *notify.Service
// satisfies it. Nil = no alerting (the feature is optional).
type alertDispatcher interface {
	Dispatch(ctx context.Context, n notify.Notification)
}

// Service drives domain monitoring: CRUD for monitored domains and the scan
// pipeline (CT log query → AI triage → candidate storage).
type Service struct {
	pg      pgStore
	ch      chStore
	ct      *ctClient
	triager *Triager
	// triage is the verdict source, defaulted to triager.Triage. A seam only so
	// the auto-dismiss gating can be tested against a fixed set of verdicts: the
	// gate is the one place a candidate leaves human review, and it was
	// unreachable for the whole life of the feature.
	triage   func(ctx context.Context, hits []CTHit) ([]triageResult, error)
	notifier alertDispatcher
}

func NewService(pg *PGRepo, ch *CHRepo, client llm.Client) *Service {
	triager := newTriager(client)
	return &Service{
		pg:      pg,
		ch:      ch,
		ct:      newCTClient(),
		triager: triager,
		triage:  triager.Triage,
	}
}

// WithNotifier wires outbound alerting. When set, confirming a phishing
// candidate fires a notification to matching channels. Nil-safe.
func (s *Service) WithNotifier(n alertDispatcher) *Service {
	s.notifier = n
	return s
}

// AddDomain normalizes and validates the domain, then adds it to the monitored
// set. Invalid input returns ErrInvalidDomain (never reaches storage).
func (s *Service) AddDomain(ctx context.Context, domain string) (MonitoredDomain, error) {
	normalized, err := NormalizeDomain(domain)
	if err != nil {
		return MonitoredDomain{}, fmt.Errorf("AddDomain: %w", err)
	}
	md, err := s.pg.AddDomain(ctx, normalized)
	if err != nil {
		return MonitoredDomain{}, fmt.Errorf("AddDomain: %w", err)
	}
	return md, nil
}

// RemoveDomain removes a monitored domain.
func (s *Service) RemoveDomain(ctx context.Context, domain string) error {
	return s.pg.RemoveDomain(ctx, domain)
}

// ListDomains returns all monitored domains.
func (s *Service) ListDomains(ctx context.Context) ([]MonitoredDomain, error) {
	return s.pg.ListDomains(ctx)
}

// ListCandidates returns phishing candidates and the true population count for
// the status (the list is capped at 500). Status "" defaults to pending.
func (s *Service) ListCandidates(ctx context.Context, status CandidateStatus) ([]PhishingCandidate, int, error) {
	return s.ch.ListCandidates(ctx, status)
}

// Confirm marks a candidate as confirmed phishing and fires an alert.
func (s *Service) Confirm(ctx context.Context, id, by string) error {
	if err := s.ch.UpdateStatus(ctx, id, StatusConfirmed, by); err != nil {
		return fmt.Errorf("Confirm: %w", err)
	}
	if s.notifier != nil {
		// Best-effort alert; never fail the confirm because alerting hiccuped.
		c, err := s.ch.GetCandidate(ctx, id)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("id", id).Msg("intel: alert lookup failed")
			return nil
		}
		s.notifier.Dispatch(ctx, notify.Notification{
			EventType: notify.EventPhishing,
			Severity:  notify.SeverityHigh,
			Score:     int(c.SimilarityScore * 100),
			Title:     "Phishing domain confirmed: " + c.Domain,
			Message: fmt.Sprintf("Confirmed by %s. This domain impersonates %s (%.0f%% similar, cert issuer %s).",
				by, c.MonitoredDomain, c.SimilarityScore*100, c.Issuer),
			Fields: []notify.Field{
				{Label: "Domain", Value: c.Domain, Short: true},
				{Label: "Impersonates", Value: c.MonitoredDomain, Short: true},
				{Label: "Similarity", Value: fmt.Sprintf("%.0f%%", c.SimilarityScore*100), Short: true},
				{Label: "Cert issuer", Value: c.Issuer, Short: true},
			},
			LinkURL:  "https://crt.sh/?q=" + c.Domain,
			LinkText: "Certificate history",
		})
	}
	return nil
}

// Dismiss marks a candidate as not phishing.
func (s *Service) Dismiss(ctx context.Context, id string) error {
	return s.ch.UpdateStatus(ctx, id, StatusDismissed, "")
}

// RunScan is the main scan pipeline: queries CT logs for all monitored domains,
// runs AI triage on new hits, and stores the results. Called by the River job.
func (s *Service) RunScan(ctx context.Context) (ScanResult, error) {
	logger := log.FromContext(ctx)

	domains, err := s.pg.ListDomains(ctx)
	if err != nil {
		return ScanResult{}, fmt.Errorf("RunScan: list domains: %w", err)
	}
	if len(domains) == 0 {
		return ScanResult{}, nil
	}

	domainNames := make([]string, len(domains))
	for i, d := range domains {
		domainNames[i] = d.Domain
	}

	// Re-score what is already in the queue before adding to it.
	rescored, err := s.reconcileQueue(ctx)
	if err != nil {
		// Never fail the scan over housekeeping.
		logger.Warn().Err(err).Msg("intel: queue reconcile failed — continuing with the scan")
	}

	// Load existing candidate IDs to skip re-triaging known hits.
	existing, err := s.ch.ExistingCandidateIDs(ctx)
	if err != nil {
		logger.Warn().Err(err).Msg("intel: could not load existing candidate IDs — proceeding without dedup")
		existing = map[string]bool{}
	}

	// Query CT logs for all monitored domains.
	hits, ctStats, err := s.ct.CheckCTLogs(ctx, domainNames)
	if err != nil {
		return ScanResult{}, fmt.Errorf("RunScan: CT scan: %w", err)
	}
	logger.Info().Int("hits", len(hits)).Int("domains", len(domains)).
		Int("ct_queried", ctStats.Queried).Int("ct_failed", ctStats.Failed).
		Msg("intel: CT scan complete")

	// Filter out already-known candidates.
	var newHits []CTHit
	for _, h := range hits {
		id := CandidateID(h.CommonName, h.MonitoredDomain)
		if !existing[id] {
			newHits = append(newHits, h)
		}
	}

	if len(newHits) == 0 {
		return ScanResult{Domains: len(domains), Hits: len(hits)}, nil
	}

	// AI triage on new hits.
	triaged, err := s.triage(ctx, newHits)
	if err != nil {
		logger.Warn().Err(err).Msg("intel: triage failed — using heuristic fallback")
		triaged = s.triager.heuristicTriage(newHits)
	}

	if len(triaged) != len(newHits) {
		return ScanResult{}, fmt.Errorf("RunScan: triage returned %d results for %d hits", len(triaged), len(newHits))
	}

	// Assemble candidates.
	now := time.Now()
	var autoDismissed, unTriaged int
	candidates := make([]PhishingCandidate, 0, len(newHits))
	for i, h := range newHits {
		tr := triaged[i]
		status := StatusPending
		switch {
		case !tr.Known:
			// No verdict came back for this hit (a batch error, or an entry the
			// reply left out). It MUST stay pending: the zero value of
			// triageResult is {IsPhishing:false, Confidence:0}, which would
			// otherwise read as "confidently benign".
			unTriaged++
		case autoDismissible(h, tr):
			status = StatusAutoDismissed
			autoDismissed++
		}
		candidates = append(candidates, PhishingCandidate{
			ID:              CandidateID(h.CommonName, h.MonitoredDomain),
			Domain:          h.CommonName,
			MonitoredDomain: h.MonitoredDomain,
			Source:          "crt_sh",
			SimilarityScore: float32(h.Score),
			Issuer:          h.Issuer,
			NotBefore:       h.NotBefore,
			NotAfter:        h.NotAfter,
			Status:          status,
			AIIsPhishing:    tr.IsPhishing,
			AIConfidence:    float32(tr.Confidence),
			AIReasoning:     tr.Reasoning,
			TriageSource:    tr.Source,
			DetectedAt:      now,
		})
	}

	if err := s.ch.BulkUpsertCandidates(ctx, candidates); err != nil {
		return ScanResult{}, fmt.Errorf("RunScan: store candidates: %w", err)
	}

	// Only LLM verdicts count as AI-triaged; heuristic ones are reported apart.
	var aiCount, heuristicCount int
	for _, tr := range triaged {
		switch tr.Source {
		case TriageLLM:
			aiCount++
		case TriageHeuristic:
			heuristicCount++
		}
	}
	newCount := len(candidates)
	logger.Info().Int("new", newCount).Int("ai_triaged", aiCount).Int("heuristic_triaged", heuristicCount).
		Int("auto_dismissed", autoDismissed).Int("pending", newCount-autoDismissed).
		Int("untriaged_kept_pending", unTriaged).
		Msg("intel: scan complete")

	return ScanResult{
		Domains:          len(domains),
		Hits:             len(hits),
		New:              newCount,
		AITriaged:        aiCount,
		HeuristicTriaged: heuristicCount,
		AutoDismissed:    autoDismissed + rescored,
	}, nil
}

// reconcileQueue re-scores the rows already sitting in the human queue and
// auto-dismisses the ones that no longer clear the detection threshold.
//
// It exists because a candidate is written once and then never re-evaluated (the
// dedup set is every id ever seen, so a scan cannot correct an old row), which
// means a change to the similarity metric would otherwise apply only to future
// hits and leave the queue showing scores no code computes any more.
//
// Only ever pending → auto_dismissed, never the reverse and never a human's
// verdict: this is the same "the AI/metric cleared it" bucket, still readable,
// still explaining itself in ai_reasoning. Re-scoring is pure computation over
// stored fields — no CT query, no API call — so it is safe to run every scan and
// idempotent (a row that already lost the threshold is no longer pending).
func (s *Service) reconcileQueue(ctx context.Context) (int, error) {
	pending, _, err := s.ch.ListCandidates(ctx, StatusPending)
	if err != nil {
		return 0, fmt.Errorf("reconcileQueue: list pending: %w", err)
	}
	var stale []PhishingCandidate
	for _, c := range pending {
		score := float32(DomainSimilarity(c.Domain, c.MonitoredDomain))
		if score >= ctSimilarityThreshold {
			// Still a candidate. Refresh the score if the metric moved, so the
			// queue never displays a number nothing computes any more.
			if score != c.SimilarityScore {
				c.SimilarityScore = score
				stale = append(stale, c)
			}
			continue
		}
		c.SimilarityScore = score
		c.Status = StatusAutoDismissed
		c.AIReasoning = strings.TrimSpace(c.AIReasoning) +
			fmt.Sprintf(" %s %.2f, below the %.2f detection threshold — not a look-alike of %s]",
				rescoreNote, score, ctSimilarityThreshold, c.MonitoredDomain)
		stale = append(stale, c)
	}
	if len(stale) == 0 {
		return 0, nil
	}
	if err := s.ch.BulkUpsertCandidates(ctx, stale); err != nil {
		return 0, fmt.Errorf("reconcileQueue: rewrite: %w", err)
	}
	var dismissed int
	for _, c := range stale {
		if c.Status == StatusAutoDismissed {
			dismissed++
		}
	}
	log.FromContext(ctx).Info().Int("rescored", len(stale)).Int("auto_dismissed", dismissed).
		Msg("intel: re-scored the pending queue against the current similarity metric")
	return dismissed, nil
}

// autoDismissMaxConfidence is the highest P(phishing) at which the AI's "not
// phishing" verdict is allowed to clear a candidate without a human ever seeing
// it. Anything above it stays in the queue even when the verdict is benign.
//
// 0.35 is meant to sit between the two clusters the model is expected to
// produce: a benign verdict should come with low confidence and reasoning that
// names the benign explanation ("Standard subdomain of legitimate
// example.com"), while a suspected candidate should come back high. Keeping the
// cutoff well below the suspected range means loosening it would start
// clearing domains the model was unsure about.
//
// NOTE: this is the ONE place a candidate is removed from human review, so it is
// deliberately conservative on both inputs — the verdict must be benign AND the
// phishing confidence low. A missing verdict never qualifies (see RunScan), and
// the heuristic fallback (triage.go) reports the similarity score as its
// confidence, which is always ≥ ctSimilarityThreshold (0.65), so a scan running
// without an API key can never auto-dismiss anything.
const autoDismissMaxConfidence = 0.35

// autoDismissible reports whether a hit may be kept out of the human queue. The
// model's verdict is never sufficient on its own: the name it judged is
// attacker-authored, so the hit must also pass the deterministic plainHostname
// check — a long, wordy or instruction-like name stays pending whatever the
// model said about it.
func autoDismissible(h CTHit, tr triageResult) bool {
	return tr.Known && !tr.IsPhishing && tr.Confidence <= autoDismissMaxConfidence &&
		plainHostname(h.CommonName)
}
