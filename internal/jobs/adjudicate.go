package jobs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/belief"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// adjudicateSweepMax bounds how many backlog findings a single tick pulls and
// assembles context for. Kept modestly above the adjudicator's MaxPerSweep so the
// "deferred" signal is real (the cap is throttling coverage) without assembling a
// large multiple of context packs we won't use this sweep. The candidates are the
// least-recently-adjudicated eligible findings (Adjudicator.Backlog), so the
// overflow beyond the cap is deferred to — and picked up first by — the next sweep.
const adjudicateSweepMax = 60

// adjudicateJobTimeout overrides River's 1-minute default JobTimeout: unlike a
// per-finding decide (one LLM call), a sweep makes many sequential adversarial
// samples, so the whole sweep needs room. Kept under the 30-min sweep interval so
// consecutive sweeps don't overlap. Beliefs are persisted incrementally as the
// sweep runs, so even a timeout leaves partial progress that the next sweep resumes.
const adjudicateJobTimeout = 20 * time.Minute

// AdjudicateArgs is the periodic tick of the severity adjudicator:
// it re-examines high-band findings whose severity is not already
// deterministically resolved and, on disagreement, forms a grounded belief. It is
// only registered when a *belief.Adjudicator is wired (ADJUDICATOR_ENABLED) — the
// posture is dark until deliberately turned on, because it spends LLM budget.
type AdjudicateArgs struct{}

func (AdjudicateArgs) Kind() string { return "adjudicate" }

func (AdjudicateArgs) InsertOpts() river.InsertOpts {
	// Dedicated queue: the sweep runs for up to adjudicateJobTimeout (20m), so it
	// gets its own single-worker lane and never blocks the respond queue's
	// per-finding reasoning (decide) or operator remediations (executor).
	// Singleton with 2 attempts (periodicSingletonOpts): each attempt spends LLM
	// budget, and beliefs persist incrementally so the next tick resumes.
	return periodicSingletonOpts(queueAdjudicate, 2)
}

// Timeout gives the sweep the whole window (River defaults to 1 minute, which only
// fits a single LLM call — a sweep makes many).
func (w *AdjudicateWorker) Timeout(*river.Job[AdjudicateArgs]) time.Duration {
	return adjudicateJobTimeout
}

// ContextAssembler assembles the grounded connected-graph/live/CSPM context for a
// finding. *respond.Service satisfies it via its Context method — reused so the
// adjudicator reasons over the exact same context the remediation reasoner sees.
type ContextAssembler interface {
	Context(ctx context.Context, f finding.Finding) (respond.ContextPack, error)
}

// PublicAccessLookup reports whether a resource is CONFIRMED publicly accessible
// by config (asset public_access = confirmed) — an independent, different-lineage
// witness the corroboration gate uses to catch a demotion of a genuinely-exposed
// resource. Nil disables the public-access witness (the gate then relies only on
// the co-located exposure signal).
type PublicAccessLookup interface {
	PublicAccessConfirmed(ctx context.Context, resourceID string) (bool, error)
}

// assetGetter is the slice of the asset service the public-access lookup needs.
type assetGetter interface {
	Get(ctx context.Context, id string) (asset.Asset, error)
}

// ExposedEdgeLookup reports whether a resource has a live exposed_to_internet
// edge — a FRESH graph re-query of a DIFFERENT lineage than the cached
// internet-hops reachability signal. This is the independent witness the
// corroboration gate needs so a reachability veto does not rest on the same
// (poisonable) signal the verdict already reasoned over. *asset.Service satisfies
// it via IsExposedEdge. Nil disables the witness (the gate then relies on
// public-access / co-located exposure only).
type ExposedEdgeLookup interface {
	IsExposedEdge(ctx context.Context, assetID string) (bool, error)
}

// assetPublicAccess adapts the asset service to PublicAccessLookup by reading the
// collector-stamped public_access metadata key (asset.PublicAccessConfirmed).
type assetPublicAccess struct{ assets assetGetter }

func (a assetPublicAccess) PublicAccessConfirmed(ctx context.Context, resourceID string) (bool, error) {
	as, err := a.assets.Get(ctx, resourceID)
	if err != nil {
		return false, err
	}
	return as.Metadata["public_access"] == asset.PublicAccessConfirmed, nil
}

// FindingByIDs hydrates the candidate finding rows the backlog cursor selected.
// *finding.Service satisfies it via its ByIDs method.
type FindingByIDs interface {
	ByIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
}

// AdjudicateWorker pulls the least-recently-adjudicated backlog candidates, gates
// them through belief.NeedsAdjudication, assembles context, and hands them to the
// cost-bounded adjudicator.
type AdjudicateWorker struct {
	river.WorkerDefaults[AdjudicateArgs]
	findings     FindingByIDs
	assembler    ContextAssembler
	publicAccess PublicAccessLookup
	exposedEdge  ExposedEdgeLookup
	adjudicator  *belief.Adjudicator
	metrics      *obs.Metrics
}

func (w *AdjudicateWorker) Work(ctx context.Context, _ *river.Job[AdjudicateArgs]) error {
	logger := log.FromContext(ctx)

	// Backlog cursor: the eligible high-band findings that haven't been freshly
	// adjudicated, least-recently-adjudicated first — not score-desc, which would
	// re-read the same top-of-list every sweep and never descend into the
	// backlog. Writing a belief per processed finding moves it out of this set,
	// so each sweep advances to findings the previous ones didn't reach.
	ids, err := w.adjudicator.Backlog(ctx, enrich.ThresholdHigh, adjudicateSweepMax)
	if err != nil {
		return fmt.Errorf("Work: backlog: %w", err)
	}
	batch, err := w.findings.ByIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("Work: hydrate candidates: %w", err)
	}

	now := time.Now()
	var cands []belief.Candidate
	for _, f := range batch {
		si := belief.SeverityInputs{
			FindingID:     f.ID,
			ResourceID:    f.ResourceID,
			Score:         f.Score,
			Band:          f.ScoreBand,
			MustFixClass:  f.MustFixClass,
			MustFixReason: f.MustFixReason,
		}
		// Attention gate: only findings whose severity is NOT already
		// deterministically resolved (controlled/contained/must_fix) are worth an
		// LLM opinion — everything else keeps the enrich-time deterministic belief.
		if !belief.NeedsAdjudication(si) {
			continue
		}
		// Best-effort context: a finding with a thin/failed context still gets
		// adjudicated (the sampler is told to return low when the context is thin),
		// so a graph hiccup never silently drops it from the sweep.
		pack, err := w.assembler.Context(ctx, f)
		if err != nil {
			logger.Warn().Err(err).Str("finding_id", f.ID).Msg("adjudicate: context assembly failed; using finding-only context")
		}
		// Independent exposure witnesses for the corroboration gate. public_access
		// is config-lineage (not in the reachability context the LLM saw), so it is
		// a true external cross-check; exposure is the co-located peer signal;
		// the must-fix reachability witness carries the deterministic layer's
		// positive internet-reachability evidence, so a demotion that contradicts
		// it (the identity category-error trap) is flagged instead of accepted.
		facts := belief.GroundingFacts{
			ExposureConfirmed: pack.Exposure.InternetFacing,
			// A failed peer-findings query (or a failed context assembly
			// entirely, in which case pack is the zero value) must not read
			// the same as "queried and found no exposure peer" — see
			// ExposureFlags.PeersKnown's doc.
			ExposurePeersKnown: pack.Exposure.PeersKnown,
			// A failed blast walk renders as "unknown", never 0. A finding with no
			// resource has nothing to walk — the not-applicable case, like an
			// unwired witness provider below.
			BlastKnown:            pack.Blast.Known || f.ResourceID == "",
			ReachabilityEvidenced: enrich.ReachabilityEvidenced(f.MustFixClass, f.MustFixReason),
			ReachabilityReason:    f.MustFixReason,
		}
		// PublicAccessKnown/ExposedEdgeKnown default to true when the
		// provider isn't wired at all — a permanent, deliberate absence of
		// this witness (see GroundingFacts' doc), the same "no independent
		// witness — the common, correct case — is left untouched" behavior
		// corroborationConflict has. This is DELIBERATELY
		// different from the blast-radius GATE's known-ness (which fails
		// closed even on "not applicable"): the corroboration gate is an
		// escalate-for-review trigger, not an autonomy-granting one, and
		// conflating "no witness available in this deployment" with "witness
		// available but this one call failed" would flag EVERY demotion for
		// review in any deployment lacking full witness coverage — defeating
		// the adjudicator's purpose rather than hardening it. Known is set
		// false ONLY when a wired provider was actually called and errored.
		facts.PublicAccessKnown = true
		if w.publicAccess != nil && f.ResourceID != "" {
			if confirmed, err := w.publicAccess.PublicAccessConfirmed(ctx, f.ResourceID); err == nil {
				facts.PublicAccessConfirmed = confirmed
			} else {
				// A failed lookup must never read the same as a confirmed
				// "not publicly exposed" — flag it so the corroboration
				// gate treats this demotion as unable-to-corroborate rather
				// than silently letting it through.
				facts.PublicAccessKnown = false
				logger.Warn().Err(err).Str("finding_id", f.ID).
					Msg("adjudicate: public-access witness lookup failed")
			}
		}
		// Independent exposed-edge witness: a fresh graph re-query of the resource's
		// OWN exposed_to_internet edge, of a different lineage than the cached
		// reachability signal. This is what makes a reachability veto trustworthy —
		// a genuinely exposed network resource has a live edge; an identity never
		// does, so the gate never defends a false 0-hop reach claim on a principal.
		facts.ExposedEdgeKnown = true
		if w.exposedEdge != nil && f.ResourceID != "" {
			if present, err := w.exposedEdge.IsExposedEdge(ctx, f.ResourceID); err == nil {
				facts.ExposedEdgePresent = present
			} else {
				facts.ExposedEdgeKnown = false
				logger.Warn().Err(err).Str("finding_id", f.ID).
					Msg("adjudicate: exposed-edge witness lookup failed")
			}
		}
		cands = append(cands, belief.Candidate{
			Input: belief.AdjudicationInput{
				FindingID:  f.ID,
				ResourceID: f.ResourceID,
				Title:      f.Title,
				RawScore:   f.Score,
				RawBand:    f.ScoreBand,
				Context:    renderAdjudicationContext(f, pack, facts.ExposedEdgePresent),
			},
			DeterministicSeverity: belief.Reconcile(si, now).Severity,
			Facts:                 facts,
		})
	}

	res, err := w.adjudicator.Run(ctx, cands)
	if err != nil {
		return fmt.Errorf("Work: adjudicate: %w", err)
	}

	w.metrics.ObserveAdjudication("cached", res.Cached)
	w.metrics.ObserveAdjudication("agreed", res.Agreed)
	w.metrics.ObserveAdjudication("adjudicated", res.Adjudicated)
	w.metrics.ObserveAdjudication("escalated", res.Escalated)
	w.metrics.ObserveAdjudication("corroboration_downgrade", res.Downgraded)
	w.metrics.ObserveAdjudication("deferred", res.Deferred)
	w.metrics.ObserveAdjudication("sample_error", res.SampleErrors)
	evt := logger.Info()
	if res.SampleErrors > 0 {
		// A non-zero sample-error count means the LLM sampler is (partly) broken —
		// bad model id, API error, or verdicts that fail the grounding contract.
		// Warn with the first error so it never hides behind "0 adjudicated".
		evt = logger.Warn().Str("first_sample_error", res.FirstSampleErr)
	}
	evt.
		Int("considered", res.Considered).Int("cached", res.Cached).Int("agreed", res.Agreed).
		Int("adjudicated", res.Adjudicated).Int("escalated", res.Escalated).
		Int("downgraded", res.Downgraded).
		Int("deferred", res.Deferred).Int("sample_errors", res.SampleErrors).
		Msg("adjudication sweep complete")

	// Crystallization: surface the stable, corroboration-surviving
	// patterns that are candidates to become cheap deterministic rules. Report-only
	// (log + metric) — no auto-application. Best-effort: never fail the sweep on it.
	if cands, err := w.adjudicator.MineCrystallization(ctx); err != nil {
		logger.Warn().Err(err).Msg("adjudicate: crystallization mining skipped")
	} else {
		w.metrics.ObserveAdjudication("crystallization_candidate", len(cands))
		for _, c := range cands {
			logger.Info().Str("signature", c.Sig.String()).Str("severity", string(c.Severity)).
				Int("instances", c.Instances).Msg("crystallization candidate")
		}
	}
	return nil
}

// renderAdjudicationContext renders the grounding the adjudicator reasons over:
// the concrete graph/enrich signals behind the raw score. Plain text (the sampler
// fences the whole block as untrusted), compact, and factual — no interpretation.
func renderAdjudicationContext(f finding.Finding, pack respond.ContextPack, exposedEdgePresent bool) string {
	var b strings.Builder
	identity := enrich.IsIdentityResource(f.ResourceType)
	fmt.Fprintf(&b, "Enriched score: %d (%s)\n", f.Score, f.ScoreBand)
	if f.MustFixClass != "" {
		fmt.Fprintf(&b, "Must-fix class: %s", f.MustFixClass)
		if f.MustFixReason != "" {
			// The scoping label may only go on a reason that actually MAKES a
			// reachability claim. Most verdicts (e.g. `routine`) say something else
			// entirely, and labeling those as a reachability claim would invent
			// evidence in a prompt whose discipline is "cite only facts present in
			// the context".
			if identity && enrich.ReachabilityEvidenced(f.MustFixClass, f.MustFixReason) {
				// Scope the reachability claim so it cannot be "refuted" by the
				// identity's own exposure facts: it is about the SOURCE asset.
				fmt.Fprintf(&b, " — reachability claim (scope: the internet-exposed SOURCE asset in the trust path, NOT this identity): %s", f.MustFixReason)
			} else {
				fmt.Fprintf(&b, " — %s", f.MustFixReason)
			}
		}
		b.WriteByte('\n')
	}
	if identity {
		// An identity's own internet_facing=false must not be read as refuting
		// "assumable from an internet-exposed asset" — that claim is about the
		// source asset, not the identity.
		fmt.Fprintf(&b, "Exposure: identity_itself_internet_facing=%t (identities are never network endpoints — this does NOT contradict reachability via a trust path), privileged=%t\n",
			pack.Exposure.InternetFacing, pack.Exposure.Privileged)
	} else {
		fmt.Fprintf(&b, "Exposure: internet_facing=%t, privileged=%t\n", pack.Exposure.InternetFacing, pack.Exposure.Privileged)
	}
	// Independent exposed-edge witness (fresh graph re-query, different lineage than
	// the cached reachability signal). A must-fix reachability claim with NO live
	// exposed edge and no other exposure witness is a STRUCTURAL CONTRADICTION the
	// verdict may act on — this is the signal that lets the model refute a poisoned
	// 0-hop reach label, per the MUST-FIX CLASS RULE.
	fmt.Fprintf(&b, "Exposed_to_internet edge (fresh graph re-query): present=%t\n", exposedEdgePresent)
	switch {
	case pack.Blast.Known:
		fmt.Fprintf(&b, "Blast radius: %d reachable asset(s)", pack.Blast.Count)
		if pack.Blast.Truncated {
			b.WriteString(" (truncated)")
		}
	case f.ResourceID == "":
		b.WriteString("Blast radius: not applicable (no resource)")
	default:
		b.WriteString("Blast radius: unknown (lookup failed)")
	}
	b.WriteByte('\n')
	if len(pack.Blast.CanAssume) > 0 {
		fmt.Fprintf(&b, "Privilege paths: %s\n", strings.Join(pack.Blast.CanAssume, ", "))
	}
	for _, line := range pack.Impact.PromptLines() {
		fmt.Fprintf(&b, "Impact: %s\n", line)
	}
	if pack.CVE != nil {
		fmt.Fprintf(&b, "Exploitability: EPSS=%.1f%% KEV=%t", pack.CVE.EPSS*100, pack.CVE.KEV)
		if pack.CVE.FixedVersion != "" {
			fmt.Fprintf(&b, " fix=%s", pack.CVE.FixedVersion)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
