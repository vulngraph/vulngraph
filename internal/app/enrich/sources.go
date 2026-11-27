package enrich

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Source names — stable identifiers used in the score breakdown.
const (
	sourceBaseSeverity = "base_severity"
	sourceKEV          = "kev"
	sourceBlastRadius  = "blast_radius"
	sourceTeamHistory  = "team_history"
	sourceAttackPaths  = "attack_paths"
	sourceToxicCombo   = "toxic_combo"
	sourceCrossCluster = "cross_cluster"
	sourceExposureType = "exposure_type"

	sourceInternetReach   = "internet_reach"
	sourceIdentityHygiene = "identity_hygiene"
	sourceFindingAge      = "finding_age"
	sourceDNSTakeover     = "dns_takeover"
	sourceTakeoverProbe   = "takeover_probe"
)

// blastDepth is how far the blast-radius walk reaches when sizing a finding's
// impact. Aliases graphschema.BlastDepth (the single source of truth shared
// with respond's decision-time walk) rather than redeclaring the literal —
// see that constant's doc for why the two must never drift independently.
const blastDepth = graphschema.BlastDepth

// ── base severity ───────────────────────────────────────────────────────────

// BaseSeverity maps the scanner's raw severity to a base contribution. This is
// what keeps raw severity an INPUT rather than the surfaced value.
type BaseSeverity struct{}

func (BaseSeverity) Name() string { return sourceBaseSeverity }

func (BaseSeverity) Evaluate(_ context.Context, f finding.Finding) (Factor, bool, error) {
	pts := 2 // unknown/info
	switch f.Severity {
	case finding.SeverityCritical:
		pts = 40
	case finding.SeverityHigh:
		pts = 30
	case finding.SeverityMedium:
		pts = 18
	case finding.SeverityLow:
		pts = 8
	}
	return Factor{Source: sourceBaseSeverity, Points: pts, Detail: string(f.Severity)}, true, nil
}

// ── KEV / threat intel ──────────────────────────────────────────────────────

// KEV contributes when a finding is flagged known-exploited (set on the finding
// by the KEV refresh job — no second catalog lifecycle here). A KEV hit
// floors the score so it always pages.
type KEV struct{}

func (KEV) Name() string { return sourceKEV }

func (KEV) Evaluate(_ context.Context, f finding.Finding) (Factor, bool, error) {
	if !f.KnownExploited {
		return Factor{}, false, nil
	}
	return Factor{
		Source: sourceKEV,
		Points: 30,
		Floor:  ThresholdPage,
		Detail: "known exploited (CISA KEV)",
	}, true, nil
}

// ── exposure type boost ─────────────────────────────────────────────────────

// ExposureType adds a base contribution for findings whose check type is
// "exposure" (internet-facing assets: public IP, open firewall, public
// bucket, NodePort service, etc.). Medium-severity exposure findings score
// only 18 from BaseSeverity, which keeps them below the high band even with
// blast radius — too low for assets directly reachable from the internet.
//
// This source adds a bonus that ensures exposure-type findings reach the
// high band (≥61) when they have any blast radius. It adds 12 points for
// medium and 0 for high/critical (which already have sufficient base).
// New intelligence domains are required to be separate Sources; this
// follows that pattern rather than hard-coding into BaseSeverity.
type ExposureType struct{}

func (ExposureType) Name() string { return sourceExposureType }

func (ExposureType) Evaluate(_ context.Context, f finding.Finding) (Factor, bool, error) {
	if f.Type != "exposure" {
		return Factor{}, false, nil
	}
	// Only boost medium-severity exposure findings — high and critical already
	// score high enough through BaseSeverity alone.
	if f.Severity != finding.SeverityMedium {
		return Factor{}, false, nil
	}
	return Factor{
		Source: sourceExposureType,
		Points: 12,
		Detail: "internet-facing asset (medium severity boosted to high band)",
	}, true, nil
}

// ── blast radius ────────────────────────────────────────────────────────────

// BlastRadiusProvider sizes a finding's reach. asset.Service implements it.
// The returned asset.BlastRadius already carries the full reachable-asset
// list (AccountID and Type per asset) — breakdownFromAssets below turns that
// into the per-account shape blastPoints needs, with no change to this
// interface or its implementation required. When a breakdown is built at all,
// it is built from THIS call's own asset list, and its own count becomes the
// score's `n` too — see countWithBreakdown for why a breakdown is never
// stitched onto a count from a different walk.
type BlastRadiusProvider interface {
	BlastRadius(ctx context.Context, seedID string, maxDepth int) (asset.BlastRadius, error)
}

// BlastRadiusCounter is the Ladybug reachable-count used for shadow comparison.
// graphstore.Service implements it. Counts distinct reachable Asset+IamRole nodes,
// excluding the seed — versus the ClickHouse provider's len(Assets), which walks all
// edge types and includes the seed. See Shadow below.
//
// BlastRadiusCounter deliberately stays a plain count, not a breakdown: Ladybug's
// Cypher variable-length traversal is the fast path specifically because it
// does the walk in one query without materialising every node in Go, and a
// GROUP BY dimension would give that up for every finding just to serve the
// minority that need it. See countWithBreakdown for how the two providers are
// combined instead.
type BlastRadiusCounter interface {
	BlastRadiusCount(ctx context.Context, seedID string, depth int) (int, error)
}

// BlastRadius scores how many assets a finding's resource can reach — a wider
// blast radius is riskier.
//
// Counter (Ladybug) is the primary when set: a single variable-length Cypher
// traversal replaces the sequential ClickHouse BFS (hundreds of queries →
// one query per finding). Provider (ClickHouse) is the fallback when Ladybug is
// unavailable or returns an error. Set Counter = graphstore.Service in
// production; leave nil for tests or when Ladybug is disabled.
type BlastRadius struct {
	Provider BlastRadiusProvider // CH BFS fallback (asset.Service)
	Counter  BlastRadiusCounter  // Ladybug primary (graphstore.Service); nil → use Provider
}

func (BlastRadius) Name() string { return sourceBlastRadius }

// BlastRadiusCount answers the plain-count question through the same
// Ladybug-primary/ClickHouse-fallback traversal countWithBreakdown already runs
// for scoring, discarding the breakdown. This makes BlastRadius itself satisfy
// BlastRadiusCounter, so a caller wires the whole source rather than the bare
// Ladybug Counter (no fallback, unmeasured whenever Ladybug is down) — must-fix
// classification then measures blast radius via the exact same traversal
// scoring uses, and the two can never disagree about HOW
// it was measured, only (if at all) the resulting count.
func (b BlastRadius) BlastRadiusCount(ctx context.Context, seedID string, depth int) (int, error) {
	n, _, err := b.countWithBreakdown(ctx, seedID)
	return n, err
}

func (b BlastRadius) Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error) {
	if f.ResourceID == "" {
		return Factor{}, false, nil
	}
	n, bd, err := b.countWithBreakdown(ctx, f.ResourceID)
	if err != nil {
		return Factor{}, false, fmt.Errorf("blast radius: %w", err)
	}
	pts, detail := blastPoints(n, bd)
	return Factor{
		Source: sourceBlastRadius,
		Points: pts,
		Detail: detail,
	}, true, nil
}

// blastAccountCap is the maximum number of reachable assets in a SINGLE
// account/project that count as independent blast targets. Assets in that
// same account beyond the cap are evidence of a shared identity mesh (e.g.
// GCP service-account impersonation, which fans out project-wide, not per
// finding) rather than additional independent exposure.
//
// This constant doubles as the ONLY count-based branch left in the blast
// scoring path (see confirmBreakdown): a breakdown can never change the score
// of a count at or below the cap, because every account's contribution is
// already <= the cap, so summing min(contribution, cap) per account is a
// no-op. That is an exact algebraic bound, not a guess about where tiers
// happen to land — a threshold based on tier-boundary guessing was tried
// and produced a non-monotonic score (a lower count scoring higher than a
// count just above it), which this replaces.
const blastAccountCap = 3

// BlastBreakdown is the per-account shape behind a reachable-asset count.
// It is always built from, and only ever paired with, the SAME walk's own
// total (see countWithBreakdown) — never stitched onto a count from a
// different engine's traversal, so Total below is always exactly the score's
// `n`. blastPoints trusts that invariant instead of re-deriving or scaling.
type BlastBreakdown struct {
	// Total is the number of reachable assets (excluding the seed) the
	// breakdown was built from — the same walk's own count, always.
	Total int
	// ByAccount counts reachable assets per AccountID. An asset with an empty
	// AccountID gets its own singleton entry (keyed by its index) rather than
	// being merged with other accountless assets: assets with no account in
	// common share no blast surface, so treating them as one cluster would
	// discount unrelated exposure instead of a real identity mesh.
	ByAccount map[string]int
}

// breakdownFromAssets groups a ClickHouse BlastRadius walk's reachable assets
// by AccountID, excluding the seed asset itself (asset.BlastRadius.Assets
// includes it, but the seed is not part of its own reach).
func breakdownFromAssets(seedID string, assets []asset.Asset) BlastBreakdown {
	bd := BlastBreakdown{ByAccount: make(map[string]int, len(assets))}
	n := 0
	for i, a := range assets {
		if a.ID == seedID {
			continue
		}
		key := a.AccountID
		if key == "" {
			key = fmt.Sprintf("__singleton_%d", i)
		}
		bd.ByAccount[key]++
		n++
	}
	bd.Total = n
	return bd
}

// countWithBreakdown returns the reachable-asset count and, when available,
// its per-account breakdown. Ladybug (single Cypher query, the hot path across
// 16 enrich workers) drives the count when set; ClickHouse's BFS is the
// fallback when Ladybug is unavailable or errors.
//
// The breakdown itself always comes from ClickHouse — Ladybug's
// BlastRadiusCounter deliberately stays a plain count with no per-account
// dimension (see its doc) — but WHENEVER a ClickHouse breakdown is fetched at
// all, its own total REPLACES n as the score's count (see confirmBreakdown):
// a breakdown is never stitched onto a count from a different walk, which
// would let a same-VPC cluster that exists only in ClickHouse's edge set
// wrongly demote a Ladybug-measured, genuinely broad finding. The two paths
// below therefore reach the identical (n, bd) pair for identical underlying
// data regardless of which one ran.
//
// When no breakdown is available at all (Provider unset, Ladybug
// count within blastAccountCap, or the confirmatory call errors), bd is nil
// and blastPoints scores on the raw count unchanged — absence of breakdown
// evidence must never manufacture a discount.
func (b BlastRadius) countWithBreakdown(ctx context.Context, resourceID string) (int, *BlastBreakdown, error) {
	if b.Counter != nil {
		n, err := b.Counter.BlastRadiusCount(ctx, resourceID, blastDepth)
		if err == nil {
			if bd := b.confirmBreakdown(ctx, resourceID, n); bd != nil {
				return bd.Total, bd, nil
			}
			return n, nil, nil
		}
		log.FromContext(ctx).Warn().Err(err).Str("resource_id", resourceID).
			Msg("blast_radius: ladybug count failed, falling back to ClickHouse")
	}
	if b.Provider == nil {
		return 0, nil, nil
	}
	br, err := b.Provider.BlastRadius(ctx, resourceID, blastDepth)
	if err != nil {
		return 0, nil, err
	}
	bd := breakdownFromAssets(resourceID, br.Assets)
	if br.Truncated {
		// The visited assets are a lower bound, not an account distribution
		// for the whole walk. A partial sample must never establish a discount.
		return bd.Total, nil, nil
	}
	return bd.Total, &bd, nil
}

// confirmBreakdown fetches the ClickHouse account breakdown for a Ladybug-driven
// count. It skips the round trip only when n is already at or below
// blastAccountCap — an exact bound (see blastAccountCap doc), not a magic
// count threshold: no breakdown shape can discount a count that low, so
// skipping there can never diverge from the un-skipped answer. Errors are
// swallowed to a nil breakdown: the Ladybug count already stands as the score,
// and a failed confirmation must not block or degrade it (see
// countWithBreakdown doc). A truncated walk is also insufficient evidence for
// discounting: its account sample may omit independent targets.
func (b BlastRadius) confirmBreakdown(ctx context.Context, resourceID string, n int) *BlastBreakdown {
	if n <= blastAccountCap || b.Provider == nil {
		return nil
	}
	br, err := b.Provider.BlastRadius(ctx, resourceID, blastDepth)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("resource_id", resourceID).
			Msg("blast_radius: account breakdown fetch failed, scoring without same-account dedupe")
		return nil
	}
	if br.Truncated {
		return nil // retain the native count; an incomplete sample cannot discount it
	}
	bd := breakdownFromAssets(resourceID, br.Assets)
	return &bd
}

// blastPoints weights the reachable-asset count into a score contribution and
// the human/LLM-facing explanation of it, from the SAME numbers — one source
// of truth for whether a finding's score was discounted, and why.
//
// At blastDepth = 2 the walk crosses the service-account impersonation mesh,
// which in GCP is project-wide: without the per-account cap below, a finding
// in a project with a large service-account population would report that
// population as its own blast radius — every privesc finding in the project
// landing in the same top tier together, regardless of its own actual reach.
//
// bd, when non-nil, breaks the count down by account (see BlastBreakdown).
// EVERY account's contribution is capped at blastAccountCap independently —
// not just the single dominant one: two distinct smaller meshes are just as
// much shared-identity fan-out as one large one, and capping only the
// dominant cluster would under-discount the rest. There is no "is n above/
// below some magic count" branch here at all — bd is either present (score
// from its capped per-account sum) or absent (score from the raw count); see
// countWithBreakdown for why that is the only distinction that can ever
// arise from a Ladybug-up/Ladybug-down difference.
func blastPoints(n int, bd *BlastBreakdown) (points int, detail string) {
	total := n
	if bd != nil {
		// bd always carries its own walk's total (see countWithBreakdown) —
		// never a count from a different engine's traversal.
		total = bd.Total
	}
	if total <= 0 {
		return 0, "0 reachable assets"
	}
	effective := total
	cappedAccounts := 0
	if bd != nil {
		capped := 0
		for _, c := range bd.ByAccount {
			if c > blastAccountCap {
				c = blastAccountCap
				cappedAccounts++
			}
			capped += c
		}
		effective = capped
	}
	switch {
	case effective <= 3:
		points = 4
	case effective <= 10:
		points = 10
	case effective <= 50:
		points = 16
	default:
		points = 20
	}
	if cappedAccounts > 0 {
		detail = fmt.Sprintf(
			"%d reachable assets (%d account(s) over %d capped as shared identity mesh, not independent targets — %d counted)",
			total, cappedAccounts, blastAccountCap, effective)
	} else {
		detail = fmt.Sprintf("%d reachable assets", total)
	}
	return points, detail
}

// ── team history ────────────────────────────────────────────────────────────

// AssetConfidenceProvider reports how we have historically fared on an asset
// type across all action classes. memory.Service implements it.
type AssetConfidenceProvider interface {
	AssetConfidence(ctx context.Context, assetType string) (memory.Confidence, error)
}

// TeamHistory inverts our track record on an asset type into risk: an asset type
// we handle reliably scores 0, one we handle poorly scores more.
//
// No track record (insufficient evidence) scores 0, not the maximum: Vulngraph
// never executes remediations on its own (ADR 087), so almost no asset type
// accrues outcomes, and scoring "insufficient" high would be a near-constant +10
// on every finding — a measurement of nothing that pushes whole populations
// across band thresholds. Absence of history is not evidence of risk.
type TeamHistory struct{ Provider AssetConfidenceProvider }

func (TeamHistory) Name() string { return sourceTeamHistory }

func (t TeamHistory) Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error) {
	conf, err := t.Provider.AssetConfidence(ctx, f.ResourceType)
	if err != nil {
		return Factor{}, false, fmt.Errorf("team history: %w", err)
	}
	pts := 0
	switch conf.Band {
	case memory.BandInsufficient:
		pts = 0
	case memory.BandLow:
		pts = 8
	case memory.BandMedium:
		pts = 4
	case memory.BandHigh:
		pts = 0
	}
	return Factor{Source: sourceTeamHistory, Points: pts, Detail: string(conf.Band)}, true, nil
}
