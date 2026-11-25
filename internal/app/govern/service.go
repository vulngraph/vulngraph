package govern

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// pendingScanLimit caps how many pending decisions the queue assembles from.
// There are far fewer pending decisions than findings, so this is a generous
// backstop, not a paging boundary.
const pendingScanLimit = 1000

// Verdicts stores governor verdicts. PGRepo implements it.
type Verdicts interface {
	Upsert(ctx context.Context, findingID, clusterKey string, verdict Verdict, actor, note, fingerprint string) error
	// ResolvedFingerprints maps a resolved finding id to the context fingerprint
	// captured when its verdict was recorded (empty if none was known).
	ResolvedFingerprints(ctx context.Context) (map[string]string, error)
}

// Pending reads the cached decisions awaiting a governor. reasoncache.Service
// implements it.
type Pending interface {
	// ListPending returns cached decisions awaiting a governor, capped at
	// limit. actionClass narrows the scan to a single action class
	// server-side, ahead of the cap — "" means unfiltered.
	ListPending(ctx context.Context, limit int, actionClass string) ([]reasoncache.Entry, error)
}

// Findings resolves decision targets to their finding context. finding.Service
// implements it.
type Findings interface {
	ByIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
}

// Outcomes feeds a human verdict back into decaying memory, the only evidence
// the confidence ledger learns from.
// memory.Service implements it.
type Outcomes interface {
	Record(ctx context.Context, o memory.Outcome) error
}

// Audit appends the governor's verdict to the durable trail. respond.CHRepo
// implements it.
type Audit interface {
	Record(ctx context.Context, e respond.AuditEvent) error
}

// PolicySnapshot is the subset of the remediation policy that govern needs.
// Values are a point-in-time snapshot fetched once per Queue call.
type PolicySnapshot struct {
	// SuggestThreshold is the minimum confidence (0-100) for parking a decision
	// for human approval. Below this the item is escalated.
	SuggestThreshold int
	// ActionRules maps action-class strings to "jit" (requires approval) or
	// "disabled" (guidance only). A missing key defaults to threshold-based
	// routing between parked and escalated.
	ActionRules map[string]string
}

// PolicyReader is the narrow read interface govern uses to fetch the current
// policy. policy.Service satisfies it via a thin adapter in serve.go.
type PolicyReader interface {
	Get(ctx context.Context) (PolicySnapshot, error)
}

// PatternVerdicts persists the latest governor verdict for a (check_id,
// action_class, resource_type) pattern, independent of any specific finding —
// the "have we ruled on this class of decision before" record respond.Decide
// consults before short-circuiting a decision. PGRepo implements it.
// Optional: without it, Resolve records finding-level verdicts only.
// resourceType scopes the ruling: a denial on s3_bucket must never suppress
// the same (check, action) pattern on rds_instance or any other resource type.
type PatternVerdicts interface {
	UpsertPattern(ctx context.Context, checkID, actionClass, resourceType string, verdict Verdict, actor string) error
	PatternVerdict(ctx context.Context, checkID, actionClass, resourceType string) (Verdict, time.Time, bool, error)
}

// ConfidenceReader looks up decaying-memory learning progress for an (action
// class, asset type) key. Used to annotate the queue with teaching value —
// which pending cluster's resolution would grow confidence the most.
// memory.Service implements this.
type ConfidenceReader interface {
	Confidence(ctx context.Context, actionClass, assetType string) (memory.Confidence, error)
}

type Service struct {
	verdicts   Verdicts
	pending    Pending
	findings   Findings
	outcomes   Outcomes
	audit      Audit
	notifier   ApprovalNotifier // optional; fires when a governor approves
	policy     PolicyReader     // optional; applies per-class rules and the suggest threshold to queue items
	confidence ConfidenceReader // optional; enables teaching-value queue ordering
	patterns   PatternVerdicts  // optional; enables pattern-level verdict persistence
	nonces     LinkNonces       // optional; without it email approval links are refused
	now        func() time.Time
}

func NewService(v Verdicts, p Pending, f Findings, o Outcomes, a Audit) *Service {
	return &Service{verdicts: v, pending: p, findings: f, outcomes: o, audit: a, now: time.Now}
}

// WithApprovalNotifier wires the outbound notification for approved decisions.
// When set, every approval fires a POST to the notifier so downstream systems
// (Jira, Linear, Slack) can create actionable work items. Best-effort — a
// notifier failure must not fail the audit trail.
func (s *Service) WithApprovalNotifier(n ApprovalNotifier) *Service {
	s.notifier = n
	return s
}

// WithPolicy wires the remediation policy reader. When set, Queue drops the
// action classes the policy marks guidance-only and labels each remaining
// item's Outcome ("parked_for_approval" / "escalated") from the per-class rules
// and the suggest threshold, purely for display — the queue only ever holds
// decisions respond.Decide already parked or escalated, and nothing here
// executes anything. Safe to omit — without a policy, items keep the outcome
// respond.Decide cached for them.
func (s *Service) WithPolicy(p PolicyReader) *Service {
	s.policy = p
	return s
}

// WithConfidence wires the decaying-memory confidence reader. When set, Queue
// annotates each cluster with its teaching value (ConfidenceEffectiveN,
// ConfidenceGap, Unlocks) and sorts the queue so the cluster closest to
// crossing minEffectiveN for its confidence key surfaces first. Safe to omit —
// without it the queue keeps its worst-score-first order unchanged.
func (s *Service) WithConfidence(c ConfidenceReader) *Service {
	s.confidence = c
	return s
}

// WithPatterns wires pattern-level verdict persistence. When set, every Resolve
// also upserts the (check_id, action_class, resource_type) pattern's latest
// verdict, and PatternVerdict becomes queryable. Safe to omit — pattern
// verdicts are purely additive. respond.Decide consults them via
// PatternVerdict once WithPatternVerdicts is wired on its side.
func (s *Service) WithPatterns(p PatternVerdicts) *Service {
	s.patterns = p
	return s
}

// Queue assembles the pending decisions awaiting a governor, clustered by check +
// action class and ordered worst-score first. Already-resolved findings are
// excluded. No new reasoning happens here — it surfaces decisions respond already
// made. actionClass narrows the queue to a single action class, filtered
// server-side ahead of pendingScanLimit — "" means unfiltered.
func (s *Service) Queue(ctx context.Context, actionClass string) ([]QueueItem, error) {
	entries, err := s.pending.ListPending(ctx, pendingScanLimit, actionClass)
	if err != nil {
		return nil, fmt.Errorf("Queue: %w", err)
	}
	resolved, err := s.verdicts.ResolvedFingerprints(ctx)
	if err != nil {
		return nil, fmt.Errorf("Queue: %w", err)
	}

	// Drop resolved decisions, then resolve the rest to finding context. A verdict
	// holds only while the finding's context is unchanged: if the fingerprint has
	// moved since the verdict (worsened — new exposure/KEV/privesc, a score-band
	// shift), the standing verdict no longer applies and the finding re-surfaces.
	var ids []string
	pending := entries[:0]
	for _, e := range entries {
		if fp, ok := resolved[e.FindingID]; ok && fp == e.Fingerprint {
			continue
		}
		pending = append(pending, e)
		ids = append(ids, e.FindingID)
	}
	if len(pending) == 0 {
		return nil, nil
	}

	findings, err := s.findings.ByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("Queue: %w", err)
	}
	byID := make(map[string]finding.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}

	items, dominantResourceType := clusterQueue(pending, byID)
	items = s.applyPolicyRules(ctx, items)
	items = s.annotateTeachingValue(ctx, items, dominantResourceType)
	return items, nil
}

// applyPolicyRules re-labels each queue item's Outcome against the remediation
// policy, for display only — see WithPolicy:
//  1. "disabled" (guidance only): removes the item from the approval queue,
//     unless it is Urgent (then escalated).
//  2. "jit" (requires approval): outcome = "parked_for_approval".
//  3. Default (no rule): the cluster's minimum confidence score (0..1 scaled
//     to 0-100) against SuggestThreshold — at or above it parks for approval,
//     below it escalates.
//
// Every outcome waits for a human: there is no rule under which a queue item
// proceeds on its own (ADR 087). Best-effort — if the policy cannot be fetched
// all items are returned unchanged.
//
// This does NOT gate any real action: it runs after respond.Decide already
// made and cached the gated decision for every item that reaches this
// queue, and nothing reads the re-labeled Outcome to drive an executor.
func (s *Service) applyPolicyRules(ctx context.Context, items []QueueItem) []QueueItem {
	if s.policy == nil || len(items) == 0 {
		return items
	}
	pol, err := s.policy.Get(ctx)
	if err != nil {
		return items // fail open: policy unavailable, show every item with its original outcome
	}

	out := items[:0]
	for i := range items {
		it := items[i]
		mode := pol.ActionRules[it.ActionClass] // "" when no rule

		switch mode {
		case "disabled":
			// Skip entirely — do not add to queue — unless the evidence says
			// it is urgent: a guidance-only class must not hide an urgent
			// finding the model planned as, say, observe.
			if !it.Urgent {
				continue
			}
			it.Outcome = "escalated"

		case "jit":
			it.Outcome = "parked_for_approval"

		default:
			// No per-class rule: the cluster's minimum confidence score decides
			// how urgently a human is asked, never whether one is.
			if int(it.ConfidenceScore*100) >= pol.SuggestThreshold {
				it.Outcome = "parked_for_approval"
			} else {
				it.Outcome = "escalated"
			}
		}

		out = append(out, it)
	}
	return out
}

// confKey is the (action class, dominant resource type) pair that identifies a
// decaying-memory confidence bucket for teaching-value purposes.
type confKey struct{ actionClass, resourceType string }

// annotateTeachingValue looks up each cluster's confidence progress and sorts
// the queue so the cluster whose resolution would make the most teaching
// progress — closest to crossing memory.MinEffectiveN for its confidence
// key — surfaces first. Clusters already at BandHigh sort last: there is
// nothing left to learn there. Best-effort and a no-op without a wired
// ConfidenceReader, matching applyPolicyRules' optional-dependency pattern.
func (s *Service) annotateTeachingValue(ctx context.Context, items []QueueItem, dominantResourceType map[string]string) []QueueItem {
	if s.confidence == nil || len(items) == 0 {
		return items
	}

	keyOf := func(it QueueItem) confKey {
		return confKey{it.ActionClass, dominantResourceType[it.ClusterKey]}
	}

	// Co-keyed cluster counts, for Unlocks: how many OTHER pending clusters
	// share this confidence key (resolving this one grows their evidence too).
	counts := make(map[confKey]int, len(items))
	for _, it := range items {
		counts[keyOf(it)]++
	}

	// Memoize the confidence lookup per unique key: many queue items share the
	// same (action class, dominant resource type) key (that's exactly what
	// Unlocks measures), and each lookup is a Postgres round trip. A failed
	// lookup must not be cached as a zero-value success, so the cache stores
	// whether the lookup succeeded alongside the result.
	type cachedConfidence struct {
		conf memory.Confidence
		ok   bool
	}
	cache := make(map[confKey]cachedConfidence, len(counts))

	isHigh := make(map[confKey]bool, len(items))
	for i := range items {
		k := keyOf(items[i])
		cached, hit := cache[k]
		if !hit {
			conf, err := s.confidence.Confidence(ctx, k.actionClass, k.resourceType)
			cached = cachedConfidence{conf: conf, ok: err == nil}
			cache[k] = cached
		}
		// Unlocks is derived purely from key grouping above — it needs no
		// confidence lookup, so it is a real measurement even when the lookup
		// failed. Set it before the guard rather than discarding it.
		items[i].Unlocks = counts[k] - 1
		if !cached.ok {
			// Best-effort: leave the CONFIDENCE fields at zero and leave
			// ConfidenceKnown false, so neither the sort below nor the UI reads
			// this item's zeros as measurements.
			continue
		}
		items[i].ConfidenceKnown = true
		items[i].ConfidenceEffectiveN = cached.conf.EffectiveN
		if cached.conf.EffectiveN < memory.MinEffectiveN {
			items[i].ConfidenceGap = memory.MinEffectiveN - cached.conf.EffectiveN
		}
		isHigh[k] = cached.conf.Band == memory.BandHigh
	}

	sort.SliceStable(items, func(i, j int) bool {
		// Unknown confidence sorts last, and must be the first comparison key:
		// an unmeasured item carries ConfidenceGap 0, the smallest possible
		// gap, so comparing gaps first would rank every measurement failure
		// ahead of the genuinely-closest-to-threshold cluster.
		if items[i].ConfidenceKnown != items[j].ConfidenceKnown {
			return items[i].ConfidenceKnown
		}
		hi, hj := isHigh[keyOf(items[i])], isHigh[keyOf(items[j])]
		if hi != hj {
			return hj // non-high (hi==false) sorts before high (hj==true)
		}
		if items[i].ConfidenceGap != items[j].ConfidenceGap {
			return items[i].ConfidenceGap < items[j].ConfidenceGap
		}
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].WorstScore > items[j].WorstScore
	})
	return items
}

// clusterQueue groups pending decisions by check + action class into one card
// each, carrying the worst score and the union of CoVe concerns. It also
// returns, per cluster key, the dominant resource type across the cluster's
// findings — the (ActionClass, dominant resource type) pair is the confidence
// key used to look up teaching value (annotateTeachingValue).
func clusterQueue(pending []reasoncache.Entry, byID map[string]finding.Finding) ([]QueueItem, map[string]string) {
	type agg struct {
		item          *QueueItem
		resources     map[string]bool
		concerns      map[string]bool
		resourceTypes map[string]int
	}
	groups := map[string]*agg{}
	var order []string

	for _, e := range pending {
		f := byID[e.FindingID]
		key := f.CheckID + "|" + e.ActionClass
		g := groups[key]
		if g == nil {
			title := f.Title
			if title == "" {
				title = e.Summary
			}
			g = &agg{
				item: &QueueItem{
					ClusterKey: key, Title: title, CheckID: f.CheckID, ActionClass: e.ActionClass,
					Summary: e.Summary, Outcome: e.Outcome, ConfidenceBand: e.ConfidenceBand,
					ConfidenceScore: e.ConfidenceScore,
					SafetyBand:      e.SafetyBand,
					DecidedAt:       e.DecidedAt,
					// Starts true; AND'd against every entry below (including this
					// one) — a cluster's blast radius is known only if EVERY
					// finding's walk was.
					BlastRadiusKnown: true,
				},
				resources:     map[string]bool{},
				concerns:      map[string]bool{},
				resourceTypes: map[string]int{},
			}
			groups[key] = g
			order = append(order, key)
		}
		it := g.item
		if f.ResourceType != "" {
			g.resourceTypes[f.ResourceType]++
		}
		it.Count++
		it.FindingIDs = append(it.FindingIDs, e.FindingID)
		if f.Score > it.WorstScore {
			it.WorstScore = f.Score
			it.WorstBand = f.ScoreBand
		}
		if respond.UrgentEvidence(f) != "" {
			it.Urgent = true
		}
		if e.BlastRadius > it.BlastRadius {
			it.BlastRadius = e.BlastRadius
		}
		// A cluster's BlastRadius is a max over its findings, so a single
		// unmeasured walk anywhere in the cluster makes the max itself
		// untrustworthy — AND, not OR: one bad apple poisons the cluster's cap
		// check, on purpose.
		it.BlastRadiusKnown = it.BlastRadiusKnown && e.BlastRadiusKnown
		it.SafetyBand = respond.WorstSafetyBand(it.SafetyBand, e.SafetyBand)
		if f.Unused {
			it.UnusedCount++
		}
		// Track minimum confidence score across the cluster: the weakest link
		// determines whether the whole cluster parks or escalates.
		if e.ConfidenceScore < it.ConfidenceScore {
			it.ConfidenceScore = e.ConfidenceScore
		}
		if e.DecidedAt.After(it.DecidedAt) {
			it.DecidedAt = e.DecidedAt
		}
		if f.ResourceID != "" {
			// Check membership BEFORE marking it seen: dedupe SampleTargets on
			// distinct resources, not distinct findings — N findings sharing
			// one resource must not burn all 5 sample slots on the same id
			_, seenResource := g.resources[f.ResourceID]
			g.resources[f.ResourceID] = true
			if !seenResource && len(it.SampleTargets) < 5 {
				it.SampleTargets = append(it.SampleTargets, f.ResourceID)
			}
		}
		for _, c := range e.CoVeConcerns {
			g.concerns[c] = true
		}
	}

	out := make([]QueueItem, 0, len(order))
	dominantResourceType := make(map[string]string, len(order))
	for _, key := range order {
		g := groups[key]
		g.item.Resources = len(g.resources)
		for c := range g.concerns {
			g.item.CoVeConcerns = append(g.item.CoVeConcerns, c)
		}
		sort.Strings(g.item.CoVeConcerns)
		out = append(out, *g.item)

		// Dominant resource type: the type with the most findings in this
		// cluster. Ties break alphabetically for determinism.
		var best string
		var bestCount int
		for rt, count := range g.resourceTypes {
			if count > bestCount || (count == bestCount && rt < best) {
				best, bestCount = rt, count
			}
		}
		dominantResourceType[key] = best
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].WorstScore > out[j].WorstScore })
	return out, dominantResourceType
}

// Resolve records a governor's verdict on a cluster of decisions. It always
// writes the verdict + an audit entry; a denial also feeds decaying memory as
// negative evidence. An approval does not: only a fix that actually ran is a
// success (RecordExecution).
func (s *Service) Resolve(ctx context.Context, in ResolveInput) error {
	if !ValidVerdict(in.Verdict) {
		return ErrBadVerdict
	}
	if len(in.FindingIDs) == 0 {
		return ErrNoTargets
	}

	// The targets, their action class and their fingerprints come from the
	// pending decisions, never from the request: a client-chosen action class
	// or a finding with no pending decision would let one admin write memory
	// outcomes (and pattern verdicts) for judgments nobody was asked to make.
	targets, err := s.pendingTargets(ctx, in.FindingIDs)
	if err != nil {
		return fmt.Errorf("Resolve: %w", err)
	}
	if in.ActionClass != "" && in.ActionClass != targets.actionClass {
		return fmt.Errorf("Resolve: %w: request says %q, the pending decisions say %q",
			ErrTargetMismatch, in.ActionClass, targets.actionClass)
	}
	ids, actionClass, fps := targets.ids, targets.actionClass, targets.fingerprints

	// resourceType keys the memory outcome. patternCheckID keys the pattern
	// verdict and the cluster key, and is derived from the resolved findings,
	// never from client input: a caller-supplied check_id would be an
	// authorization primitive (a typo or forged body could record a
	// standing ruling for a pattern the governor never saw). Findings
	// disagreeing on check_id make the pattern key ambiguous, and an ambiguous
	// key is not recorded at all.
	resourceType := map[string]string{}
	patternCheckID, patternAmbiguous := "", false
	findings, err := s.findings.ByIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("Resolve: %w", err)
	}
	for _, f := range findings {
		resourceType[f.ID] = f.ResourceType
		switch {
		case patternCheckID == "":
			patternCheckID = f.CheckID
		case patternCheckID != f.CheckID:
			patternAmbiguous = true
		}
	}
	clusterKey := patternCheckID + "|" + actionClass
	if patternAmbiguous {
		clusterKey = "mixed|" + actionClass
	}

	now := s.now()
	details, _ := json.Marshal(map[string]string{"verdict": string(in.Verdict), "note": in.Note})
	for _, id := range ids {
		// The fingerprint snapshot lets a later material change re-surface the
		// finding.
		if err := s.verdicts.Upsert(ctx, id, clusterKey, in.Verdict, in.Actor, in.Note, fps[id]); err != nil {
			return fmt.Errorf("Resolve: %w", err)
		}
		if err := s.audit.Record(ctx, respond.AuditEvent{
			ID: id + ":" + string(in.Verdict), TS: now, Actor: in.Actor,
			Action: "governor_verdict", TargetType: "finding", TargetID: id, Details: string(details),
		}); err != nil {
			return fmt.Errorf("Resolve: audit: %w", err)
		}
	}

	// A denial is a negative outcome for this (action class, asset type) key:
	// it means proposing this class of action on this kind of asset would
	// have been wrong. An approval writes NOTHING: it is a yes to try the fix,
	// not evidence the fix worked — the ledger learns success only from a fix
	// the executor actually carried out (RecordExecution). VerdictRiskAccepted
	// writes nothing either: it is a judgment call about the finding (leave the
	// exposure as-is, accept the risk), not about whether the agent's proposed
	// action would have been correct.
	//
	// One human judgment is one piece of evidence per asset type, not one per
	// finding: recording per finding would let a single "deny all" on a large
	// cluster write dozens of negative samples for one decision, and decay
	// never repairs that ratio because it applies uniformly to both sides. The
	// governor made one call; the ledger records one sample per distinct asset
	// type it covered. The sample is keyed by the decisions it judged (finding
	// + fingerprint), so a concurrent duplicate resolve stores it once.
	if in.Verdict == VerdictDenied {
		byAssetType := map[string][]string{}
		var assetTypes []string
		for _, id := range ids {
			assetType := resourceType[id]
			if assetType == "" {
				// The finding did not load, so its asset type is unknown.
				// Recording against ("class", "") would file the evidence under
				// a key that describes nothing — a zero value standing in for a
				// measurement. Skip it and say so.
				log.FromContext(ctx).Warn().Str("finding_id", id).Str("verdict", string(in.Verdict)).
					Msg("govern: verdict outcome skipped — finding's asset type unknown")
				continue
			}
			if _, seen := byAssetType[assetType]; !seen {
				assetTypes = append(assetTypes, assetType)
			}
			byAssetType[assetType] = append(byAssetType[assetType], id)
		}
		for _, assetType := range assetTypes {
			if err := s.outcomes.Record(ctx, memory.Outcome{
				ActionClass: actionClass, AssetType: assetType,
				Success: false, DecidedBy: "governor", OccurredAt: now,
				DedupeKey: "governor:" + actionClass + ":" + assetType + ":" + decisionSetHash(byAssetType[assetType], fps),
			}); err != nil {
				return fmt.Errorf("Resolve: outcome: %w", err)
			}
		}
	}

	// Persist the pattern-level verdict once per cluster per distinct resource
	// type (not per finding): the (check_id, action_class, resource_type)
	// record respond.Decide consults before a specific future finding even
	// exists. Latest verdict wins per resource type.
	//
	// One row per resource type in the cluster, never one row for the whole
	// cluster, keeps a denial scoped: a cluster spanning package and
	// container_image findings writes two rows, so denying on one resource
	// type never silently suppresses the other. resourceType == "" is
	// skipped for the same reason the outcome ledger above skips it: a
	// pattern filed under an empty resource type would match nothing real.
	//
	// risk_accepted is deliberately not recorded: it would need expiry and
	// scope semantics that do not exist yet, and a standing "risk accepted"
	// pattern must never read as consent to act. Best-effort: the verdicts,
	// audit rows and memory outcomes above are already written and
	// action_outcomes is append-only, so failing the whole call here would
	// make a retry double-count every outcome in the cluster.
	if s.patterns != nil && actionClass != "" &&
		(in.Verdict == VerdictApproved || in.Verdict == VerdictDenied) {
		switch {
		case patternAmbiguous:
			log.FromContext(ctx).Warn().Str("cluster_key", clusterKey).
				Msg("govern: pattern verdict skipped — cluster spans multiple checks")
		case patternCheckID == "":
			log.FromContext(ctx).Warn().Str("cluster_key", clusterKey).
				Msg("govern: pattern verdict skipped — no check_id resolved from the findings")
		default:
			resourceTypes := map[string]bool{}
			for _, rt := range resourceType {
				if rt != "" {
					resourceTypes[rt] = true
				}
			}
			sortedTypes := make([]string, 0, len(resourceTypes))
			for rt := range resourceTypes {
				sortedTypes = append(sortedTypes, rt)
			}
			sort.Strings(sortedTypes) // deterministic write order
			for _, rt := range sortedTypes {
				if err := s.patterns.UpsertPattern(ctx, patternCheckID, actionClass, rt, in.Verdict, in.Actor); err != nil {
					log.FromContext(ctx).Error().Err(err).Str("check_id", patternCheckID).
						Str("action_class", actionClass).Str("resource_type", rt).
						Msg("govern: pattern verdict upsert failed")
				}
			}
		}
	}

	// Fire the approval notifier once per cluster (not per finding) — a Jira
	// ticket covers the whole cluster, not one row per finding. Best-effort:
	// a notifier failure must not roll back an audited verdict.
	if in.Verdict == VerdictApproved && s.notifier != nil {
		p := approvalPayload(in, clusterKey, actionClass, targets.entries, findings, now)
		if err := s.notifier.NotifyApproval(ctx, p); err != nil {
			// Best-effort: a notifier failure must not roll back an audited
			// verdict. But surface it here too — a silently-dropped approval
			// handoff means an approved action may never reach its executor.
			log.FromContext(ctx).Error().Err(err).Str("cluster_key", clusterKey).
				Msg("govern: approval handoff (NotifyApproval) failed; verdict recorded but downstream not notified")
		}
	}
	return nil
}

// PatternVerdict returns the latest standing verdict recorded for a (check_id,
// action_class, resource_type) pattern, independent of any specific finding,
// and when it was decided. found is false, with no error, when no verdict has
// ever been recorded for this pattern or no PatternVerdicts store is wired —
// a sentinel-error-free "not found" contract. Consulted by respond.Decide
// via the cmd/graph closure over this method.
func (s *Service) PatternVerdict(ctx context.Context, checkID, actionClass, resourceType string) (Verdict, time.Time, bool, error) {
	if s.patterns == nil {
		return "", time.Time{}, false, nil
	}
	v, decidedAt, found, err := s.patterns.PatternVerdict(ctx, checkID, actionClass, resourceType)
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("PatternVerdict: %w", err)
	}
	return v, decidedAt, found, nil
}
