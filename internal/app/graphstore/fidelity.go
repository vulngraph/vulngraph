package graphstore

// fidelity.go — the publish gate. A candidate rebuild that cannot vouch for its
// own load set is ABANDONED; the previous graph keeps serving.
//
// This exists because a rebuild can silently lose a large slice of its topology
// (a ClickHouse memory error mid-fetch, a partial correlate sweep, a producer
// that stopped emitting) while every existing health signal stays green — the
// edge-count and reach-completeness gauges don't distinguish "fetched
// everything" from "fetched the tier that happened to succeed". The post-BFS
// risk score and reach this graph serves feed enrich -> must_fix_class ->
// respond, whose proposals a person approves on that evidence, so a silently
// incomplete graph means confident proposals on bad data, not just a stale
// dashboard.
//
// SyncFromSources already builds the replacement graph off to the side and
// swaps it in atomically; this file is the missing decision to throw the
// candidate away instead of always swapping.
//
// TWO LAYERS, ONLY THE FIRST IS UNCONDITIONAL
//
// Layer 1 — a self-reported partial fetch never publishes. asset.EdgeSyncResult
// already knows its bulk pass failed or a type hit its row cap, and
// asset.AssetSyncResult knows the asset load hit its row cap, so this is a
// report of a known fact, not a heuristic, and it needs no baseline.
//
// Layer 2 — a shape check against the last published build, for degradations
// that do NOT self-report (a partial correlate sweep, a producer gone dark, a
// silent truncation). Thresholds in fidelityThresholds below are sized against
// the expected sweep-to-sweep variation of healthy builds.
//
// WHICH WAY IT FAILS
//
// It refuses. A refused rebuild costs freshness (the previous graph is at most
// one correlate interval old, and complete); an accepted degraded rebuild costs
// correctness (incomplete by an unknown amount, and every consumer treats it as
// whole). Staleness is bounded and already alarmed; incompleteness was not
// observable at all.
//
// The false-refusal case that matters is a LEGITIMATE large change (an account
// purge, an intentional prune, a decommissioned connector) — thresholds cannot
// tell that apart from a degradation, because both are a step. So the gate does
// not try to classify it: it refuses once and accepts the same shape on the next
// sweep (acceptOnRepeat below). A transient failure never publishes, because it
// does not reproduce; a real change publishes one sweep late. That turns an
// impossible classification into a bounded freshness cost.
//
// THREE EDGE CASES, EACH WITH ITS OWN ESCAPE
//
// 1. A SchemaVersion bump rejects the PVC snapshot, so the first build after a
//    deploy has no Layer-2 baseline — exactly when a producer regression is most
//    likely. ReadSnapshotShapeAnyVersion reads the snapshot's shape ignoring the
//    version check (LoadFromSnapshot still refuses to warm-start the graph from
//    it) so Layer 2 still has a baseline to compare against.
//
// 2. Layer 1 has no repeat escape by design — but that stops being correct on a
//    genuine cold start under sustained ClickHouse pressure: every fetch is
//    partial, there is no previous graph, and refusing forever means no graph at
//    all, which is worse than a stale one for every read path and no worse for
//    respond (must_fix_class never fires with nothing built either way). A
//    Layer-1 failure may therefore publish on repeat ONLY when noGraphServed is
//    true; the instant something publishes, "refuse forever" resumes protecting it.
//
// 3. acceptOnRepeat requires the SAME shape twice, so a monotonic legitimate
//    decline (a multi-day teardown shrinking a bit more each sweep) never
//    satisfies it and would freeze the graph for the whole teardown.
//    monotonicDeclineStreak consecutive refusals, each a further decline on the
//    last, confirm a ramp rather than a step and publish the latest one.
//
// (Case 4 — a crash between a refusal and its repeat wiping this state — is
// handled in fidelity_persist.go: the refused shape, decline streak and wall
// clock are persisted next to the topology snapshot.)

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// fidelityThresholds are the Layer-2 limits, sized against the sweep-to-sweep
// variation that graph_ladybug_edge_type_rows and graph_ladybug_node_count show across
// consecutive healthy builds.
const (
	// minVolumeRatio is the floor on candidate/baseline for BOTH total fetched
	// edges and post-filter assets, set below the worst expected legitimate
	// sweep-to-sweep ratio (edges drift under 1%, nodes under ~5%) with margin —
	// acceptOnRepeat is what makes the thinner node margin safe, since the cost
	// of being wrong is one sweep, not an outage.
	minVolumeRatio = 0.85

	// minTypeBaselineRows is the baseline row count above which an edge type going
	// to EXACTLY ZERO is treated as a defect rather than churn. A relative
	// per-type floor is not useful here: real per-type churn swings enough that
	// any floor tight enough to catch a degradation would refuse healthy builds
	// constantly. Total disappearance is the discriminating signal instead — no
	// type at or above this floor is expected to legitimately reach zero.
	minTypeBaselineRows = 50

	// repeatVolumeTolerance is how much a candidate may differ from the shape that
	// was just refused and still count as "the same thing again", i.e. persistent
	// reality rather than a transient failure. Generous on purpose: legitimate
	// sweep-to-sweep drift is under 1% on edges, so 5% cannot mistake a second
	// distinct degradation for a repeat while still absorbing normal churn.
	repeatVolumeTolerance = 0.05

	// monotonicDeclineStreak is how many CONSECUTIVE, independently-timed refusals,
	// each declining further than the last, must be seen before a ramp is trusted
	// as reality rather than noise reversing. A step's acceptOnRepeat trusts two
	// observations because the shape repeats exactly; a ramp's shape does NOT
	// repeat by definition, so there's no exact-match test to lean on, and two
	// points cannot show a trend — "dropped, then dropped again" is
	// indistinguishable from a dip about to recover until a third point confirms
	// the direction held. Three is the minimum, not a margin.
	monotonicDeclineStreak = 3
)

// minRepeatAge is how old a refusal must be before the same shape may be
// accepted on repeat. Shape equality alone is not enough because a refusal
// triggers a River retry within seconds — re-reading ClickHouse and reproducing
// the identical degraded shape would satisfy "arrived twice" before the
// transient that caused it had any time to clear, turning the safety valve into
// a seconds-long bypass. "Twice" therefore has to mean two INDEPENDENT
// observations in time: one correlate interval (jobs.defaultCorrelateInterval,
// 30m) minus a jitter margin. A real estate change is still there half an hour
// later; a transient failure is not.
const minRepeatAge = 25 * time.Minute

// fidelityShape is the coarse shape of one build's load set: what a later build is
// compared against. Deliberately counts, not content — the load digest
// already answers "did anything change?"; this answers "did we lose a chunk?".
type fidelityShape struct {
	// Assets is the POST-filterLadybugAssets count, so it matches what actually loads
	// and what graph_ladybug_node_count reports.
	Assets int
	// TotalEdges is every edge the fetch returned, before load-time drops.
	TotalEdges int
	// ByType is the per-edge_type fetched count. Only types still declared synced in
	// the graphschema registry are compared, so taking a type to TierUnsynced on
	// purpose can never be read as losing it.
	ByType map[string]int
}

// shapeOf measures a candidate (or a just-published) load set.
func shapeOf(assets []asset.Asset, edges []asset.Edge) fidelityShape {
	byType := make(map[string]int, 32)
	for i := range edges {
		byType[edges[i].EdgeType]++
	}
	return fidelityShape{Assets: len(assets), TotalEdges: len(edges), ByType: byType}
}

// empty reports a shape carrying no baseline (first boot, or a snapshot that
// predates the gate).
func (s fidelityShape) empty() bool { return s.Assets == 0 && s.TotalEdges == 0 }

// fidelityVerdict is the gate's decision plus the operator-readable reason. Reasons
// are also the alert annotation, so they name concrete numbers.
type fidelityVerdict struct {
	Refuse bool
	Reason string
	// RepeatCategory is set only when Refuse is false because of an accept-on-repeat
	// rule ("step", "cold_start" or "monotonic") — the obs layer reads it to break
	// graph_ladybug_publish_degraded_accepted_total down by WHICH escape fired, since
	// the three have very different operational meanings (a step is a one-off
	// estate change; cold_start means the platform bootstrapped on a degraded fetch
	// because nothing else was being served; monotonic means a multi-day teardown is
	// in progress).
	RepeatCategory string
}

// pendingRefusal is the immediately preceding refusal: its shape, how long ago it
// happened, and its position in a decline streak. All three are needed — see
// minRepeatAge for why the shape/age alone are not enough, and monotonicDeclineStreak
// for why a streak count is needed on top of shape equality.
type pendingRefusal struct {
	shape         fidelityShape
	age           time.Duration
	declineStreak int
}

// checkFidelity decides whether a candidate build may be published.
//
// fetchComplete is true only when asset.EdgeSyncResult.FetchComplete() holds
// and asset.AssetSyncResult.Truncated is false — Layer 1. baseline is the
// last PUBLISHED build's shape; an empty baseline skips Layer 2 entirely (see the
// first-boot paragraph in the file header). refused describes the immediately
// preceding refusal, or is nil if the last decision was to publish. noGraphServed is
// true when nothing is currently being protected — no live graph has ever
// successfully published in this process (or its warm-started predecessor) — which
// is the one condition under which a Layer-1 failure may still escape via repeat
// (case 2 in the file header).
func checkFidelity(cand, baseline fidelityShape, fetchComplete bool, fetchDetail string, refused *pendingRefusal, noGraphServed bool) fidelityVerdict {
	var reasons []string

	// Layer 1: the fetch itself said it was partial. No baseline needed, and no
	// judgement involved.
	if !fetchComplete {
		reasons = append(reasons, "fetch reported partial coverage ("+fetchDetail+")")
	}

	// Layer 2: shape against the last published build.
	if !baseline.empty() {
		if r := ratio(cand.TotalEdges, baseline.TotalEdges); r < minVolumeRatio {
			reasons = append(reasons, fmt.Sprintf("fetched edges %d vs baseline %d (%.3f of baseline, floor %.2f)",
				cand.TotalEdges, baseline.TotalEdges, r, minVolumeRatio))
		}
		if r := ratio(cand.Assets, baseline.Assets); r < minVolumeRatio {
			reasons = append(reasons, fmt.Sprintf("assets %d vs baseline %d (%.3f of baseline, floor %.2f)",
				cand.Assets, baseline.Assets, r, minVolumeRatio))
		}
		if lost := lostTypes(cand, baseline); len(lost) > 0 {
			reasons = append(reasons, "edge types that fetched zero rows against a nonzero baseline: "+strings.Join(lost, ", "))
		}
	}

	if len(reasons) == 0 {
		return fidelityVerdict{}
	}
	reason := strings.Join(reasons, "; ")

	repeatEligible := refused != nil && refused.age >= minRepeatAge
	switch {
	case repeatEligible && fetchComplete && sameShapeClass(cand, refused.shape, baseline):
		// acceptOnRepeat, the step case. A degradation that reproduces a full sweep
		// later is no longer a transient, and refusing it forever would freeze the
		// graph on an unbounded stale copy — worse than publishing it with the alarm
		// already ringing.
		return fidelityVerdict{Refuse: false, RepeatCategory: "step", Reason: "PUBLISHED ON REPEAT: " + reason}

	case repeatEligible && !fetchComplete && noGraphServed && sameShapeClass(cand, refused.shape, baseline):
		// Case 2: Layer 1 normally never accepts a repeat, but with NOTHING to
		// protect (no previous graph), refusing forever means no graph at all —
		// strictly worse than a degraded one, and no worse for respond since
		// must_fix_class never fires with nothing built either way. The instant
		// this publishes, noGraphServed goes false and refuse-forever resumes.
		return fidelityVerdict{Refuse: false, RepeatCategory: "cold_start",
			Reason: "PUBLISHED ON REPEAT (cold start — nothing was being served, so a partial graph beats none): " + reason}

	case repeatEligible && fetchComplete && refused.declineStreak >= monotonicDeclineStreak-1 && declines(cand, refused.shape):
		// Case 3: a monotonic legitimate decline shrinks more than
		// repeatVolumeTolerance every sweep, so sameShapeClass never matches and
		// the step rule never fires. monotonicDeclineStreak consecutive refusals
		// that each decline further than the last are trusted as a trend instead.
		return fidelityVerdict{Refuse: false, RepeatCategory: "monotonic", Reason: fmt.Sprintf(
			"PUBLISHED ON REPEAT (monotonic decline, %d consecutive shrinking sweeps): %s",
			refused.declineStreak+1, reason)}
	}
	return fidelityVerdict{Refuse: true, Reason: reason}
}

// ratio is candidate/baseline, with a zero baseline reading as 1 (nothing to
// compare — fail open, the empty-baseline case is handled by the caller).
func ratio(cand, baseline int) float64 {
	if baseline <= 0 {
		return 1
	}
	return float64(cand) / float64(baseline)
}

// lostTypes names the still-synced edge types whose baseline was material and whose
// candidate count is exactly zero, sorted so the reason string is stable.
func lostTypes(cand, baseline fidelityShape) []string {
	var out []string
	for et, n := range baseline.ByType {
		if n < minTypeBaselineRows || cand.ByType[et] != 0 {
			continue
		}
		if graphschema.TierOf(et) == graphschema.TierUnsynced {
			continue // deliberately taken out of the fetch — not a loss
		}
		out = append(out, fmt.Sprintf("%s (%d -> 0)", et, n))
	}
	sort.Strings(out)
	return out
}

// sameShapeClass reports whether cand is the same degradation that was just
// refused, rather than a new or different one: the same set of vanished edge types
// and a total within repeatVolumeTolerance.
func sameShapeClass(cand, refused, baseline fidelityShape) bool {
	if !withinTolerance(cand.TotalEdges, refused.TotalEdges) || !withinTolerance(cand.Assets, refused.Assets) {
		return false
	}
	return strings.Join(lostTypes(cand, baseline), ",") == strings.Join(lostTypes(refused, baseline), ",")
}

func withinTolerance(a, b int) bool {
	if b == 0 {
		return a == 0
	}
	d := float64(a-b) / float64(b)
	if d < 0 {
		d = -d
	}
	return d <= repeatVolumeTolerance
}

// declines reports whether newer is a further, non-trivial shrinkage of older: both
// edges and assets down, and the edge drop bigger than the noise floor
// sameShapeClass already tolerates. A shape that merely REPEATS older (within
// repeatVolumeTolerance) is never counted as another step of a decline — that case
// belongs to sameShapeClass, not here, or a flat degradation would inflate its own
// streak forever.
func declines(newer, older fidelityShape) bool {
	if newer.TotalEdges >= older.TotalEdges || newer.Assets > older.Assets {
		return false
	}
	return !withinTolerance(newer.TotalEdges, older.TotalEdges)
}

// fidelityState is the gate's memory: the shape of the last published build (the
// baseline), the shape and decline streak of the last refusal, plus the counters the
// obs gauges read. Guarded by its own mutex — SyncFromSources is the only writer, but
// the metrics scrape reads it concurrently.
type fidelityState struct {
	mu       sync.Mutex
	baseline fidelityShape
	refused  *fidelityShape
	// declineStreak counts consecutive refusals, ending at refused, that each
	// declined further than the one before (case 3 — see monotonicDeclineStreak).
	// Reset to 1 whenever a refusal does not continue the previous one's decline.
	declineStreak int
	// refusals counts abandoned rebuilds for the process lifetime. It is the signal
	// this whole change ships: it can only move if the gate actually fires.
	refusals int64
	// repeatPublishes counts builds published under any accept-on-repeat rule.
	// repeatPublishesByCategory breaks that down by which rule fired ("step",
	// "cold_start", "monotonic") — each is a materially different operational claim,
	// and folding them into one counter is how "was that you?" stops being answerable.
	repeatPublishes           int64
	repeatPublishesByCategory map[string]int64
	// lastRefusalUnix is the wall time of the most recent refusal (0 = never), so an
	// alert can distinguish "refusing right now" from "refused once last week".
	lastRefusalUnix int64
	lastReason      string
}

// seedBaseline arms the baseline WITHOUT touching a pending refusal. Used by
// LoadFromSnapshot: the snapshot's shape is the last known-good baseline, but
// bootstrapping that is not the same claim as "a fresh decision just resolved"
// — a refusal from before a crash is a separate question, restored
// independently by fidelity_persist.go's rearm, and seedBaseline must not
// clobber it (compare publishedShape, which deliberately does).
func (f *fidelityState) seedBaseline(s fidelityShape) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.baseline = s
}

// publishedShape records a shape that reached the live graph FROM A FRESH DECISION
// (a full rebuild, a no-op/signal-refresh confirming the live graph still matches, or
// an accept-on-repeat publish), clearing any pending refusal: the next degradation is
// judged fresh, never against a shape two builds old.
func (f *fidelityState) publishedShape(s fidelityShape) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.baseline, f.refused, f.declineStreak = s, nil, 0
}

// refusalRecord is the durable form of a pending refusal (see fidelity_persist.go):
// small enough to write on every refusal, and independent of SchemaVersion — it
// describes counts and a timestamp, not the Ladybug DDL or the loading set. recordRefusal
// returns one so the caller can persist it without a second lock round-trip.
type refusalRecord struct {
	Shape         fidelityShape
	DeclineStreak int
	RefusedUnix   int64
	Reason        string
}

// recordRefusal stores the refused shape so the next sweep can recognise a repeat
// or a continuing decline, and returns the record for the caller to persist to
// disk (case 4 — a crash must not wipe this).
//
// River retries ladybug_rebuild within seconds of a refusal, so this is called far
// more often per episode than once per real correlate sweep — a retry's
// near-identical re-refusal must never count as a fresh, independent
// observation. Two invariants follow:
//
//  1. declineStreak only advances on a genuine further decline. A retry
//     reproducing the last refused shape is the same observation recurring, not
//     "not a decline" — treating it as the latter would reset the streak to 1 on
//     every retry, and case 3 (monotonicDeclineStreak) could never accumulate.
//  2. lastRefusalUnix anchors the START of the current refusal episode, not the
//     most recent attempt. Overwriting it on every call would restart the clock
//     on every retry, so minRepeatAge — whose whole purpose is to stop a repeat
//     being trusted within seconds of the first sighting — would never mature.
//     An episode boundary is either the very first refusal (f.refused == nil) OR
//     a genuinely new, unrelated shape (the default case below): both must reset
//     the anchor, or a new failure can inherit an old, already-stale episode's age.
func (f *fidelityState) recordRefusal(s fidelityShape, reason string, nowUnix int64) refusalRecord {
	f.mu.Lock()
	defer f.mu.Unlock()

	newEpisode := f.refused == nil
	switch {
	case newEpisode:
		f.declineStreak = 1
	case declines(s, *f.refused):
		f.declineStreak++
	case withinTolerance(s.TotalEdges, f.refused.TotalEdges) && withinTolerance(s.Assets, f.refused.Assets):
		// A retry (or a subsequent sweep) reproducing the last refusal: not a
		// new independent observation, leave the streak exactly as it was.
	default:
		// A genuinely different, unrelated shape: this IS a new episode too,
		// even though f.refused was already non-nil.
		f.declineStreak = 1
		newEpisode = true
	}

	cp := s
	f.refused = &cp
	f.refusals++
	if newEpisode {
		f.lastRefusalUnix = nowUnix
	}
	f.lastReason = reason
	return refusalRecord{Shape: s, DeclineStreak: f.declineStreak, RefusedUnix: f.lastRefusalUnix, Reason: reason}
}

// rearmRefusal restores a pending refusal persisted before a crash (fidelity_persist.go).
// Called once, at startup, after seedBaseline — never after publishedShape, which
// deliberately clears this same state for a fresh decision.
func (f *fidelityState) rearmRefusal(rec refusalRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := rec.Shape
	f.refused = &cp
	f.declineStreak = rec.DeclineStreak
	f.lastRefusalUnix = rec.RefusedUnix
	f.lastReason = rec.Reason
}

func (f *fidelityState) recordRepeatPublish(category string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.repeatPublishes++
	if f.repeatPublishesByCategory == nil {
		f.repeatPublishesByCategory = make(map[string]int64, 3)
	}
	f.repeatPublishesByCategory[category]++
}

// snapshotState returns the baseline and pending refusal for a decision, with the
// refusal's age resolved against now so checkFidelity stays a pure function.
func (f *fidelityState) snapshotState(now time.Time) (baseline fidelityShape, refused *pendingRefusal) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refused != nil {
		refused = &pendingRefusal{
			shape:         *f.refused,
			age:           now.Sub(time.Unix(f.lastRefusalUnix, 0)),
			declineStreak: f.declineStreak,
		}
	}
	return f.baseline, refused
}

// FidelityStats is the gate's observability surface: refusals, repeat publishes (by
// category) and the last refusal's wall time and reason.
type FidelityStats struct {
	Refusals        int64
	RepeatPublishes int64
	// RepeatPublishesStep/ColdStart/Monotonic break RepeatPublishes down by which
	// accept-on-repeat rule fired. Each is a signal that can only move if its
	// specific fix works: ColdStart cannot move unless case 2 (Layer 1 escaping on a
	// graph-less cold start) actually ran, Monotonic cannot move unless case 3 (a
	// decline streak reaching monotonicDeclineStreak) actually ran.
	RepeatPublishesStep      int64
	RepeatPublishesColdStart int64
	RepeatPublishesMonotonic int64
	LastRefusalUnix          int64
	LastReason               string
}

// FidelityStats reports the publish gate's counters for /metrics.
func (s *Service) FidelityStats() FidelityStats {
	s.fidelity.mu.Lock()
	defer s.fidelity.mu.Unlock()
	return FidelityStats{
		Refusals:                 s.fidelity.refusals,
		RepeatPublishes:          s.fidelity.repeatPublishes,
		RepeatPublishesStep:      s.fidelity.repeatPublishesByCategory["step"],
		RepeatPublishesColdStart: s.fidelity.repeatPublishesByCategory["cold_start"],
		RepeatPublishesMonotonic: s.fidelity.repeatPublishesByCategory["monotonic"],
		LastRefusalUnix:          s.fidelity.lastRefusalUnix,
		LastReason:               s.fidelity.lastReason,
	}
}

// EdgeFetchComplete reports whether the last build's edge fetch covered every
// synced tier in full — the signal graph_ladybug_reach_complete must not be
// mistaken for.
func (s *Service) EdgeFetchComplete() bool { return s.edgeFetchComplete.Load() }

// AssetFetchComplete reports whether the last build's asset load came back
// whole, i.e. did not hit the sync row cap.
func (s *Service) AssetFetchComplete() bool { return s.assetFetchComplete.Load() }
