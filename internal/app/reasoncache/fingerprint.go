package reasoncache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// FingerprintInput is the set of facts about a finding and its connected graph
// context that, if any change, warrant re-reasoning. Hash these and nothing
// volatile (timestamps, edge order, raw counts, within-band score wiggle).
type FingerprintInput struct {
	FindingID string
	CheckID   string
	Type      string
	// ScoreBand (the bucket), NOT the raw score: the enrich score has a
	// time-decaying component (decaying-memory, blast count) that wiggles between
	// sweeps without changing the decision. Hashing the exact score would
	// re-reason every sweep; the band only changes on a real escalation.
	ScoreBand      string
	KnownExploited bool

	// Blast-radius membership: the set of asset IDs reachable from the finding's
	// resource. Order-independent (sorted). When the walk was truncated we hash a
	// stable sentinel instead of the partial set, which would otherwise flap as
	// the node budget cuts at different points each sweep.
	BlastAssetIDs  []string
	BlastTruncated bool
	SeedID         string

	// Extra carries the rest of the reasoning context (exposure flags, peer
	// signatures, provenance, impact — see respond's fingerprintExtra) so a
	// change in the context the LLM reasons over re-reasons.
	Extra []string
}

// LogicVersion identifies the CURRENT reasoning-cache fingerprint scheme — the
// set of facts in FingerprintInput that respond.Decide treats as
// answer-relevant, and (implicitly) the reasoning logic that consumes them: the
// prompt/plan schema and the gate inputs the LLM sees. It prefixes every
// fingerprint (see Fingerprint below), so bumping it changes EVERY entry's
// fingerprint at once: respond.planFor compares the freshly computed
// fingerprint against reasoncache.Entry.Fingerprint byte-for-byte (service.go /
// respond/service.go), so a changed prefix alone guarantees a miss for every
// row written under the old version, and a miss re-runs the LLM. That is the
// primary invalidation path here — lazy, on the next read — and it needs no
// extra machinery to be sufficient for it, unlike enrichcache.LogicVersion:
//
//   - enrichcache keeps a SEPARATE version-independent ContextFingerprint so a
//     miss caused only by a version bump (inputs unchanged) can be told apart
//     from a miss caused by a real input change — because enrichcache's job on
//     a version-only miss is to decide whether to also cascade a re-Decide into
//     respond (this package), and re-triggering the LLM for every unaffected
//     finding just because the *upstream* scorer's version ticked would be a
//     wasteful storm.
//   - reasoncache has no such downstream to protect: the action a fingerprint
//     miss takes IS re-running the LLM, in this same package's caller
//     (respond.Decide). There is nothing further downstream to shield from a
//     cascade, so the extra split hash is deliberately not carried over here.
//
// The lazy path alone still leaves a gap enrichcache also has: respond.Decide
// is only enqueued from the enrich sweep for already-enriched, above-threshold
// findings (jobs.enqueueDecide) — a finding whose asset never changes is never
// re-enqueued, so its cached plan can outlive several LogicVersion bumps with
// no natural read to invalidate it on. Service.InvalidateAll (service.go) is
// the bounded, explicit purge that closes that gap: wiping the cache after a
// bump forces every finding through a fresh Decide the next time it is
// enqueued, without needing to tell which stored rows are stale by inspecting
// their (opaque, fully-hashed) fingerprint — enrichcache solves the equivalent
// problem with a separately persisted LastFullPassVersion watermark plus a
// dedicated sweep worker (jobs.ReenrichWorker); reasoncache does not have one,
// because driving that sweep means iterating the finding corpus and
// re-enqueuing decide jobs, which belongs in internal/jobs (outside this
// package) — InvalidateAll is the primitive such a job would call.
//
// Bump this whenever respond's REASONING semantics change — the prompt, the
// plan schema, or the gate inputs the LLM is shown — not on unrelated
// refactors, and say in the commit why the standing corpus's cached plans are
// now stale.
const LogicVersion = "v1"

// Fingerprint returns a stable hex sha256 over the canonical serialization of
// in, prefixed with LogicVersion so a version bump invalidates every existing
// entry (see LogicVersion's doc comment for the full invalidation story).
func Fingerprint(in FingerprintInput) string {
	var b strings.Builder
	b.WriteString(LogicVersion)
	b.WriteByte('\n')
	b.WriteString(in.FindingID)
	b.WriteByte('\n')
	b.WriteString(in.CheckID)
	b.WriteByte('\n')
	b.WriteString(in.Type)
	b.WriteByte('\n')
	fmt.Fprintf(&b, "%s\n%t\n", in.ScoreBand, in.KnownExploited)

	if in.BlastTruncated {
		b.WriteString("blast:truncated:")
		b.WriteString(in.SeedID)
		b.WriteByte('\n')
	} else {
		ids := append([]string(nil), in.BlastAssetIDs...)
		sort.Strings(ids)
		for _, id := range ids {
			b.WriteString("a:")
			b.WriteString(id)
			b.WriteByte('\n')
		}
	}

	extra := append([]string(nil), in.Extra...)
	sort.Strings(extra)
	for _, e := range extra {
		b.WriteString("x:")
		b.WriteString(e)
		b.WriteByte('\n')
	}

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
