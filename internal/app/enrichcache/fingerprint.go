package enrichcache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// FingerprintInput is the set of a finding's INPUT facts that, if any change,
// warrant re-enriching. It deliberately excludes the enrichment OUTPUTS
// (Score/ScoreBand — hashing them would loop, since they are computed by
// enrichment) and all timestamps (volatile). KnownExploited is included so a KEV
// escalation flips the fingerprint and re-enriches even within the freshness
// backstop.
//
// IsExposed and PrivescBucket add the minimum graph context required to detect
// score-changing topology shifts without expensive per-finding BFS:
//   - IsExposed: resource has an exposed_to_internet edge — drives BlastRadius,
//     ToxicCombo, and SupplyChainExposure scoring directly.
//   - PrivescBucket: bucketed count of ciem_privesc findings on the resource —
//     drives AttackPaths and ToxicCombo. Bucketed (not exact count) so minor
//     fluctuations don't cause unnecessary re-enrichment.
type FingerprintInput struct {
	FindingID      string
	CheckID        string
	Type           string
	Severity       string
	ResourceID     string
	KnownExploited bool
	// Graph context — derived at fingerprint time via point queries.
	IsExposed     bool   // resource has exposed_to_internet edge
	PrivescBucket string // "0","1","2-3","4+" — ciem_privesc count for resource
	// ReachBucket buckets transitive internet reachability ("direct","1-3","none",
	// "" unknown) so a topology change that makes a resource reachable (or no longer)
	// re-enriches it — drives the must-fix reachability source.
	ReachBucket string
	// RootCause is a root-cause finding's membership counts (base-layer KEVs
	// and CVEs, running images, exposed workloads; a fleet's instances). They
	// live in metadata the other inputs never see, so without them a base that
	// gains a KEV member kept its fingerprint and was not re-scored to the page
	// band its now-silenced members rely on it to raise. Empty for every other
	// finding, and then not hashed at all, so their fingerprints are unchanged.
	RootCause string
	// SecretValidity is GitHub's validity verdict on a leaked secret
	// (finding.SecretValidityKey). It lives in metadata the other inputs never
	// see and moves the must-fix class (active/unknown vs inactive), so without
	// it a key GitHub found revoked kept its cached class. Empty — and then not
	// hashed — for every other finding.
	SecretValidity string
}

// Fingerprint returns a stable hex sha256 over the canonical serialization of
// in, prefixed with LogicVersion.
//
// Bump LogicVersion whenever the SCORING LOGIC changes, not just the inputs: the
// new prefix makes the change-driven gate re-enrich every finding once so the
// new scores take effect. Without a bump, unchanged findings keep their stale
// cached score, because nothing else would ever recompute the standing corpus.
// Say in the commit which scoring change the one-time global re-enrich is for.
func Fingerprint(in FingerprintInput) string {
	var b strings.Builder
	b.WriteString(LogicVersion)
	b.WriteByte('\n')
	writeFingerprintBody(&b, in)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// ContextFingerprint hashes the same INPUT facts as Fingerprint but WITHOUT the
// LogicVersion prefix — i.e. it is stable across a version bump and changes
// only when something about the finding or its graph context actually changed.
//
// Version-only re-score skip: bumping LogicVersion forces a cache miss for the entire corpus so
// the new scoring logic recomputes, but most findings' inputs did not change —
// only the logic did — so most of those recomputes land on the same
// ScoreBand they already had. Comparing ContextFingerprint against the value
// stored at the finding's last enrichment (enrichcache.Entry.ContextFP) is
// how EnrichWorker tells "the version bumped and nothing about this finding
// changed" apart from "this finding's actual inputs changed" — only the
// latter re-enters the decide pipeline when the recomputed band matches the
// stored one.
func ContextFingerprint(in FingerprintInput) string {
	var b strings.Builder
	writeFingerprintBody(&b, in)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// writeFingerprintBody writes the version-independent fingerprint material
// shared by Fingerprint and ContextFingerprint.
func writeFingerprintBody(b *strings.Builder, in FingerprintInput) {
	b.WriteString(in.FindingID)
	b.WriteByte('\n')
	b.WriteString(in.CheckID)
	b.WriteByte('\n')
	b.WriteString(in.Type)
	b.WriteByte('\n')
	b.WriteString(in.Severity)
	b.WriteByte('\n')
	b.WriteString(in.ResourceID)
	b.WriteByte('\n')
	if in.KnownExploited {
		b.WriteString("kev\n")
	}
	if in.IsExposed {
		b.WriteString("exposed\n")
	}
	b.WriteString(in.PrivescBucket)
	b.WriteByte('\n')
	b.WriteString(in.ReachBucket)
	b.WriteByte('\n')
	if in.RootCause != "" {
		b.WriteString("root_cause:")
		b.WriteString(in.RootCause)
		b.WriteByte('\n')
	}
	if in.SecretValidity != "" {
		b.WriteString("secret_validity:")
		b.WriteString(in.SecretValidity)
		b.WriteByte('\n')
	}
}

// transitiveReachBucket is the label for any positive hop count 1..MaxReachDepth
// — derived from graphschema.MaxReachDepth (declare once, derive everywhere)
// rather than a hand-copied "1-3" literal, which a depth change elsewhere would
// silently leave wrong. NOT cosmetic: this string feeds FingerprintInput.ReachBucket
// (Fingerprint below), so a future MaxReachDepth change moves every affected
// finding's fingerprint and forces a real, corpus-wide re-enrich cascade on
// its own — correct (the depth genuinely changed the input the fingerprint
// exists to track), but worth knowing before bumping that constant, not
// something to discover from an unexpected reenrich spike.
var transitiveReachBucket = fmt.Sprintf("1-%d", graphschema.MaxReachDepth)

// Measured reports which graph fields of a FingerprintInput were actually read
// on this visit (a read error, or Ladybug not holding the node mid-rebuild, is not
// a measurement).
type Measured struct {
	Exposed, Privesc, Reach bool
}

// CarryForward replaces every graph field of in that was not measured this
// visit with the last measured value in prev, and returns the context to store
// for next time. A read error therefore never looks like a state change: the
// fingerprint of a finding whose exposure read failed hashes the exposure it
// had, not "not exposed" — which would re-enrich (and re-alert) the finding,
// then do it again when the read recovered. With nothing measured before
// either, the field keeps its zero value and stores as unmeasured.
func CarryForward(in FingerprintInput, m Measured, prev GraphContext) (FingerprintInput, GraphContext) {
	var out GraphContext
	switch {
	case m.Exposed:
		out.Exposed = fmt.Sprint(in.IsExposed)
	case prev.Exposed != "":
		in.IsExposed = prev.Exposed == "true"
		out.Exposed = prev.Exposed
	}
	if !m.Privesc {
		in.PrivescBucket = prev.PrivescBucket
	}
	out.PrivescBucket = in.PrivescBucket
	if !m.Reach {
		in.ReachBucket = prev.ReachBucket
	}
	out.ReachBucket = in.ReachBucket
	return in, out
}

// ReachBucketFor buckets a transitive-reachability hop count for the fingerprint.
// ok=false (unknown) → "" so a transient graph miss doesn't churn the cache.
func ReachBucketFor(hops int, ok bool) string {
	switch {
	case !ok:
		return ""
	case hops < 0:
		return "none"
	case hops == 0:
		return "direct"
	default:
		return transitiveReachBucket
	}
}

// PrivescBucketFor converts a raw ciem_privesc count to the coarse bucket
// stored in the fingerprint. Bucketing avoids re-enriching on every minor
// count fluctuation while still detecting threshold-crossing changes.
func PrivescBucketFor(count int) string {
	switch {
	case count == 0:
		return "0"
	case count == 1:
		return "1"
	case count <= 3:
		return "2-3"
	default:
		return "4+"
	}
}
