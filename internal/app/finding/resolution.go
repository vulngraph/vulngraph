package finding

// ResolutionReason records WHY a finding stopped being open.
//
// The taxonomy exists to answer one question a timestamp cannot: was this
// finding worth showing a human? A resolved_at timestamp alone
// conflates the two outcomes that matter most —
//
//	someone corrected the control      → the finding did its job
//	the resource evaporated by itself  → nobody ever needed to see it
//
// so a check whose findings all resolve looks identical whether it is driving
// real remediation or just narrating cloud churn — a near-100%-false-positive
// check and a legitimately-churning-but-correct one both show "100% resolved"
// with no way to tell them apart, unless that distinction lives in a metric
// rather than a note someone has to remember to reread.
//
// Keep this set SMALL and closed. Its value is comparability across checks: a new
// reason that overlaps an existing one silently splits a check's history in two
// and breaks the very ratio this exists to produce.
type ResolutionReason string

const (
	// ReasonFixed: the emitting check or feed ran again against a live resource and
	// no longer reports the problem, or the provider reports the remediation itself
	// (a GHAS code-scanning alert GitHub marked fixed, a leaked secret resolved as
	// revoked). The control was corrected — this is the outcome that means the
	// finding was worth surfacing.
	ReasonFixed ResolutionReason = "fixed"

	// ReasonResourceGone: the resource no longer exists (deleted, terminated, or
	// last_seen fell behind its provider's collection high-water mark). The finding
	// closed itself without anyone acting on it. This is the junk signal — not
	// always noise, since a genuinely dangerous resource can be legitimately torn
	// down, but a check that closes this way almost every time is describing
	// ephemeral infrastructure rather than risk.
	ReasonResourceGone ResolutionReason = "resource_gone"

	// ReasonManual: a human resolved it explicitly — through the API, or by
	// dismissing the provider's own alert (a GHAS alert dismissed, or a secret
	// alert resolved as false positive / won't fix / used in tests, on GitHub) —
	// with their justification recorded separately (resolved_reason /
	// resolved_by metadata). Deliberately its own reason:
	// folding it into "fixed" would let manual triage inflate a check's apparent
	// effectiveness, which is exactly the self-congratulatory metric to avoid.
	ReasonManual ResolutionReason = "manual"

	// ReasonProviderClosed: a provider-native feed stopped listing the finding as
	// active in a listing proven complete (GuardDuty: an operator archived it, a
	// suppression rule matched it, or it aged out of the provider's window; SCC:
	// the finding went inactive), or the provider closed it for a reason that is
	// neither a fix nor a human dismissal (a GHAS secret alert resolved because
	// its custom pattern was edited or deleted).
	// Deliberately NOT "fixed": archiving is triage, not remediation, and a
	// suppression rule says nothing about the threat having stopped. Excluded from
	// the junk ratio: the provider's reason is not visible to us, so it cannot
	// grade the finding either way.
	ReasonProviderClosed ResolutionReason = "provider_closed"
)

// validResolutionReasons is the closed set the repo accepts.
var validResolutionReasons = map[ResolutionReason]bool{
	ReasonFixed:          true,
	ReasonResourceGone:   true,
	ReasonManual:         true,
	ReasonProviderClosed: true,
}

// Valid reports whether r is a known reason. Service.Resolve rejects anything else:
// every resolution must say why, and silently accepting "" would let unexplained
// resolutions in one call site at a time.
func (r ResolutionReason) Valid() bool { return validResolutionReasons[r] }

// CountsTowardQuality reports whether a resolution says anything about whether the
// finding was worth showing. provider_closed and unknown (no reason recorded)
// do not.
func (r ResolutionReason) CountsTowardQuality() bool {
	return r == ReasonFixed || r == ReasonResourceGone || r == ReasonManual
}

// CheckQuality is one check's resolution outcomes — the standing scoreboard that
// replaces sampling findings by hand.
type CheckQuality struct {
	CheckID      string
	Source       string
	Open         int
	Fixed        int
	ResourceGone int
	Manual       int
	Unknown      int // resolved with no reason recorded; Service.Resolve rejects an empty reason
}

// JunkRate is the fraction of quality-bearing resolutions that closed because the
// resource disappeared rather than because anyone acted. 0 when nothing
// quality-bearing has resolved yet — deliberately not -1 or NaN, so a caller that
// forgets to check Measurable simply sees a harmless zero instead of a wild value
// in a dashboard.
//
// Manual counts as "acted on", not junk: a human looked at it and made a call.
func (q CheckQuality) JunkRate() float64 {
	total := q.Fixed + q.ResourceGone + q.Manual
	if total == 0 {
		return 0
	}
	return float64(q.ResourceGone) / float64(total)
}

// Measurable reports whether this check has enough quality-bearing resolutions for
// JunkRate to mean anything. A check with three resolutions is not evidence.
func (q CheckQuality) Measurable() bool {
	return q.Fixed+q.ResourceGone+q.Manual >= minQualitySample
}

// minQualitySample is the number of quality-bearing resolutions a check needs
// before its junk rate is reported. Low enough that a small check is not invisible
// forever, high enough that one unlucky week cannot condemn it.
const minQualitySample = 20
