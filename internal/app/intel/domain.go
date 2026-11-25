// Package intel implements domain squatting and phishing domain monitoring.
// Monitored domains are stored in Postgres; phishing candidates detected via
// certificate transparency logs are stored in ClickHouse. A River job scans
// every 6 hours.
package intel

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

var (
	ErrNotFound      = errors.New("intel: not found")
	ErrDomainExists  = errors.New("intel: domain already monitored")
	ErrInvalidDomain = errors.New("intel: not a valid domain name")
)

// domainRe matches a registrable hostname: one or more dot-separated labels
// (letters/digits/hyphens, no leading/trailing hyphen) followed by an alphabetic
// TLD of ≥2 chars. Deliberately strict — a monitored domain is compared against
// CT-log names, so garbage like "acme,cin" must never enter the set.
var domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

// NormalizeDomain lowercases and strips a scheme, path, port, trailing dot, and a
// leading "*." wildcard so operators can paste a URL or wildcard cert name. It
// returns ErrInvalidDomain if the result is not a syntactically valid hostname.
func NormalizeDomain(raw string) (string, error) {
	d := strings.TrimSpace(strings.ToLower(raw))
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	d = strings.TrimPrefix(d, "*.")
	d = strings.SplitN(d, "/", 2)[0] // drop any path
	d = strings.SplitN(d, ":", 2)[0] // drop any port
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 || !domainRe.MatchString(d) {
		return "", ErrInvalidDomain
	}
	return d, nil
}

// MonitoredDomain is a domain the operator wants to watch for squatters.
type MonitoredDomain struct {
	ID        string
	Domain    string
	CreatedAt time.Time
}

// CandidateStatus tracks the lifecycle of a detected phishing candidate.
type CandidateStatus string

const (
	StatusPending   CandidateStatus = "pending"
	StatusDismissed CandidateStatus = "dismissed" // a human said no
	StatusConfirmed CandidateStatus = "confirmed"
	// StatusAutoDismissed is the cleared-without-a-person bucket. It is a
	// SEPARATE state from StatusDismissed so the human queue means "genuinely
	// suspected" without losing the audit trail or making an automatic clear
	// indistinguishable from an analyst's: the row stays queryable
	// (?status=auto_dismissed) and is never deleted. Kept out of the pending
	// count, and out of the notification path. ClearedBy says which of the two
	// automatic paths put a row here.
	StatusAutoDismissed CandidateStatus = "auto_dismissed"
)

// ClearCause says why a candidate is StatusAutoDismissed.
type ClearCause string

const (
	// ClearedByTriage: the scan-time verdict passed autoDismissible.
	ClearedByTriage ClearCause = "triage"
	// ClearedByRescore: reconcileQueue re-scored a pending row below the
	// detection threshold, whatever its verdict or TriageSource said.
	ClearedByRescore ClearCause = "rescore"
	// NotCleared: the candidate is not StatusAutoDismissed.
	NotCleared ClearCause = ""
)

// rescoreNote opens the note reconcileQueue appends to AIReasoning. It is the
// only persisted trace of a re-score clear, so ClearedBy reads it back.
const rescoreNote = "[auto: re-scored"

// ClearedBy reports which automatic path cleared the candidate.
func (c PhishingCandidate) ClearedBy() ClearCause {
	switch {
	case c.Status != StatusAutoDismissed:
		return NotCleared
	case strings.Contains(c.AIReasoning, rescoreNote):
		return ClearedByRescore
	default:
		return ClearedByTriage
	}
}

// TriageSource says what produced a candidate's verdict. Only TriageLLM is an
// AI verdict: the heuristic fallback scores similarity and issuer, and must
// never be shown or counted as one.
type TriageSource string

const (
	TriageLLM       TriageSource = "llm"       // the configured LLM returned this verdict
	TriageHeuristic TriageSource = "heuristic" // no LLM configured, or the call failed
	TriageNone      TriageSource = ""          // no verdict came back for this hit
)

// PhishingCandidate is a domain detected in CT logs that resembles a monitored domain.
type PhishingCandidate struct {
	ID              string
	Domain          string // the suspicious domain
	MonitoredDomain string // which monitored domain triggered this
	Source          string // "crt_sh" | "certspotter"
	SimilarityScore float32
	Issuer          string
	NotBefore       time.Time
	NotAfter        time.Time
	Status          CandidateStatus
	// AIIsPhishing is the triage verdict. It must be persisted: without it the
	// auto-dismiss gate in RunScan is unreachable and every AI-cleared domain
	// parks in the human queue.
	AIIsPhishing bool
	// AIConfidence is P(phishing): 0 = certainly benign, 1 = certainly a squat.
	AIConfidence float32
	AIReasoning  string
	// TriageSource is what produced AIIsPhishing/AIConfidence/AIReasoning —
	// despite the field names, not always an LLM.
	TriageSource TriageSource
	DetectedAt   time.Time
	ConfirmedBy  string
	ConfirmedAt  *time.Time
}

// CTHit is a raw result from a certificate transparency log query.
type CTHit struct {
	CommonName      string
	Issuer          string
	NotBefore       time.Time
	NotAfter        time.Time
	MonitoredDomain string
	Score           float64
}

// ScanResult is what one full scan cycle produces.
type ScanResult struct {
	Domains          int // monitored domains scanned
	Hits             int // CT log hits found
	New              int // new candidates written to CH
	AITriaged        int // candidates the configured LLM returned a verdict for
	HeuristicTriaged int // candidates scored by the heuristic fallback instead
	AutoDismissed    int // how many were cleared without a person, by triage or re-score (never reached the human queue)
}
