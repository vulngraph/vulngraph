package enrich

import (
	"context"
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Threat findings (GuardDuty, GCP SCC) are BEHAVIORAL detections — "something is
// happening on this resource now." Enrichment's graph-signal scoring (exposure,
// blast, privesc) can't see why they matter, so it demotes them to the monitor
// band and an active compromise is buried. This source floors them by threat
// FAMILY, not blanket severity: the volume is dominated by two noisy DNS-observation
// types (PhishingDomainRequest, DriveBySourceTraffic) that would flood the
// worklist, so those are NOT floored on their own; the genuinely act-now families
// are lifted into the actionable/page bands per their real urgency.
//
// The two DNS-observation families stay excluded from the blanket per-check
// floor — workloads that resolve user- or third-party-supplied domains make
// a lone DNS lookup to a flagged domain expected traffic, not evidence of
// compromise, and floors on it would flood the actionable band with
// noise. Instead they get a corroboration-gated floor: if the SAME host also has
// another distinct, independently-floored threat detection, that is real
// converging evidence of compromise and the DNS-observation finding escalates to
// actionable alongside it. An isolated phishing-domain DNS query with no other
// signal on the host stays at its graph-scored band.

const sourceThreatFloor = "threat_floor"

// threatDNSObservationFamilies are the noisy, single-signal DNS-observation
// GuardDuty families: NOT floored on their own, but eligible for the
// corroboration escalation in corroboratedByAnotherThreat below.
//
// "DomainRequest" covers the whole DNS-reputation family in one entry —
// PhishingDomainRequest, DGADomainRequest, SuspiciousDomainRequest,
// AbusedDomainRequest. Naming only PhishingDomainRequest would leave the
// siblings matching threatHighMarkers instead ("DGADomainRequest" is literally
// one of them, and the Reputation variants match "Impact:"), floating findings
// that are the SAME single-DNS-lookup mechanism to actionable while
// PhishingDomainRequest is held back.
//
// A host that resolves externally-supplied domains makes a DNS lookup to a
// flagged domain expected traffic rather than evidence of compromise. The corroboration gate is what separates the two, and every
// DNS-mechanism family has to reach it.
var threatDNSObservationFamilies = []string{
	"DomainRequest",
	"DriveBySourceTraffic",
}

// threatPageMarkers: highest-fidelity active-compromise families — a live host is
// executing malware, mining, or its stolen credentials are being used. Low volume,
// genuinely page-worthy.
var threatPageMarkers = []string{
	"InstanceCredentialExfiltration", // stolen instance-role creds used
	"MaliciousFile",                  // malware executed on the host
	"CryptoCurrency", "BitcoinTool",  // active mining = compromised host
}

// threatHighMarkers: actionable active-threat families — command-and-control,
// exfiltration, malware domain-generation, credential-theft attempts, impact.
// Investigate promptly, but not necessarily wake-someone.
var threatHighMarkers = []string{
	"C&CActivity", "Backdoor",
	"DataExfiltration", "Exfiltration",
	"DGADomainRequest",
	"MetadataDNSRebind",
	"PrivilegeEscalation", "Persistence",
	"Impact:", "Impact/",
}

// isThreatFinding reports whether a finding is a behavioral threat detection.
func isThreatFinding(f finding.Finding) bool {
	return f.Type == "threat" || f.Source == "aws_guardduty" || f.Source == "gcp_scc"
}

// threatFloor returns the band floor for a threat finding, or 0 for none. The
// noisy DNS-observation GuardDuty types are excluded, so they stay at their
// graph-scored band and never flood the actionable queue.
func threatFloor(f finding.Finding) int {
	id := f.CheckID
	// The DNS-observation gate runs FIRST, ahead of every marker list.
	//
	// A DNS-observation finding (GuardDuty's '!DNS' suffix, or the named noisy
	// families) is a single reputation signal — a lone DNS query to a flagged
	// domain, no confirmed connection. Defer it to the corroboration gate rather
	// than blanket-flooring by family: C&CActivity.B!DNS / Backdoor... match the
	// high markers below and would floor every host hitting a threat-intel
	// domain to actionable on one lookup each (a shared resolver/agent hitting
	// the domain, not a breach on every host). A genuine beacon on a compromised
	// host carries other signals and escalates via corroboration; an isolated
	// lookup stays at its graph-scored band.
	//
	// Order matters: this gate must run BEFORE the page-marker loop below.
	// CryptoCurrency:EC2/BitcoinTool.B!DNS matches "CryptoCurrency"/"BitcoinTool"
	// and would floor straight to PAGE despite ending in '!DNS' if the page-marker
	// loop ran first — precisely the single-lookup class this gate exists to hold
	// back. A host genuinely mining crypto emits other signals and still reaches
	// page through corroboration; the lookup on its own does not.
	if isDNSObservationFamily(id) {
		return 0
	}
	for _, m := range threatPageMarkers {
		if strings.Contains(id, m) {
			return ThresholdPage
		}
	}
	floor := 0
	for _, m := range threatHighMarkers {
		if strings.Contains(id, m) {
			floor = ThresholdHigh
			break
		}
	}
	// GuardDuty's own severity is the fallback for every family no marker
	// names (AttackSequence:*, Trojan:*, UnauthorizedAccess:*/AnomalousBehavior,
	// Execution:Runtime/ReverseShell, CredentialAccess:* …): a critical is its
	// highest-confidence compromise verdict (AttackSequence correlates several
	// signals into one), a high an act-now one. Without it those land in the
	// pipeline band and never alert. One floor, the higher of the two — a
	// marker and the severity never add up.
	//
	// Policy:* types are excluded: they report standing configuration (root
	// credentials used, S3 public access unblocked), not a live compromise —
	// the same posture-not-compromise line that keeps principal_class and
	// identity_hygiene out of the alerting floors. Recon:* and TorClient stay
	// in: someone is acting on the resource now.
	if f.Source == "aws_guardduty" && !strings.HasPrefix(id, "Policy:") {
		switch f.Severity {
		case finding.SeverityCritical:
			return ThresholdPage
		case finding.SeverityHigh:
			return ThresholdHigh
		}
	}
	if floor > 0 {
		return floor
	}
	// GCP SCC threat findings are a small, GCP-curated set — floor high/critical
	// ones to the actionable band wholesale (no per-family list to maintain, no
	// flood risk at their volume).
	if f.Source == "gcp_scc" && (f.Severity == finding.SeverityHigh || f.Severity == finding.SeverityCritical) {
		return ThresholdHigh
	}
	return 0
}

// isDNSObservationFamily reports whether a check belongs to one of the noisy
// single-signal DNS-observation GuardDuty families excluded from the blanket
// per-check floor.
func isDNSObservationFamily(checkID string) bool {
	// GuardDuty suffixes DNS-based detections with "!DNS" — a single DNS-query
	// observation, the noisiest/most-FP-prone signal class, regardless of the
	// threat family it names. Treat all of them as corroboration-gated.
	if strings.HasSuffix(checkID, "!DNS") {
		return true
	}
	for _, m := range threatDNSObservationFamilies {
		if strings.Contains(checkID, m) {
			return true
		}
	}
	return false
}

// ThreatFloor floors active-threat findings out of the monitor band so behavioral
// detections graph-scoring can't judge are not silently missed.
type ThreatFloor struct {
	// Findings is optional (nil disables corroboration): it lets a noisy
	// DNS-observation finding check whether the SAME host also carries another
	// distinct, independently-floored threat detection.
	Findings ResourceFindings
}

// Name identifies the source in the score breakdown.
func (ThreatFloor) Name() string { return sourceThreatFloor }

// Evaluate floors an act-now threat finding; noise and non-threats pass through.
// A DNS-observation finding with no independent floor is escalated to
// actionable only when corroborated by another distinct threat detection on
// the same host.
func (t ThreatFloor) Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error) {
	if !isThreatFinding(f) {
		return Factor{}, false, nil
	}
	floor := threatFloor(f)
	if floor == 0 {
		corroborated, err := t.corroboratedByAnotherThreat(ctx, f)
		if err != nil {
			// Unknown corroboration is not "uncorroborated" and not
			// "corroborated" — but the ceiling below is the fail-safe half, and
			// dropping the whole source on an error would also drop the ceiling,
			// letting graph points carry a lone DNS lookup into high/page. Keep
			// the ceiling and report the source unmeasured.
			return uncorroboratedDNSCeiling(), true, fmt.Errorf("threat floor: corroboration check: %w", err)
		}
		if !corroborated {
			// Declining to FLOOR is not the same as holding the finding back:
			// threatFloor returning 0 only removes a lift, it caps nothing, so the
			// additive graph sources (blast radius, internet reach) can carry an
			// uncorroborated single-DNS-lookup finding into the actionable band on
			// their own — a GuardDuty '!DNS' detection on a busy, internet-facing
			// EC2 can score High base plus enough resource context to clear the
			// threshold without any second signal about the host. The corroboration
			// gate above is the intended escalation path; this ceiling is what makes
			// it the ONLY one, so an isolated reputation lookup can reach the
			// pipeline band for review but never the high/page bands.
			//
			// Only the DNS-observation families are capped — threatFloor also
			// returns 0 for threat findings that match no marker at all (e.g.
			// Recon:EC2/PortProbeUnprotectedPort), and those keep their graph score.
			// Aggregate lets a page-level Floor (KEV, CriticalFloor) breach a
			// Ceiling, so this can never hide a known-exploited finding.
			if isDNSObservationFamily(f.CheckID) {
				return uncorroboratedDNSCeiling(), true, nil
			}
			return Factor{}, false, nil
		}
		return Factor{
			Source: sourceThreatFloor,
			Floor:  ThresholdHigh,
			Detail: "corroborated by another distinct active-threat detection on the same host — escalated to the actionable band despite being an excluded noisy DNS-observation family on its own",
		}, true, nil
	}
	band := "actionable"
	if floor >= ThresholdPage {
		band = "page"
	}
	return Factor{
		Source: sourceThreatFloor,
		Floor:  floor,
		Detail: "active-threat detection (" + f.Source + ") floored to the " + band + " band — behavioral signal graph scoring can't contextualize",
	}, true, nil
}

// uncorroboratedDNSCeiling caps a DNS-observation detection below the
// actionable band until another threat on the same host corroborates it.
func uncorroboratedDNSCeiling() Factor {
	return Factor{
		Source:  sourceThreatFloor,
		Ceiling: ThresholdHigh,
		Detail:  "uncorroborated DNS-observation detection — a single reputation lookup with no other active-threat signal on the same host; capped below the actionable band",
	}
}

// corroboratedByAnotherThreat reports whether f is an excluded DNS-observation
// finding AND the same resource carries another, distinct threat finding that
// independently earns a floor — real converging evidence, not an isolated hit.
// That includes a marker-less GuardDuty finding floored by its own high or
// critical severity: a second, distinct GuardDuty verdict on the same host is
// exactly the converging evidence this gate waits for. Medium and Policy:
// peers carry no floor and corroborate nothing.
func (t ThreatFloor) corroboratedByAnotherThreat(ctx context.Context, f finding.Finding) (bool, error) {
	if t.Findings == nil || f.ResourceID == "" || !isDNSObservationFamily(f.CheckID) {
		return false, nil
	}
	peers, err := t.Findings.List(ctx, finding.Filter{ResourceID: f.ResourceID, Limit: 200})
	if err != nil {
		return false, err
	}
	for _, p := range peers {
		if p.ID == f.ID || p.CheckID == f.CheckID || !isThreatFinding(p) {
			continue
		}
		if threatFloor(p) > 0 {
			return true, nil
		}
	}
	return false, nil
}
