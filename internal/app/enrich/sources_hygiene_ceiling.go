package enrich

import (
	"context"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// hygieneOptimizationChecks are IAM hygiene/optimization checks whose content is
// purely advisory (right-size, rotate, disable-if-unused) — never a "wake
// someone up" action, regardless of how dangerous the underlying principal
// looks by OTHER findings on the same resource.
//
// These checks dominate the page band for a structural reason: attack_paths and
// toxic_combo score the RESOURCE's escalation reach from its ciem_privesc/
// exposure peer findings (legitimately, for those peer findings), but that same
// peer-derived signal additively lands on every hygiene finding about the
// resource too. aws-iam-user-unused-access-key (a DORMANT key) and
// aws-iam-user-stale-console (a 90+-day-idle login) are the clearest cases: the
// checks themselves describe the OPPOSITE of urgency.
//
// This does not touch the resource-context sources (attack_paths, toxic_combo,
// cross_cluster) or blanket-suppress these checks' severity — the underlying
// signal is real and still surfaces the actual privesc/exposure findings on the
// resource at page/high. It only caps THESE specific advisory checks below the
// page band, mirroring contextIndependentCriticals' shape but inverted. Kept
// deliberately tiny — only add a check here when its content is unambiguously
// advisory, never an active-incident description.
//
// The GCP entries are the ceiling's other half. Each is documented in
// internal/checks/cspm_gcp_iam.go as the mirror of the AWS check directly above
// it — same finding, same advisory content — so both sides need the same
// ceiling, or the identical credential-hygiene claim pages on one cloud and not
// the other. gcp-sa-key-exposed is deliberately NOT here: a leaked private key
// is a confirmed incident, not hygiene, and its own check text says so.
var hygieneOptimizationChecks = map[string]string{
	"aws-iam-overprivileged-role":    "right-sizing suggestion — an admin role using a fraction of its grant, not an active incident",
	"aws-iam-access-key-old":         "key-rotation hygiene on a key that is still active and in use, not an active incident",
	"aws-iam-user-unused-access-key": "a DORMANT access key nobody is using — the opposite of urgent",
	"aws-iam-user-no-mfa":            "missing-control hygiene on the user's own console login, not an active incident",
	"aws-iam-user-stale-console":     "a console login unused for 90+ days — the opposite of urgent",
	// One graded check covers GCP SA key age and disuse
	// (internal/checks/cspm_gcp_iam.go); the ceiling keys on its exact ID, so a
	// rename that misses this map silently stops the ceiling applying.
	// A ceiling is scoring logic over UNCHANGED finding inputs, so it does not
	// re-enrich on its own — an enrichcache.LogicVersion bump is required to
	// apply it to the standing corpus.
	"gcp-sa-user-managed-key": "standing-credential hygiene — rotate or migrate to keyless auth; a CONFIRMED leaked key is gcp-sa-key-exposed, which is deliberately not capped",
	// The privilege-aware dormancy and key checks grade HIGHER than their plain
	// siblings because a leak would hand over the account, but their content is
	// the same advisory "disable/delete/replace this credential" — privilege
	// raises the queue position, not the claim to an incident.
	"aws-iam-admin-role-dormant":    "a dormant admin role — delete or lock it down; nobody is using it, so nothing is under way",
	"aws-iam-admin-user-dormant":    "a dormant admin user — remove its credentials; nobody is using it, so nothing is under way",
	"gcp-sa-admin-dormant":          "a dormant admin-equivalent service account — disable it; nobody is using it, so nothing is under way",
	"aws-iam-admin-user-key-no-mfa": "a long-lived admin key with no MFA device — replace it with a role; a standing risk, not an active incident",
	// The GCP mirror of aws-iam-overprivileged-role: a service account holding
	// an admin role is a right-sizing task, however reachable the account is.
	"gcp-sa-admin-privileges": "an admin role on a service account — narrow it; a standing grant, not an active incident",
	// Not IAM, but the same shape: cryptographic inventory for post-quantum
	// planning. Every RSA/ECDSA certificate fires; none may page on graph context.
	"acm-cert-non-pqc": "post-quantum migration inventory — informational, never an incident",
}

const sourceHygieneCeiling = "hygiene_ceiling"

// HygieneCeiling caps IAM hygiene/optimization checks below the page band.
// Resource-context sources (attack_paths, toxic_combo, cross_cluster) correctly
// score how dangerous the RESOURCE is from its other findings, but an advisory
// suggestion about that same resource must never inherit enough of that signal
// to page on its own — the actual privesc/exposure findings already do that.
type HygieneCeiling struct{}

// Name identifies the source in the score breakdown.
func (HygieneCeiling) Name() string { return sourceHygieneCeiling }

// Evaluate caps a listed check below the page band; all other findings pass
// through untouched.
func (HygieneCeiling) Evaluate(_ context.Context, f finding.Finding) (Factor, bool, error) {
	reason, ok := hygieneOptimizationChecks[f.CheckID]
	if !ok {
		return Factor{}, false, nil
	}
	return Factor{
		Source:  sourceHygieneCeiling,
		Ceiling: ThresholdPage,
		Detail:  reason,
	}, true, nil
}
