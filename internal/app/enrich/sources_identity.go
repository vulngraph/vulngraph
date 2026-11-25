package enrich

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// neverUsedSentinel is what the AWS IAM collector writes to last_used_days when
// GetRole succeeded and reported no last-used date — the role has never been
// assumed, or not within GetRole's ~400-day tracking window. It is a sentinel, not
// a day count — never render or arithmetic it as one. It does not cover "GetRole
// failed": the collector (roleNeverUsed / roleDetail.observed in
// internal/collect/aws/iam.go) OMITS last_used_days entirely in that case.
const neverUsedSentinel = "9999"

// checkAdminRoleDormant is the CSPM check whose subject is an admin role's
// dormancy (internal/checks/identity_dormant.go).
const checkAdminRoleDormant = "aws-iam-admin-role-dormant"

// roleTrustControl is the compensating control observed on an IAM role's trust
// policy. Two callers ask the question — this source's Suppress branch (which
// moves the score band) and mustfix.go's isControlled (which stamps
// must_fix_class) — and classifyRoleTrust is the single answer both read, so the
// two cannot disagree.
type roleTrustControl int

const (
	roleTrustNone          roleTrustControl = iota // nothing gates entry — never demote
	roleTrustSSOAdminGrant                         // an SSO permission set that GRANTS ADMIN: an anti-control, elevate
	roleTrustMFA                                   // trust policy requires MFA to assume
	roleTrustSSONonAdmin                           // entry via an observed, non-admin SSO permission set
)

// demotes reports whether the control is a real, positively-observed gate on the
// privilege-escalation path.
func (c roleTrustControl) demotes() bool {
	return c == roleTrustMFA || c == roleTrustSSONonAdmin
}

// classifyRoleTrust reports the compensating control gating assumption of an IAM
// role, and the evidence string for it.
//
// The rule is the one isControlled's iam_user branch also follows: ABSENCE OF
// EVIDENCE NEVER DEMOTES. A control must be positively observed, and it must
// actually gate the credential-theft path. Three plausible-looking grounds fail
// that bar and are not controls:
//
//   - trust_entry == "service" is not a control at all — it is the DEFINITION of a
//     workload role, and it is precisely the credential an attacker receives for
//     free after an SSRF or RCE on the workload that holds it. Demoting on it
//     would label a purely by-design fact "MFA / IdP federation" gated, when
//     nothing about it implies MFA.
//
//   - federated_trust == "oidc" is GitHub Actions and EKS IRSA machine
//     federation. No human is involved, so it is not MFA by any reading, and a
//     workflow-assumable role is assumable by anyone who can land a commit on a
//     matching ref.
//
//   - federated_trust == "saml" on a role the platform cannot corroborate rests
//     on data nothing collects — nothing anywhere observes that the IdP
//     enforces MFA. Fail-closed, the same
//     way graphstore's NewNodeSignals defaults to ReachUnknown rather than
//     assuming reachability facts it does not have.
//
// What counts is what the platform actually sees. mfa_required_to_assume is read
// from an aws:MultiFactorAuthPresent condition on the trust policy itself. And a
// SAML role that resolves to a collected sso_permission_set has an observed,
// centrally-revocable, non-admin entry path — that keeps the demotion, on
// evidence. An SSO permission set that GRANTS admin remains an anti-control: it
// is a real admin path and elevates.
// Callers scope this to IAM roles themselves — isControlled off the asset's Type,
// IdentityHygiene off the finding's ResourceType — so it deliberately does not
// re-check the type here; the two callers disagree about which field carries it.
func classifyRoleTrust(ctx context.Context, a asset.Asset, sso SSOResolver) (roleTrustControl, string) {
	var info SSOInfo
	resolved := false
	if sso != nil {
		info, resolved = sso.ResolveRole(ctx, a)
	}
	if resolved && info.GrantsAdmin {
		return roleTrustSSOAdminGrant, "SSO permission set " + info.PermissionSet +
			" grants admin — SSO gating does not neutralize an admin grant"
	}
	if a.Metadata["mfa_required_to_assume"] == "true" {
		return roleTrustMFA, "role assumption requires MFA — the privilege-escalation path is MFA-gated"
	}
	if a.Metadata["federated_trust"] == "saml" && resolved {
		return roleTrustSSONonAdmin, "entry is via SSO permission set " + info.PermissionSet +
			", which does not grant admin"
	}
	return roleTrustNone, ""
}

// AssetGetter fetches a single asset (its identity metadata). asset.Service implements it.
type AssetGetter interface {
	Get(ctx context.Context, id string) (asset.Asset, error)
}

// EdgeReader reads inbound edges and resolves assets by id — used for the human-
// identity federation MFA-gap check. asset.Service implements it. Optional.
type EdgeReader interface {
	EdgesInto(ctx context.Context, dstID, edgeType string) ([]asset.Edge, error)
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
}

// identityPointClamp bounds this source's net contribution so metadata pile-ups
// can't dominate the additive score.
const identityPointClamp = 20

// maxFederatedHumans caps the human-identity fan-out for the MFA-gap check.
const maxFederatedHumans = 25

// IdentityHygiene scores real identity metadata that is collected but was never
// used in scoring (collect/aws/iam.go): MFA, federation, key age, activity. It is
// the metadata-backed successor to PrincipalClass's naming heuristics. Two effects:
//   - DEMOTE (Suppress → monitor + "controlled") a privesc path that is gated by a
//     real compensating control — MFA-required assumption, or SAML entry that
//     resolves to a non-admin SSO permission set (classifyRoleTrust) — encoding
//     the "years-old privesc behind SSO isn't urgent" case.
//   - ELEVATE genuinely weak identities (no-MFA console user, wildcard trust).
//
// Guardrail: missing metadata contributes NOTHING and NEVER demotes — a control
// must be positively present to lower urgency (absence of evidence ≠ safe). KEV is
// never demoted.
type IdentityHygiene struct {
	Assets AssetGetter
	Edges  EdgeReader  // nil disables the human-federation MFA-gap check
	SSO    SSOResolver // nil disables SSO grounding (falls back to trust metadata)
}

func (IdentityHygiene) Name() string { return sourceIdentityHygiene }

func (h IdentityHygiene) Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error) {
	if h.Assets == nil || f.ResourceID == "" {
		return Factor{}, false, nil
	}
	rt := f.ResourceType
	if rt != "iam_user" && rt != "iam_role" {
		return Factor{}, false, nil
	}
	a, err := h.Assets.Get(ctx, f.ResourceID)
	if err != nil {
		return Factor{}, false, err // degrade: score without this source
	}
	m := a.Metadata
	privesc := isPrivesc(f)

	if rt == "iam_role" {
		// Uncontrolled wildcard trust — strong elevate, takes precedence over any
		// control demote (there is no control here, anyone can assume it).
		if m["public_trust"] == "true" {
			return Factor{
				Source: sourceIdentityHygiene, Points: 15, Floor: ThresholdPipeline,
				Detail: "role trust policy allows any principal to assume it (public AssumeRole)",
			}, true, nil
		}
		// Compensating control on a privilege-escalation path → demote to monitor
		// (must_fix class "controlled"). Never demote a known-exploited one.
		//
		// classifyRoleTrust is the SINGLE definition of what counts as a control
		// here — shared with mustfix.go's isControlled so the score band and the
		// must-fix class can never disagree about the same role. See its doc comment
		// for which grounds do not count and why.
		//
		// The suppression is what actually moves the band: it pins any score of 50 or
		// more to ThresholdPipeline-1 (49) — a "controlled" finding is capped by this
		// branch, not scoring low on its own merits.
		if privesc && !f.KnownExploited {
			ctrl, detail := classifyRoleTrust(ctx, a, h.SSO)
			switch {
			case ctrl == roleTrustSSOAdminGrant:
				return Factor{
					Source: sourceIdentityHygiene, Points: 15, Floor: ThresholdHigh,
					Detail: detail,
				}, true, nil
			case ctrl.demotes():
				return Factor{Source: sourceIdentityHygiene, Suppress: true, Detail: detail}, true, nil
			}
		}
		// Right-sizing: dormant vs actively-used admin. Not applied to the
		// dormant-admin finding itself: its dormancy IS the finding, and
		// demoting it for being dormant would grade it down by its own predicate.
		var pts int
		var notes []string
		if f.CheckID != checkAdminRoleDormant {
			pts, notes = adminRightSizing(m)
		}
		if privesc {
			g, note, err := h.humanMFAGap(ctx, f.ResourceID)
			if err != nil {
				return Factor{}, false, fmt.Errorf("IdentityHygiene: %w", err) // degrade: score without this source
			}
			if g > 0 {
				pts, notes = pts+g, append(notes, note)
			}
		}
		return factorFromPoints(pts, notes)
	}

	// iam_user
	pts, notes := 0, []string(nil)
	var unread error
	switch {
	case m["console_access"] == "true" && m["mfa_enabled"] == "false":
		pts, notes = pts+12, append(notes, "console user without MFA")
	case m["console_access"] != "false" && m["mfa_enabled"] != "true":
		// Console access or MFA was not read (the account root's console_access
		// needs the credential report): the penalty is neither applied nor ruled
		// out, so the rest is scored and the source reported unmeasured.
		unread = fmt.Errorf("IdentityHygiene: %s: console access or MFA unread", f.ResourceID)
	}
	if atoiOr(m["active_key_count"], 0) >= 2 {
		pts, notes = pts+4, append(notes, "multiple active access keys")
	}
	if atoiOr(m["access_key_age_days"], 0) > 365 {
		pts, notes = pts+4, append(notes, "access key older than 1 year")
	}
	if m["inactive"] == "true" {
		pts, notes = pts-12, append(notes, "inactive principal (no console, no active keys)")
	}
	factor, applied, _ := factorFromPoints(pts, notes)
	return factor, applied, unread
}

// humanMFAGap returns +10 if any human identity federated into this role lacks MFA
// — an unMFA'd human who can federate in is a real path. A nil EdgeReader
// disables the check. A read error is returned, not read as "no unMFA'd human":
// the factor is then unknown and the caller records the source as unmeasured.
func (h IdentityHygiene) humanMFAGap(ctx context.Context, roleID string) (int, string, error) {
	if h.Edges == nil {
		return 0, "", nil
	}
	edges, err := h.Edges.EdgesInto(ctx, roleID, "federated_access")
	if err != nil {
		return 0, "", fmt.Errorf("humanMFAGap: federated edges: %w", err)
	}
	ids := make([]string, 0, len(edges))
	for _, e := range edges {
		if e.SrcType == "human_identity" && e.SrcID != "" {
			ids = append(ids, e.SrcID)
			if len(ids) >= maxFederatedHumans {
				break
			}
		}
	}
	if len(ids) == 0 {
		return 0, "", nil
	}
	humans, err := h.Edges.ByIDs(ctx, ids)
	if err != nil {
		return 0, "", fmt.Errorf("humanMFAGap: human identities: %w", err)
	}
	for _, hu := range humans {
		if strings.EqualFold(hu.Metadata["mfa_enabled"], "false") {
			return 10, "a human identity without MFA can federate into this privilege-escalation-capable role", nil
		}
	}
	return 0, "", nil
}

// factorFromPoints builds the source's Factor from an accumulated point total,
// clamped to ±identityPointClamp. Zero total → not applied.
func factorFromPoints(pts int, notes []string) (Factor, bool, error) {
	if pts == 0 {
		return Factor{}, false, nil
	}
	if pts > identityPointClamp {
		pts = identityPointClamp
	}
	if pts < -identityPointClamp {
		pts = -identityPointClamp
	}
	return Factor{Source: sourceIdentityHygiene, Points: pts, Detail: strings.Join(notes, "; ")}, true, nil
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// adminRightSizing scores an admin principal by how recently it was actually used,
// and renders the evidence note. Extracted so the sentinel handling is testable.
func adminRightSizing(m map[string]string) (int, []string) {
	pts, notes := 0, []string(nil)
	if m["admin"] != "true" {
		return pts, notes
	}
	// ABSENT means the collector never observed this role's last-used date (its
	// GetRole call failed), NOT that the role is idle. Neither direction may be
	// scored off it: an unobserved role is neither demoted as dormant nor promoted
	// as active. Stated explicitly rather than left to atoiOr's -1 default, because
	// this is the guarantee, not an accident of the default.
	raw, ok := m["last_used_days"]
	if !ok {
		return pts, notes
	}
	if d := atoiOr(raw, -1); d >= 90 {
		// "9999" is the collector's observed-never-used sentinel, not a measurement.
		// Rendering it verbatim produced "admin role unused for 9999d" — a
		// fabricated, specific-looking 27 years that a responder would reasonably
		// read as real evidence. aws-iam-role-unused already guards this sentinel
		// explicitly; this consumer did not.
		note := "admin role unused for " + raw + "d"
		if raw == neverUsedSentinel {
			note = "admin role has no recorded use"
		}
		pts, notes = pts-6, append(notes, note)
	} else if d >= 0 && d < 30 {
		pts, notes = pts+6, append(notes, "admin role actively used")
	}
	return pts, notes
}
