package ciem

import (
	"encoding/json"
	"strings"

	"github.com/vulngraph/vulngraph/internal/awspolicy"
)

// Trust-entry classes for the `trust_entry` signal — who can actually get INTO a
// role. This is the inbound half action-based privesc detection ignores: a
// privesc-capable role whose only entry is an IdP or one specific cross-account
// role is materially harder to reach than a wildcard-assumable one. Worst class
// wins.
const (
	TrustEntryPublic      = "public"        // wildcard principal — anyone can assume
	TrustEntryMixed       = "mixed"         // federated + direct AWS-principal entries coexist
	TrustEntryFederated   = "federated"     // ONLY IdP-federated principals (Okta/Identity Center/OIDC)
	TrustEntryCrossAcct   = "cross_account" // only specific AWS principals, at least one in another account
	TrustEntrySameAcct    = "same_account"  // only specific AWS principals in this account
	TrustEntryServiceOnly = "service"       // only AWS service principals — no human entry at all
)

// TrustEvaluation is the deny-aware verdict on a role's trust policy: who may
// actually assume it once explicit Deny statements are applied.
//
// A trust policy read Allow-only misses the two dominant hardening idioms: an
// "Allow AWS:*" confined by "Deny unless aws:PrincipalOrgID matches" (the
// standard organization-confined cross-account trust) reads as public without
// the Deny, and "Allow" plus "Deny unless aws:MultiFactorAuthPresent" (the
// dominant way MFA is enforced) reads as no-MFA. Both errors push the same
// way — they inflate severity — and PublicEntry, RequiresMFA, and EntryClass
// feed the privesc score cap, enrich suppression, must-fix demotion, belief
// evidence, the graph's trust_entry column, and the assistant's narrative
// prompt, so one wrong verdict here propagates through all of them at once.
type TrustEvaluation struct {
	// PublicEntry reports that some Allow admits the wildcard principal and no
	// Deny confines it — genuinely anyone, in any account, may assume.
	PublicEntry bool

	// HasWildcard reports a surviving wildcard-principal Allow, even if a Deny
	// confines it. A fully blocked wildcard contributes no entry classification.
	HasWildcard bool

	// RequiresMFA reports that EVERY surviving entry path requires an
	// MFA-authenticated session, whether via a Condition on the Allow or a Deny
	// that blocks assumption when MFA is absent. A public path never counts:
	// a caller from any account satisfies MFA with a device of its own, so it
	// controls nothing there.
	RequiresMFA bool

	// AWSPrincipals are the concrete IAM principal ARNs that may assume, with any
	// principal an explicit Deny excludes removed. These become can_assume graph
	// edges, so a phantom entry here is a phantom attack path.
	AWSPrincipals []string

	HasFederated bool
	HasService   bool

	// FederationKind is "saml" | "oidc" | "" and FederationProvider the provider
	// ARN/host of the first federated principal found.
	FederationKind     string
	FederationProvider string

	// ConfinedBy lists the identity-scoping condition keys a Deny used to narrow a
	// wildcard Allow (e.g. "aws:PrincipalOrgID"). Non-empty means the trust looked
	// public but is not.
	//
	// Internal to this evaluation today: it is what suppresses PublicEntry, and is
	// asserted in tests, but no collector or finding surfaces it yet. It is the
	// natural "why is this not public" evidence string for a narrative or for
	// trust-policy finding metadata; wiring it there needs a consumer, and adding a
	// metadata key with no reader is how this repo accumulated its dead-signal
	// backlog. Do not document it as surfaced until it is.
	ConfinedBy []string
}

// EntryClass classifies inbound assumability. accountID is the role's own account,
// used to tell same-account from cross-account entry.
//
// A wildcard Allow confined by a Deny (e.g. to an AWS Organization) is classified
// cross_account, NOT public: entry is limited to the accounts that satisfy the
// Deny's condition, which is materially narrower than "anyone" even though the
// exact member set is not enumerable from the policy alone. Grading it public
// gave such roles the full, uncapped privesc score.
func (e TrustEvaluation) EntryClass(accountID string) string {
	// Federation only counts as a compensating control when the provider is one we
	// actually recognise (SAML/OIDC from a known IdP shape). An unrecognised
	// Federated principal — e.g. an arbitrary attacker-supplied host string — sets
	// HasFederated but resolves no kind, and treating that as IdP-gated entry
	// capped a real critical down to medium on the strength of a provider nobody
	// vetted. Such a trust falls through to the classes below, ending at "" (no
	// cap) if nothing else applies.
	vettedFederation := e.HasFederated && e.FederationKind != ""
	switch {
	case e.PublicEntry:
		return TrustEntryPublic
	case vettedFederation && len(e.AWSPrincipals) > 0:
		return TrustEntryMixed
	case vettedFederation:
		return TrustEntryFederated
	case e.HasWildcard:
		// Confined wildcard — see the doc comment above.
		return TrustEntryCrossAcct
	case e.hasCrossAccountPrincipal(accountID):
		return TrustEntryCrossAcct
	case len(e.AWSPrincipals) > 0:
		return TrustEntrySameAcct
	case e.HasService:
		return TrustEntryServiceOnly
	}
	return ""
}

func (e TrustEvaluation) hasCrossAccountPrincipal(accountID string) bool {
	for _, p := range e.AWSPrincipals {
		if accountID == "" || !strings.Contains(p, ":"+accountID+":") {
			return true
		}
	}
	return false
}

// EvaluateTrustPolicy applies real explicit-deny-wins semantics to a role's trust
// policy (AssumeRolePolicyDocument) and returns the deny-aware verdict.
//
// Each Allow is split into principal/method paths. A Deny affects only paths its
// principal and action cover; universal verdicts combine the surviving paths.
func EvaluateTrustPolicy(doc string) TrustEvaluation {
	statements := parseTrustStatements(doc)
	if len(statements) == 0 {
		return TrustEvaluation{}
	}

	var allows, denies []trustStatement
	for _, st := range statements {
		switch {
		case strings.EqualFold(st.Effect, "Allow"):
			allows = append(allows, st.assumptionPaths()...)
		case strings.EqualFold(st.Effect, "Deny"):
			denies = append(denies, st)
		}
	}
	if len(allows) == 0 {
		return TrustEvaluation{}
	}

	var eval TrustEvaluation

	// A Deny of one principal or assumption method says nothing about another.
	reachingDenies := func(a trustStatement) []trustStatement {
		var out []trustStatement
		for _, d := range denies {
			if d.coversPrincipalOf(a) && d.coversActionsOf(a) {
				out = append(out, d)
			}
		}
		return out
	}

	seen := map[string]bool{}
	mfaOnEveryPath := true
	var confiningKeys []string
	allEntryBlocked := true
	for _, a := range allows {
		var confinedHere []string
		states := a.possibleMFAStates()
		for _, d := range reachingDenies(a) {
			states &^= d.deniedMFAStates()
			if keys := awspolicy.ConfiningKeys(d.Condition); len(keys) > 0 {
				confinedHere = append(confinedHere, keys...)
			}
		}
		if states == 0 {
			continue // A blocked path contributes neither entry nor MFA evidence.
		}
		eval.HasWildcard = eval.HasWildcard || a.principalHasWildcard()
		confiningKeys = append(confiningKeys, confinedHere...)
		allEntryBlocked = false
		publicHere := false
		if a.principalHasWildcard() {
			// Public unless something narrows WHO may take THIS path: a confining
			// Deny reaching it, an unconditional Deny reaching it, or a Condition
			// on the Allow that pins the caller (aws:PrincipalOrgID,
			// aws:SourceAccount, a source network short of the internet). A
			// condition on anything a caller from any account can satisfy —
			// aws:SecureTransport, MFA, a source range covering the internet, an
			// sts:ExternalId, which AWS documents as not a secret — narrows
			// nothing, so the trust stays public.
			publicHere = !awspolicy.RestrictsCaller(a.Condition) && len(confinedHere) == 0
			eval.PublicEntry = eval.PublicEntry || publicHere
		}
		if states != mfaTrue || publicHere {
			mfaOnEveryPath = false
		}
		for _, arn := range a.awsPrincipals() {
			if seen[arn] {
				continue
			}
			seen[arn] = true
			eval.AWSPrincipals = append(eval.AWSPrincipals, arn)
		}
		if fed := a.federatedPrincipals(); len(fed) > 0 {
			eval.HasFederated = true
			if eval.FederationKind == "" {
				for _, f := range fed {
					if kind := FederationKind(f); kind != "" {
						eval.FederationKind, eval.FederationProvider = kind, f
						break
					}
				}
			}
		}
		if a.hasServicePrincipal() {
			eval.HasService = true
		}
	}
	eval.ConfinedBy = dedupeStrings(confiningKeys)
	// MFA is only a compensating control if some path actually survives to be
	// gated; a fully blocked trust grants nothing and needs no control.
	eval.RequiresMFA = mfaOnEveryPath && !allEntryBlocked
	if allEntryBlocked {
		eval.PublicEntry = false
		eval.AWSPrincipals = nil
	}
	return eval
}

// FederationKind classifies an IAM federated principal as "saml", "oidc", or "".
func FederationKind(federated string) string {
	l := strings.ToLower(federated)
	switch {
	case strings.Contains(l, ":saml-provider/"):
		return "saml"
	case strings.Contains(l, ":oidc-provider/"),
		strings.Contains(l, "token.actions.githubusercontent.com"),
		strings.Contains(l, "accounts.google.com"),
		strings.Contains(l, "oidc.eks."):
		return "oidc"
	}
	return ""
}

// ─── trust statement parsing ─────────────────────────────────────────────────

// trustStatement is one statement of a trust policy, keeping the polymorphic
// Principal/Action/Condition as raw JSON for tolerant parsing.
type trustStatement struct {
	Effect string `json:"Effect"`
	// Action names WHICH assumption method the statement governs —
	// sts:AssumeRole, sts:AssumeRoleWithSAML or sts:AssumeRoleWithWebIdentity.
	// TagSession governs tagging, not entry. A Deny scoped to one action must
	// not be credited with blocking another.
	Action    json.RawMessage `json:"Action"`
	Principal json.RawMessage `json:"Principal"`
	Condition json.RawMessage `json:"Condition"`
}

// conditions decodes the Condition block into operator → key → value; nil
// when absent or unparseable.
func (s trustStatement) conditions() map[string]map[string]any {
	var c map[string]map[string]any
	if len(s.Condition) == 0 || json.Unmarshal(s.Condition, &c) != nil {
		return nil
	}
	return c
}

func (s trustStatement) matchesAction(action string) bool {
	if len(s.Action) == 0 {
		return true // Older inventory fixtures omit Action.
	}
	for _, pattern := range rawJSONStrings(s.Action) {
		if WildcardMatch(pattern, action) {
			return true
		}
	}
	return false
}

// The evaluator splits Allows into concrete assumption methods before matching.
func (s trustStatement) coversActionsOf(other trustStatement) bool {
	for _, action := range rawJSONStrings(other.Action) {
		if !s.matchesAction(action) {
			return false
		}
	}
	return true
}

// parseTrustStatements decodes a trust policy's Statement(s), tolerant of the
// single-object-or-array polymorphism AWS allows and of URL-encoded documents.
func parseTrustStatements(doc string) []trustStatement {
	if doc == "" {
		return nil
	}
	doc = awspolicy.NormalizeDocument(doc)
	var p struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &p) != nil || len(p.Statement) == 0 {
		return nil
	}
	var arr []trustStatement
	if json.Unmarshal(p.Statement, &arr) == nil {
		return arr
	}
	var one trustStatement
	if json.Unmarshal(p.Statement, &one) == nil {
		return []trustStatement{one}
	}
	return nil
}

func (s trustStatement) principalHasWildcard() bool {
	var asString string
	if json.Unmarshal(s.Principal, &asString) == nil {
		return asString == "*"
	}
	for _, values := range s.principalMap() {
		for _, v := range values {
			if v == "*" {
				return true
			}
		}
	}
	return false
}

func (s trustStatement) awsPrincipals() []string {
	var out []string
	for key, values := range s.principalMap() {
		if !strings.EqualFold(key, "AWS") {
			continue
		}
		for _, v := range values {
			if v != "*" {
				out = append(out, v)
			}
		}
	}
	return out
}

func (s trustStatement) federatedPrincipals() []string {
	var out []string
	for key, values := range s.principalMap() {
		if strings.EqualFold(key, "Federated") {
			out = append(out, values...)
		}
	}
	return out
}

func (s trustStatement) hasServicePrincipal() bool {
	for key := range s.principalMap() {
		if strings.EqualFold(key, "Service") {
			return true
		}
	}
	return false
}

// principalMap flattens the Principal block's object form into type → values.
func (s trustStatement) principalMap() map[string][]string {
	if len(s.Principal) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(s.Principal, &obj) != nil {
		return nil
	}
	out := make(map[string][]string, len(obj))
	for key, raw := range obj {
		out[key] = rawJSONStrings(raw)
	}
	return out
}

// ─── small JSON helpers ──────────────────────────────────────────────────────

func rawJSONStrings(v json.RawMessage) []string {
	var single string
	if json.Unmarshal(v, &single) == nil {
		return []string{single}
	}
	var list []string
	if json.Unmarshal(v, &list) == nil {
		return list
	}
	return nil
}

// anyStrings normalises a condition value, which JSON-decodes to a string, a
// []any of strings, or a bool.
func anyStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case bool:
		if t {
			return []string{"true"}
		}
		return []string{"false"}
	case []any:
		var out []string
		for _, item := range t {
			out = append(out, anyStrings(item)...)
		}
		return out
	}
	return nil
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
