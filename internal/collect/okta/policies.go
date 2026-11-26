package okta

import (
	"context"
	"fmt"
	"strings"
)

// Okta policy types. MFA_ENROLL decides who must ENROLL a factor at all;
// ACCESS_POLICY (the authentication policies) decides how many factors an app
// sign-on actually CHALLENGES for. Both are needed: a user can be required to
// enroll and still sign in to a legacy app under a one-factor rule.
const (
	policyTypeMFAEnroll  = "MFA_ENROLL"
	policyTypeAccess     = "ACCESS_POLICY"
	factorModeSingle     = "1FA"
	accessAllow          = "ALLOW"
	enrollSelfNever      = "NEVER"
	statusActive         = "ACTIVE"
	maxPoliciesPerType   = 200
	policyRuleFetchLimit = 200
)

// orgMFAPolicy is the org's OBSERVED authentication posture, resolved per Okta
// group. It exists only when every policy and rule listing succeeded; a partial
// read yields ok=false from readOrgMFAPolicy and the caller emits no policy keys
// at all. Half a policy set answers the question "is there a gap for one group?"
// wrongly in the reassuring direction, which is the failure mode this whole
// connector exists to stop.
type orgMFAPolicy struct {
	// enrollRequired holds group IDs an ACTIVE MFA_ENROLL rule requires factor
	// enrollment for. everyoneEnrollRequired covers rules with no group condition.
	enrollRequired         map[string]bool
	everyoneEnrollRequired bool

	// singleFactor holds group IDs an ACTIVE authentication-policy rule admits
	// with ONE factor (access ALLOW, factorMode 1FA) — the legacy
	// conditional-access gap. everyoneSingleFactor covers ungrouped rules.
	singleFactor         map[string]bool
	everyoneSingleFactor bool
}

// enrollRequiredFor reports whether the group must enroll a factor.
func (p orgMFAPolicy) enrollRequiredFor(groupID string) bool {
	return p.everyoneEnrollRequired || p.enrollRequired[groupID]
}

// singleFactorFor reports whether any active rule lets this group in with one
// factor.
func (p orgMFAPolicy) singleFactorFor(groupID string) bool {
	return p.everyoneSingleFactor || p.singleFactor[groupID]
}

// oktaPolicy is one row of GET /api/v1/policies?type=...; conditions may scope
// the whole policy to groups, and each rule may narrow further.
type oktaPolicy struct {
	ID         string           `json:"id"`
	Status     string           `json:"status"`
	Conditions policyConditions `json:"conditions"`
}

type policyConditions struct {
	People struct {
		Groups struct {
			Include []string `json:"include"`
		} `json:"groups"`
	} `json:"people"`
}

// oktaPolicyRule is one row of GET /api/v1/policies/{id}/rules.
type oktaPolicyRule struct {
	Status     string           `json:"status"`
	Conditions policyConditions `json:"conditions"`
	Actions    struct {
		Enroll struct {
			Self string `json:"self"` // CHALLENGE | LOGIN | NEVER
		} `json:"enroll"`
		AppSignOn struct {
			Access             string `json:"access"` // ALLOW | DENY
			VerificationMethod struct {
				FactorMode string `json:"factorMode"` // 1FA | 2FA
			} `json:"verificationMethod"`
		} `json:"appSignOn"`
	} `json:"actions"`
}

// readOrgMFAPolicy resolves the org's enrollment and sign-on posture per group.
// ok is false when ANY policy or rule listing failed — the result is then
// unusable and must not be published as fact.
func (c *Collector) readOrgMFAPolicy(ctx context.Context, domain, token string) (orgMFAPolicy, bool) {
	p := orgMFAPolicy{
		enrollRequired: map[string]bool{},
		singleFactor:   map[string]bool{},
	}

	enroll, err := c.listPolicies(ctx, domain, token, policyTypeMFAEnroll)
	if err != nil {
		return orgMFAPolicy{}, false
	}
	access, err := c.listPolicies(ctx, domain, token, policyTypeAccess)
	if err != nil {
		return orgMFAPolicy{}, false
	}

	for _, pol := range enroll {
		if !strings.EqualFold(pol.Status, statusActive) {
			continue
		}
		rules, err := c.policyRules(ctx, domain, token, pol.ID)
		if err != nil {
			return orgMFAPolicy{}, false
		}
		for _, r := range rules {
			if !strings.EqualFold(r.Status, statusActive) {
				continue
			}
			if strings.EqualFold(r.Actions.Enroll.Self, enrollSelfNever) {
				continue // this rule exempts its audience from enrolling
			}
			groups := ruleGroups(pol, r)
			if len(groups) == 0 {
				p.everyoneEnrollRequired = true
				continue
			}
			for _, g := range groups {
				p.enrollRequired[g] = true
			}
		}
	}

	for _, pol := range access {
		if !strings.EqualFold(pol.Status, statusActive) {
			continue
		}
		rules, err := c.policyRules(ctx, domain, token, pol.ID)
		if err != nil {
			return orgMFAPolicy{}, false
		}
		for _, r := range rules {
			if !strings.EqualFold(r.Status, statusActive) {
				continue
			}
			a := r.Actions.AppSignOn
			if !strings.EqualFold(a.Access, accessAllow) {
				continue
			}
			if !strings.EqualFold(a.VerificationMethod.FactorMode, factorModeSingle) {
				continue
			}
			groups := ruleGroups(pol, r)
			if len(groups) == 0 {
				p.everyoneSingleFactor = true
				continue
			}
			for _, g := range groups {
				p.singleFactor[g] = true
			}
		}
	}

	return p, true
}

// ruleGroups returns the group IDs a rule applies to: the rule's own include
// list when it has one, otherwise the policy's. An empty result means the rule
// is unscoped and therefore applies to everyone.
func ruleGroups(pol oktaPolicy, r oktaPolicyRule) []string {
	if g := r.Conditions.People.Groups.Include; len(g) > 0 {
		return g
	}
	return pol.Conditions.People.Groups.Include
}

func (c *Collector) listPolicies(ctx context.Context, domain, token, policyType string) ([]oktaPolicy, error) {
	url := fmt.Sprintf("%s/api/v1/policies?type=%s&limit=%d", domain, policyType, maxPoliciesPerType)
	var all []oktaPolicy
	for page := 0; page < maxPages; page++ {
		var batch []oktaPolicy
		next, err := c.doJSON(ctx, url, token, &batch)
		if err != nil {
			return nil, fmt.Errorf("listPolicies %s page %d: %w", policyType, page, err)
		}
		all = append(all, batch...)
		if next == "" {
			return all, nil
		}
		url = next
	}
	return nil, fmt.Errorf("listPolicies: page limit %d reached with more policies unread", maxPages)
}

func (c *Collector) policyRules(ctx context.Context, domain, token, policyID string) ([]oktaPolicyRule, error) {
	url := fmt.Sprintf("%s/api/v1/policies/%s/rules?limit=%d", domain, policyID, policyRuleFetchLimit)
	var all []oktaPolicyRule
	for page := 0; page < maxPages; page++ {
		var rules []oktaPolicyRule
		next, err := c.doJSON(ctx, url, token, &rules)
		if err != nil {
			return nil, fmt.Errorf("policyRules %s page %d: %w", policyID, page, err)
		}
		all = append(all, rules...)
		if next == "" {
			return all, nil
		}
		url = next
	}
	return nil, fmt.Errorf("policyRules: page limit %d reached with more rules unread", maxPages)
}
