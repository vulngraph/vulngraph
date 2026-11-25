package awspolicy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/cidrset"
)

// restrictingConditionKeys are the condition keys that pin an open-ended
// principal set (Principal "*", or a NotPrincipal) to a known network,
// organization, account or caller — the keys AWS's own public-policy
// evaluation treats as making a grant non-public — plus the service keys
// with the same effect: kms:CallerAccount (the caller's account),
// elasticfilesystem:AccessedViaMountTarget (the request must arrive through
// a mount target inside the VPC) and sns:Endpoint (a subscription can
// deliver only to the named endpoint). Lowercased.
//
// Deliberately absent are keys whose value the caller chooses or can satisfy
// from any account: sts:ExternalId (a shared string AWS documents as not a
// secret; it stops a confused deputy only when the Principal already names
// the trusted account), aws:MultiFactorAuthPresent (an attacker's own user can
// have MFA), aws:SecureTransport and aws:UserAgent (transport and client
// shape), aws:PrincipalTag/ and aws:RequestTag/ (tags the caller sets on its
// own principal or session), aws:username (a name any account can create),
// and the keys that scope the request without naming the caller or the
// destination (sns:Protocol, kms:ViaService, aws:CalledVia,
// aws:PrincipalIsAWSService, which admits any account's service principals).
var restrictingConditionKeys = map[string]bool{
	"aws:sourceip": true, "aws:vpcsourceip": true, "aws:sourcevpc": true, "aws:sourcevpce": true,
	"aws:principalorgid": true, "aws:principalorgpaths": true, "aws:principalaccount": true,
	"aws:principalarn": true, "aws:userid": true, "aws:principalservicename": true,
	"aws:sourceaccount": true, "aws:sourcearn": true, "aws:sourceowner": true,
	"aws:sourceorgid": true, "aws:sourceorgpaths": true,
	"s3:dataaccesspointarn": true, "s3:dataaccesspointaccount": true,
	"kms:calleraccount": true, "elasticfilesystem:accessedviamounttarget": true,
	"sns:endpoint": true,
}

// matchingConditionOperators are the operators under which a restricting key
// admits only callers whose value matches, lowercased and without a
// ForAnyValue: qualifier. Every other form lets a caller through who matches
// nothing: a negated operator (StringNotEquals aws:PrincipalOrgID admits
// everyone outside the organization), an ...IfExists variant or ForAllValues:
// (both pass when the request carries no such key, as an anonymous request
// does not), and Null.
var matchingConditionOperators = map[string]bool{
	"stringequals": true, "stringequalsignorecase": true, "stringlike": true,
	"arnequals": true, "arnlike": true, "ipaddress": true, "bool": true,
}

// negatedConditionOperators maps each negated operator, lowercased and
// without its IfExists suffix, to the matching operator it negates.
var negatedConditionOperators = map[string]string{
	"stringnotequals": "stringequals", "stringnotequalsignorecase": "stringequalsignorecase",
	"stringnotlike": "stringlike", "arnnotequals": "arnequals", "arnnotlike": "arnlike",
	"notipaddress": "ipaddress",
}

// isMatchingOperator reports whether a condition operator admits only
// requests whose value matches one the policy lists (StringEquals,
// StringLike, …, optionally ForAnyValue:), as opposed to a negated,
// ...IfExists, ForAllValues: or Null form, each of which also admits a
// request that matches nothing listed.
func isMatchingOperator(op string) bool {
	return matchingConditionOperators[strings.TrimPrefix(strings.ToLower(op), "foranyvalue:")]
}

// PresentKeyOperator classifies an operator applied to a single-valued key
// every request carries, such as an OIDC token's sub. On such a key the
// ...IfExists suffix and a ForAnyValue:/ForAllValues: qualifier change
// nothing, so StringLikeIfExists admits exactly what StringLike admits.
// matching is true for an operator that admits only the listed values,
// negated for one that admits every value but them; both are false for any
// other operator (Null, numeric, date).
func PresentKeyOperator(op string) (matching, negated bool) {
	l := strings.ToLower(op)
	l = strings.TrimPrefix(strings.TrimPrefix(l, "foranyvalue:"), "forallvalues:")
	l = strings.TrimSuffix(l, "ifexists")
	return matchingConditionOperators[l], negatedConditionOperators[l] != ""
}

// RestrictsCaller reports whether an Allow's Condition pins the caller: it
// tests a restricting key under a matching operator — with ranges short of
// the whole internet for a source-IP key, like patterns that keep the value's
// owner literal (likePins), and true for a boolean one. A condition on anything else (TLS,
// MFA, an ExternalId, a tag) still admits a caller from any account.
// Unparseable reads as restricting, for the reason HasCondition gives.
func RestrictsCaller(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var cond map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &cond) != nil {
		return true
	}
	for op, kv := range cond {
		if !isMatchingOperator(op) {
			continue
		}
		op = strings.TrimPrefix(strings.ToLower(op), "foranyvalue:")
		for k, v := range kv {
			if pinsCaller(op, strings.ToLower(k), conditionValues(v)) {
				return true
			}
		}
	}
	return false
}

// ConfiningKeys returns the restricting keys a Deny's Condition tests under a
// negated operator. Bare negated comparisons also match an absent key, so both
// StringNotEquals and StringNotEqualsIfExists can confine callers to an org.
// Every predicate must confine: Deny(outside-org AND outside-network) leaves the
// union of the named organization and network, while adding insecure-transport
// admits anyone using TLS. Network exemptions are unioned across predicates;
// complementary halves of the internet do not confine. ForAnyValue does not
// match an absent/empty set and earns no credit.
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
func ConfiningKeys(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var cond map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &cond) != nil {
		return nil
	}
	var keys []string
	var networks []string
	for op, kv := range cond {
		l := strings.ToLower(op)
		l = strings.TrimPrefix(l, "forallvalues:")
		matching := negatedConditionOperators[strings.TrimSuffix(l, "ifexists")]
		if matching == "" || len(kv) == 0 {
			return nil
		}
		for k, v := range kv {
			values := conditionValues(v)
			if len(values) == 0 || !pinsCaller(matching, strings.ToLower(k), values) {
				return nil
			}
			if strings.EqualFold(k, "aws:SourceIp") || strings.EqualFold(k, "aws:VpcSourceIp") {
				networks = append(networks, values...)
			}
			keys = append(keys, k)
		}
	}
	if cidrset.CoversWorld(networks) {
		return nil
	}
	slices.Sort(keys)
	return keys
}

// pinsCaller reports whether a (lowercased) key tested under a matching
// operator admits only callers whose value matches something narrower than
// everyone. Policy variables depend on request context and cannot prove a fixed
// owner here. ArnEquals has the same wildcard semantics as ArnLike.
func pinsCaller(op, key string, vals []string) bool {
	switch {
	case !restrictingConditionKeys[key]:
		return false
	case slices.ContainsFunc(vals, func(v string) bool { return strings.Contains(v, "${") }):
		return false
	case (key == "aws:sourceip" || key == "aws:vpcsourceip") && cidrset.CoversWorld(vals):
		return false
	case (op == "stringlike" || op == "arnlike" || op == "arnequals") && slices.ContainsFunc(vals, func(v string) bool { return !likePins(key, v) }):
		return false
	case op == "bool" && !conditionIsTrue(vals):
		return false
	}
	return true
}

// likePins reports whether a like pattern for a restricting key still names
// one owner: an account, organization, principal or endpoint host that the
// caller cannot create for itself. A wildcard is allowed only after that
// owner: in an ARN's resource part once its account field is literal (or
// anywhere but the bucket name in an S3 bucket ARN), in an
// organization path below a literal organization ID, in an aws:userid after a
// literal unique ID, and in an SNS endpoint past a literal host. Anywhere else
// — arn:aws:iam::*:role/deploy (any account can create that role), o-*, a
// wildcard VPC or account ID — it admits callers from accounts it does not
// name.
func likePins(key, v string) bool {
	if !strings.ContainsAny(v, "*?") {
		return true
	}
	literal := func(s string) bool { return s != "" && !strings.ContainsAny(s, "*?") }
	switch key {
	case "aws:principalarn", "aws:sourcearn", "s3:dataaccesspointarn":
		f := strings.SplitN(v, ":", 6)
		if len(f) != 6 {
			return false
		}
		// A bucket ARN carries no region or account (arn:aws:s3:::name), and
		// bucket names are global, so a literal bucket pins one owner however
		// the empty fields are written (arn:aws:s3:*:*:name, as AWS's own
		// event-notification examples write it).
		if f[2] == "s3" && literal(f[5]) && !strings.Contains(f[5], "/") {
			return true
		}
		return literal(f[4])
	case "aws:principalorgpaths", "aws:sourceorgpaths":
		org, _, _ := strings.Cut(v, "/")
		return literal(org)
	case "aws:userid":
		id, _, ok := strings.Cut(v, ":")
		return ok && literal(id)
	case "sns:endpoint":
		rest := v
		if _, after, ok := strings.Cut(v, "://"); ok {
			rest = after
		} else if _, after, ok := strings.Cut(v, "@"); ok {
			rest = after
		}
		host, _, _ := strings.Cut(rest, "/")
		return literal(host)
	}
	return false
}

// conditionValues returns a condition key's value or values as strings,
// accepting JSON booleans and numbers as AWS does.
func conditionValues(raw json.RawMessage) []string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		list = []any{v}
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, fmt.Sprint(e))
	}
	return out
}

// conditionIsTrue reports whether a boolean condition's values are exactly true.
func conditionIsTrue(vals []string) bool {
	return len(vals) == 1 && strings.EqualFold(vals[0], "true")
}

// HasCondition reports whether a statement's Condition carries any operator,
// i.e. whether some requests can fall outside the statement. It is the test
// for a Deny (a conditioned Deny cannot be relied on to take a grant back);
// whether a condition keeps an Allow from being public is RestrictsCaller's
// question.
//
// `len(raw) > 0` is not the same question: a policy carrying `"Condition": {}` —
// an empty object, which restricts nothing — has a non-empty raw JSON value.
// Unmarshal and require at least one operator.
func HasCondition(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var cond map[string]json.RawMessage
	if json.Unmarshal(raw, &cond) != nil {
		// Unparseable: treat as restricting rather than assume the resource is open,
		// so a malformed document cannot manufacture a critical finding.
		return true
	}
	return len(cond) > 0
}
