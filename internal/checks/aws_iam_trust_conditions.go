package checks

// aws_iam_trust_conditions.go — reads a trust statement's Condition for the
// role-trust checks: which keys it pins, and whether the pin is something a
// caller in another account could not satisfy.

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// iamCondition maps an operator, as written, to its keys (lowercased) and the
// raw values written under each. An operator whose block is not an object is
// kept with no keys: it still counts as a condition, it just pins nothing.
type iamCondition map[string]map[string][]json.RawMessage

// parseCondition decodes a statement's Condition. An absent, null or empty one
// yields an empty condition; ok is false when it is not an object.
func parseCondition(s iamStatement) (iamCondition, bool) {
	cond := iamCondition{}
	if len(s["Condition"]) == 0 {
		return cond, true
	}
	var ops map[string]json.RawMessage
	if json.Unmarshal(s["Condition"], &ops) != nil {
		return nil, false
	}
	for op, raw := range ops {
		block := map[string][]json.RawMessage{}
		var keys map[string]json.RawMessage
		if json.Unmarshal(raw, &keys) == nil {
			for k, v := range keys {
				block[strings.ToLower(k)] = append(block[strings.ToLower(k)], v)
			}
		}
		cond[op] = block
	}
	return cond, true
}

// scalarOrList is how the confused-deputy condition test reads a value: only a
// string or a list counts as one that names something.
func scalarOrList(raws []json.RawMessage) bool {
	for _, r := range raws {
		var str string
		var list []any
		if json.Unmarshal(r, &str) == nil || json.Unmarshal(r, &list) == nil {
			return true
		}
	}
	return false
}

// values flattens the raw values written under one key into a list of decoded
// JSON values, one level of list expanded.
func values(raws []json.RawMessage) []any {
	var out []any
	for _, r := range raws {
		var v any
		if json.Unmarshal(r, &v) != nil {
			continue
		}
		if list, ok := v.([]any); ok {
			out = append(out, list...)
		} else {
			out = append(out, v)
		}
	}
	return out
}

var (
	sourceKeys = []string{
		"aws:sourceaccount", "aws:sourceowner", "aws:sourcearn", "aws:principalaccount",
		"aws:principalarn", "aws:principalorgid", "aws:principalorgpaths", "aws:resourceaccount",
		"aws:sourcevpc", "aws:sourcevpce", "aws:sourceorgid", "aws:sourceorgpaths", "aws:userid",
		"aws:username", "aws:calledvia", "aws:calledviafirst", "aws:calledvialast",
		"kms:calleraccount", "kms:viaservice", "s3:resourceaccount", "lambda:eventsourcetoken",
	}
	arnSourceKeys = []string{"aws:sourcearn", "aws:principalarn"}

	orgIDPattern   = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	orgPathPattern = regexp.MustCompile(`^o-[a-z0-9]{10,32}/`)
)

// conditionConfinesSource reports whether a Condition names a source: a
// string-comparison operator on an account, ARN, principal, organisation or
// network key, a literal organisation under an organisation key, or a
// source-address range made only of private addresses. The value is not
// inspected (a wildcard account still counts), which is what separates this
// from pinsSource below.
func conditionConfinesSource(cond iamCondition) bool {
	for _, op := range []string{"StringEquals", "StringLike"} {
		for _, k := range sourceKeys {
			if scalarOrList(cond[op][k]) {
				return true
			}
		}
	}
	for _, op := range []string{"ArnLike", "ArnEquals"} {
		for _, k := range arnSourceKeys {
			if scalarOrList(cond[op][k]) {
				return true
			}
		}
	}
	return namesOneOrganization(cond) || fromPrivateAddresses(cond)
}

func namesOneOrganization(cond iamCondition) bool {
	for _, op := range []string{"StringEquals", "StringLike", "ForAnyValue:StringEquals", "ForAnyValue:StringLike"} {
		for _, key := range []string{"aws:principalorgid", "aws:principalorgpaths"} {
			vals := values(cond[op][key])
			if len(vals) == 0 {
				continue
			}
			if slices.ContainsFunc(vals, func(v any) bool { return !namesOrganization(key, v) }) {
				continue
			}
			return true
		}
	}
	return false
}

func namesOrganization(key string, v any) bool {
	str, ok := v.(string)
	if !ok {
		return false
	}
	if key == "aws:principalorgpaths" {
		return orgPathPattern.MatchString(str)
	}
	return !strings.Contains(str, "*")
}

// fromPrivateAddresses is true when an IpAddress aws:SourceIp condition lists
// only private, loopback or link-local addresses; an unparseable entry or a
// match-everything range makes it false.
func fromPrivateAddresses(cond iamCondition) bool {
	vals := values(cond["IpAddress"]["aws:sourceip"])
	if len(vals) == 0 {
		return false
	}
	for _, v := range vals {
		str, ok := v.(string)
		if !ok || str == "*" || str == "0.0.0.0/0" {
			return false
		}
		var addr netip.Addr
		if prefix, err := netip.ParsePrefix(str); err == nil {
			addr = prefix.Masked().Addr()
		} else if a, err := netip.ParseAddr(str); err == nil {
			addr = a
		} else {
			return false
		}
		if !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
			return false
		}
	}
	return true
}

// ── pinning the source to a literal ──────────────────────────────────────────

// comparingOperators are the operators that compare a request value against
// the statement's own, lowercased, with the set qualifier and IfExists forms.
var comparingOperators = func() map[string]bool {
	out := map[string]bool{}
	for _, q := range []string{"", "foranyvalue:", "forallvalues:"} {
		for _, suffix := range []string{"", "ifexists"} {
			for _, op := range []string{"stringequals", "stringequalsignorecase", "stringlike", "arnequals", "arnlike"} {
				out[q+op+suffix] = true
			}
		}
	}
	return out
}()

var accountIDPattern = regexp.MustCompile(`^\d{12}$`)

func isAccountID(v any) bool {
	str, ok := v.(string)
	return ok && accountIDPattern.MatchString(str)
}

func arnCarriesAccount(v any) bool {
	str, ok := v.(string)
	if !ok {
		return false
	}
	fields := strings.Split(str, ":")
	return len(fields) >= 5 && isAccountID(fields[4])
}

// nullGuardedKeys are the keys a `Null: "false"` test forces to be present.
// Every value must be "false": IAM ORs the values of one operator, so a list
// holding "true" as well binds nothing.
func nullGuardedKeys(cond iamCondition) map[string]bool {
	guarded := map[string]bool{}
	for op, block := range cond {
		if strings.ToLower(op) != "null" {
			continue
		}
		for key, raws := range block {
			vals := values(raws)
			if len(vals) > 0 && !slices.ContainsFunc(vals, func(v any) bool {
				str, ok := v.(string)
				return !ok || strings.ToLower(strings.TrimSpace(str)) != "false"
			}) {
				guarded[key] = true
			}
		}
	}
	return guarded
}

// pinsEvery reports whether some one operator holds key to values that all
// qualify. Operators are ANDed by IAM, so one pinned operator confines the
// request whatever the others say. A set operator or IfExists form is vacuous
// when the key is absent, so it counts only beside a Null "false" guard.
func pinsEvery(cond iamCondition, key string, qualifies func(any) bool) bool {
	guarded := nullGuardedKeys(cond)
	for op, block := range cond {
		lowered := strings.ToLower(op)
		if !comparingOperators[lowered] {
			continue
		}
		vals := values(block[key])
		if len(vals) == 0 {
			continue
		}
		vacuous := strings.HasPrefix(lowered, "forallvalues:") || strings.HasSuffix(lowered, "ifexists")
		if vacuous && !guarded[key] {
			continue
		}
		if !slices.ContainsFunc(vals, func(v any) bool { return !qualifies(v) }) {
			return true
		}
	}
	return false
}

func pinsAccountOrARN(cond iamCondition) bool {
	return pinsEvery(cond, "aws:sourceaccount", isAccountID) || pinsEvery(cond, "aws:sourcearn", arnCarriesAccount)
}

func pinsOrganization(cond iamCondition) bool {
	return pinsEvery(cond, "aws:sourceorgid", func(v any) bool {
		str, ok := v.(string)
		return ok && orgIDPattern.MatchString(str)
	}) || pinsEvery(cond, "aws:sourceorgpaths", func(v any) bool {
		str, ok := v.(string)
		return ok && orgPathPattern.MatchString(str)
	})
}

func preventsConfusedDeputy(cond iamCondition) bool {
	return pinsAccountOrARN(cond) || pinsOrganization(cond)
}

// hasEnforcedCondition reports whether the statement is gated at all: some
// operator that is neither negated nor IfExists carries a key. A Null presence
// test counts, since it does gate access.
func hasEnforcedCondition(cond iamCondition) bool {
	for op, block := range cond {
		lowered := strings.ToLower(op)
		if strings.Contains(lowered, "not") || strings.HasSuffix(lowered, "ifexists") {
			continue
		}
		if len(block) > 0 {
			return true
		}
	}
	return false
}
