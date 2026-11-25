package asset

import (
	"sort"
	"strings"
	"unicode"
)

// Environment is the deployment stage an asset belongs to. Unknown is a real
// state, not a default: most estates tag only part of their resources, and an
// untagged asset is not evidence of anything.
type Environment string

const (
	EnvProd    Environment = "prod"
	EnvStaging Environment = "staging"
	EnvDev     Environment = "dev"
	EnvUnknown Environment = "unknown"
)

// Known reports whether the environment was actually determined.
func (e Environment) Known() bool {
	return e == EnvProd || e == EnvStaging || e == EnvDev
}

// TreatAsProd is the fail-closed reading for anything that guards a change to
// the resource: only an asset positively classified non-production escapes
// production caution. Unknown — and the zero value — are treated as prod.
func (e Environment) TreatAsProd() bool {
	return e != EnvStaging && e != EnvDev
}

// EnvClassification is an environment plus the evidence it came from, so an
// operator can see why an asset was called production.
type EnvClassification struct {
	Env Environment
	// Source names the evidence: "tag:<key>", "metadata:<key>", "namespace",
	// "account_id". Empty when Env is EnvUnknown and nothing matched; for a
	// conflict it names the disagreeing tier, e.g. "conflict:tag".
	Source string
}

// envKeyNames are the tag/metadata key names (last segment, lowercased) that
// carry an environment. Matched on the last segment so namespaced conventions
// (example.com/env, app.kubernetes.io/environment) work without org-specific keys.
var envKeyNames = map[string]bool{
	"env": true, "environment": true, "stage": true, "tier": true,
	"deployment-environment": true, "deployment_environment": true,
}

// envValues maps a normalised value (or a single token of one) to its
// environment. "test"/"qa"/"uat" are pre-production, so staging.
var envValues = map[string]Environment{
	"prod": EnvProd, "production": EnvProd, "prd": EnvProd, "live": EnvProd,
	"staging": EnvStaging, "stage": EnvStaging, "stg": EnvStaging, "preprod": EnvStaging,
	"preproduction": EnvStaging, "uat": EnvStaging, "qa": EnvStaging, "test": EnvStaging,
	"testing": EnvStaging, "dev": EnvDev, "development": EnvDev, "develop": EnvDev,
	"sandbox": EnvDev, "sbx": EnvDev, "local": EnvDev, "lab": EnvDev,
}

// negationTokens make a value say what an environment is NOT ("non-prod"),
// which names no single stage.
var negationTokens = map[string]bool{"non": true, "not": true, "nonprod": true, "nonproduction": true}

// ClassifyEnvironment is the single environment classifier. Sources, strongest
// first — the first tier with any match decides:
//
//  1. tags whose key names an environment (env, environment, stage, tier, …)
//  2. metadata under the same key names
//  3. the Kubernetes namespace (tag or metadata "namespace")
//  4. the account id, when it is a name rather than a number (GCP project ids
//     such as "acme-prod-1"; AWS account ids are numeric and say nothing)
//
// Values within a tier that disagree (env=prod, stage=dev) yield EnvUnknown:
// neither answer is trustworthy, and Unknown already fails closed wherever it
// matters.
func ClassifyEnvironment(a Asset) EnvClassification {
	if c, ok := classifyKeyed(a.Tags, "tag"); ok {
		return c
	}
	if c, ok := classifyKeyed(a.Metadata, "metadata"); ok {
		return c
	}
	for _, ns := range []string{a.Tags["namespace"], a.Metadata["namespace"]} {
		if env := classifyValue(ns); env != "" {
			return EnvClassification{Env: env, Source: "namespace"}
		}
	}
	if hasLetter(a.AccountID) {
		if env := classifyValue(a.AccountID); env != "" {
			return EnvClassification{Env: env, Source: "account_id"}
		}
	}
	return EnvClassification{Env: EnvUnknown}
}

// classifyKeyed classifies one key/value tier. ok is false when no
// environment-named key produced a value, so the next tier is consulted.
func classifyKeyed(kv map[string]string, tier string) (EnvClassification, bool) {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys) // stable Source when several keys agree
	var found Environment
	source := ""
	for _, k := range keys {
		if !isEnvKey(k) {
			continue
		}
		env := classifyValue(kv[k])
		switch {
		case env == "":
			continue
		case found == "":
			found, source = env, tier+":"+k
		case env != found:
			return EnvClassification{Env: EnvUnknown, Source: "conflict:" + tier}, true
		}
	}
	if found == "" {
		return EnvClassification{}, false
	}
	return EnvClassification{Env: found, Source: source}, true
}

// isEnvKey matches the key's last segment (after '/', ':' or '.') against
// envKeyNames, plus segments ending in "-env"/"_env"/"-environment"/"_environment".
func isEnvKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if i := strings.LastIndexAny(k, "/:."); i >= 0 {
		k = k[i+1:]
	}
	if envKeyNames[k] {
		return true
	}
	for _, suffix := range []string{"-env", "_env", "-environment", "_environment"} {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}

// classifyValue maps a value to an environment, or "" when it names none. The
// whole value is tried with separators removed ("pre-prod" → preprod), then each
// token; tokens that disagree, or a negation ("non-prod"), name nothing.
func classifyValue(v string) Environment {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	tokens := strings.FieldsFunc(v, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	joined := strings.Join(tokens, "")
	if negationTokens[joined] {
		return ""
	}
	if env, ok := envValues[joined]; ok {
		return env
	}
	var found Environment
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if negationTokens[t] {
			return ""
		}
		// "pre" + "prod" split by a separator inside a longer value ("pre-prod-eu").
		if t == "pre" && i+1 < len(tokens) && envValues[tokens[i+1]] == EnvProd {
			t = "preprod"
			i++
		}
		env, ok := envValues[t]
		if !ok {
			continue
		}
		if found != "" && env != found {
			return ""
		}
		found = env
	}
	return found
}

func hasLetter(s string) bool {
	return strings.IndexFunc(s, unicode.IsLetter) >= 0
}
