package gcp

import (
	"slices"
	"strings"
)

// The plaintext-secret heuristic for function and service environment
// variables (CIS GCP 1.18). It mirrors the ECS task-definition heuristic
// (internal/collect/aws/ecs_taskdef.go): a secret-suggesting name holding a
// real literal. Only variable NAMES leave this file — values never do.

// secretEnvParts mark a variable name that suggests a secret value.
var secretEnvParts = []string{"password", "passwd", "secret", "token", "apikey", "api_key", "private_key", "credential"}

// referenceEnvSuffixes mark a variable that names or locates a secret rather
// than holding one (DB_PASSWORD_SECRET_NAME, TOKEN_FILE).
var referenceEnvSuffixes = []string{"_name", "_id", "_path", "_file", "_url", "_region", "_key_id", "_version"}

// plaintextSecretVars returns the sorted names of variables that look like a
// credential stored in plaintext.
func plaintextSecretVars(env map[string]string) []string {
	var out []string
	for name, value := range env {
		if secretVarName(name) && len(value) > 8 && !secretRefValue(value) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func secretVarName(name string) bool {
	lower := strings.ToLower(name)
	for _, suf := range referenceEnvSuffixes {
		if strings.HasSuffix(lower, suf) {
			return false
		}
	}
	return slices.ContainsFunc(secretEnvParts, func(p string) bool { return strings.Contains(lower, p) })
}

// secretRefValue reports a value that points at a secret rather than being
// one: a Secret Manager resource name, a template placeholder, a file path,
// or a URL without credentials in its userinfo.
func secretRefValue(v string) bool {
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		host, _, _ := strings.Cut(strings.SplitN(v, "://", 2)[1], "/")
		return !strings.Contains(host, "@")
	}
	return strings.HasPrefix(v, "projects/") && strings.Contains(v, "/secrets/") ||
		strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$(") || strings.HasPrefix(v, "{{") ||
		strings.HasPrefix(v, "/") || v == "CHANGEME" || v == "REPLACE_ME"
}
