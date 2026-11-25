package iac

import (
	"regexp"
	"strings"
)

// DeclaredIdentity is one cloud identity referenced verbatim in a repo's text.
//
// This is a generic alternative to a parser per IaC tool: Terraform, CDK,
// CloudFormation, Helm values, k8s manifests, IRSA/Workload-Identity
// annotations, raw IAM policy JSON, deploy scripts and Makefiles all name the
// same identities the same way — a role ARN, a service-account email, a GitHub
// OIDC subject — so harvesting needs no per-repo configuration or knowledge of
// the tool that wrote them; the join downstream is exact string equality
// against a live asset ID.
type DeclaredIdentity struct {
	// Kind is the live asset type this identity joins to.
	Kind string
	// Value is the canonical join key: exactly the live asset's ID.
	Value string
	// Raw is the text as written, kept for evidence.
	Raw string
}

// Identity kinds. These are live asset types, not new concepts.
const (
	IdentityIamRole    = "iam_role"
	IdentityIamUser    = "iam_user"
	IdentityGCPSA      = "gcp_service_account"
	IdentityGitHubOIDC = "github_oidc_sub"
)

var (
	// IAM role/user ARNs. The partition is matched loosely (aws, aws-cn,
	// aws-us-gov). The name charset is AWS's documented one for role/user names
	// plus "/" for paths, so a path-qualified SSO role
	// (…:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_Admin_abc)
	// is captured whole — that IS its ARN.
	iamRoleARNRe = regexp.MustCompile(`arn:aws[a-z-]*:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+`)
	iamUserARNRe = regexp.MustCompile(`arn:aws[a-z-]*:iam::\d{12}:user/[A-Za-z0-9+=,.@_/-]+`)

	// GCP service-account emails, covering user-managed
	// (<name>@<project>.iam.gserviceaccount.com) as well as the default compute
	// (<num>-compute@developer.gserviceaccount.com) and App Engine
	// (<project>@appspot.gserviceaccount.com) forms.
	gcpSARe = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._%+-]*@[a-z0-9.-]*gserviceaccount\.com`)

	// GitHub Actions OIDC subject, as written in a trust policy's
	// token.actions.githubusercontent.com:sub condition. The org/repo portion is
	// the join key; the ref/environment suffix is not.
	ghOIDCSubRe = regexp.MustCompile(`repo:([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)`)
)

// A non-literal identity is one an unresolved template or a wildcard runs
// into: a Terraform interpolation ("role/${var.env}-app"), a CloudFormation
// !Sub ("${AWS::AccountId}"), a Helm template ("{{ .Values.env }}"), or a
// policy-resource wildcard ("role/app-*"). Those name no single identity, so
// joining them would match nothing or the wrong thing. None of the identity
// regexes match "$", "{", "}" or "*", so such a token is cut short rather than
// rejected: "role/app-${env}" would harvest as "role/app". cutMidToken catches
// that from the characters around the match. Braces and asterisks that only
// delimit a whole literal are not templates: a YAML flow mapping
// ("{AWS: arn:...}") and Markdown bold ("**arn:...**") still harvest.

// continuationChars are the identity characters a match cannot start on; one
// right before a match means the regex began mid-token.
const continuationChars = "._%+-"

// cutMidToken reports whether the match text[start:end] is part of a larger,
// templated or truncated token rather than a whole literal identity.
func cutMidToken(text string, start, end int) bool {
	if start > 0 {
		switch prev := text[start-1]; {
		case strings.IndexByte(continuationChars, prev) >= 0:
			return true
		case prev == '}': // the end of "${...}" or "{{ ... }}"
			return true
		case prev == '*' && (start < 2 || text[start-2] != '*'): // a wildcard, not "**" bold
			return true
		}
	}
	if end < len(text) {
		rest := text[end:]
		switch {
		case strings.HasPrefix(rest, "${"), strings.HasPrefix(rest, "{{"):
			return true
		case rest[0] == '*' && !strings.HasPrefix(rest, "**"):
			return true
		}
	}
	return false
}

// HarvestIdentities extracts every concrete cloud identity referenced in src,
// deduplicated, in first-seen order. Content type is irrelevant: it reads .tf,
// .json, .yaml, .ts, .sh and prose the same way, because the identifiers are the
// same in all of them.
func HarvestIdentities(src []byte) []DeclaredIdentity {
	text := string(src)
	var out []DeclaredIdentity
	seen := map[string]bool{}

	add := func(kind, value, raw string) {
		if value == "" || seen[kind+"|"+value] {
			return
		}
		seen[kind+"|"+value] = true
		out = append(out, DeclaredIdentity{Kind: kind, Value: value, Raw: raw})
	}

	for _, ix := range iamRoleARNRe.FindAllStringIndex(text, -1) {
		if arn, ok := literalARN(text[ix[0]:ix[1]]); ok && !cutMidToken(text, ix[0], ix[1]) {
			add(IdentityIamRole, arn, arn)
		}
	}
	for _, ix := range iamUserARNRe.FindAllStringIndex(text, -1) {
		if arn, ok := literalARN(text[ix[0]:ix[1]]); ok && !cutMidToken(text, ix[0], ix[1]) {
			add(IdentityIamUser, arn, arn)
		}
	}
	for _, ix := range gcpSARe.FindAllStringIndex(text, -1) {
		email := strings.Trim(text[ix[0]:ix[1]], ".")
		if cutMidToken(text, ix[0], ix[1]) {
			continue
		}
		// gcp_service_account asset IDs are "serviceAccount:<email>"
		// (internal/collect/gcp/iam.go), which is what the join compares against.
		add(IdentityGCPSA, "serviceAccount:"+email, email)
	}
	for _, ix := range ghOIDCSubRe.FindAllStringSubmatchIndex(text, -1) {
		if repo := text[ix[2]:ix[3]]; !cutMidToken(text, ix[0], ix[1]) {
			add(IdentityGitHubOIDC, repo, text[ix[0]:ix[1]])
		}
	}
	return out
}

// literalARN trims trailing punctuation an ARN can pick up from surrounding
// syntax (a quote or comma is already excluded by the charset, but a trailing
// "/" or "-" is not).
func literalARN(arn string) (string, bool) {
	arn = strings.TrimRight(arn, "/-")
	// A path with no name after it ("…:role/") identifies nothing.
	if strings.HasSuffix(arn, ":role") || strings.HasSuffix(arn, ":user") {
		return "", false
	}
	return arn, true
}
