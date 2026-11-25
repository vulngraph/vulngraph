package aws

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// kmsDecryptActions are the actions FSBP KMS.1/KMS.2 block on all keys: either
// one lets the holder read any data encrypted under any key in the account.
var kmsDecryptActions = []string{"kms:decrypt", "kms:reencryptfrom"}

// grantFacts is what one identity-policy document grants, for the policy-level
// checks (FSBP IAM.1, IAM.21, KMS.1/KMS.2).
type grantFacts struct {
	fullAdmin        bool     // an Allow of Action "*" on Resource "*"
	serviceWildcards []string // "service:*" actions an Allow grants, sorted, lowercased
	kmsDecryptAll    bool     // an Allow covering kms:Decrypt/ReEncryptFrom on Resource "*"
}

type identityStatement struct {
	Effect   string          `json:"Effect"`
	Action   json.RawMessage `json:"Action"`
	Resource json.RawMessage `json:"Resource"`
}

// identityGrantFacts evaluates a policy document. ok is false when it does not
// parse, so the caller writes nothing rather than an unread "grants nothing".
//
// NotAction statements are skipped: their reach is the complement of a list,
// and reading them as Action "*" would invent admin grants. A NotAction admin
// grant still shows up in the principal's effective-permission `admin` verdict.
func identityGrantFacts(doc string) (grantFacts, bool) {
	var p struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if doc == "" || json.Unmarshal([]byte(doc), &p) != nil || len(p.Statement) == 0 {
		return grantFacts{}, false
	}
	var stmts []identityStatement
	if json.Unmarshal(p.Statement, &stmts) != nil {
		var one identityStatement
		if json.Unmarshal(p.Statement, &one) != nil {
			return grantFacts{}, false
		}
		stmts = []identityStatement{one}
	}
	var f grantFacts
	for _, s := range stmts {
		if !strings.EqualFold(s.Effect, "Allow") || len(s.Action) == 0 {
			continue
		}
		actions := resourcePolicyActionPatterns(s.Action)
		// "*:*" is the service-qualified spelling of every action; read it as
		// "*" so it neither hides a full-admin grant nor counts as a service.
		for i, a := range actions {
			if a == "*:*" {
				actions[i] = "*"
			}
		}
		allResources := slices.Contains(jsonStrings(s.Resource), "*")
		if allResources && slices.Contains(actions, "*") {
			f.fullAdmin = true
		}
		for _, a := range actions {
			if svc, ok := strings.CutSuffix(a, ":*"); ok && svc != "" && !strings.Contains(svc, "*") && !slices.Contains(f.serviceWildcards, a) {
				f.serviceWildcards = append(f.serviceWildcards, a)
			}
		}
		if allResources && slices.ContainsFunc(kmsDecryptActions, func(k string) bool {
			return slices.ContainsFunc(actions, func(p string) bool { return resourcePolicyActionPatternCovers(p, k) })
		}) {
			f.kmsDecryptAll = true
		}
	}
	slices.Sort(f.serviceWildcards)
	return f, true
}

// jsonStrings reads a string-or-array-of-strings policy field.
func jsonStrings(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

// isAWSManagedPolicyARN reports whether a policy ARN is an AWS-managed policy
// (arn:<partition>:iam::aws:policy/...). Those share one ARN across every
// account, so per-policy findings are only raised on customer-managed ones.
func isAWSManagedPolicyARN(arn string) bool {
	return strings.Contains(arn, ":iam::aws:policy/")
}

// policyGrantMetadata is the iam_policy keys a read document supports.
func policyGrantMetadata(f grantFacts) map[string]string {
	return map[string]string{
		"full_admin":                strconv.FormatBool(f.fullAdmin),
		"service_wildcard_actions":  strings.Join(f.serviceWildcards, ","),
		"kms_decrypt_all_resources": strconv.FormatBool(f.kmsDecryptAll),
	}
}

// dedupePolicyAssets collapses the iam_policy asset each attachment emitted to
// one per ARN, keeping the copy with the most metadata: a document read that
// failed for one principal and succeeded for a later one must not leave two
// rows that disagree about what the policy grants.
func dedupePolicyAssets(assets []asset.Asset) []asset.Asset {
	best := map[string]int{}
	out := assets[:0]
	for _, a := range assets {
		if a.Type != "iam_policy" {
			out = append(out, a)
			continue
		}
		if i, ok := best[a.ID]; ok {
			if len(a.Metadata) > len(out[i].Metadata) {
				out[i] = a
			}
			continue
		}
		best[a.ID] = len(out)
		out = append(out, a)
	}
	return out
}
