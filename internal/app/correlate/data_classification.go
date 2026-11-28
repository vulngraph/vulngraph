package correlate

import (
	"iter"
	"slices"
	"sort"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// dataClassSentinelPrefix is the stable prefix for synthetic DataClass node IDs.
// DataClass nodes are not collected — they are synthetic graph nodes created by
// this correlator to anchor ContainsData edges.
const dataClassSentinelPrefix = "dataclass:"

// DataClass sentinel IDs — stable, never collected from cloud providers.
const (
	DataClassPII         = dataClassSentinelPrefix + "pii"
	DataClassFinancial   = dataClassSentinelPrefix + "financial"
	DataClassCredentials = dataClassSentinelPrefix + "credentials"
	DataClassHealth      = dataClassSentinelPrefix + "health"
	DataClassPCI         = dataClassSentinelPrefix + "pci"
	DataClassInternal    = dataClassSentinelPrefix + "internal"
)

// Classification confidence — how the class was inferred. Explicit operator tags
// are trustworthy; name patterns are a guess; the internal floor is a default.
//
// This value is PERSISTED on the ContainsData rel and surfaced by the DSPM API,
// so an operator-confirmed `data-classification: pii` tag and a bucket whose
// name merely contains the letters "pii" are distinguishable in the UI rather
// than collapsing to the same signal. The paired `source` property says WHICH
// asserted/guessed signal fired.
const (
	confidenceHigh   = "high"   // asserted: operator tag, or the resource type itself
	confidenceMedium = "medium" // guessed: resource-name pattern match
	confidenceLow    = "low"    // "internal" floor (no signal matched)
)

// EdgeContainsData links an asset to the data class it is likely to contain.
const EdgeContainsData = "contains_data"

// ── Matching rule ─────────────────────────────────────────────────────────────
//
// Only the resource NAME (plus operator tags) is matched — never the resource
// ID. A Secrets Manager entry is a credential by RESOURCE TYPE (a fact already
// carried by asset.Type and by the AccessesSecret edges), not by content
// inference, so re-asserting it from the ID (every AWS Secrets Manager ARN
// literally contains ":secret:") would be a tautology, not a classification,
// and would bury the buckets/databases a human actually has to go look inside.
// A secret whose NAME says what it holds ("db-password", "signing-keys") still
// matches by name; everything else still gets a ContainsData edge at the
// `internal` floor, so no asset leaves the DSPM graph.
//
// Patterns match on TOKEN boundaries, not raw substrings. A name is split on
// non-alphanumeric characters and a pattern matches a contiguous run of tokens
// (simple English plurals allowed). This is what stops "personalversion2" from
// being PII and "healthscore" from being medical data.
//
// A small curated set of long, domain-specific keywords is ALSO matched as a
// raw substring (unambiguousPatterns) because concatenated names are real —
// "exampleallpasswords" and "examplebilling" have no token boundary to find.
// Membership there is deliberately conservative: a keyword only qualifies if
// its letters appearing inside a longer word is not something that happens by
// accident. "password" qualifies; "personal", "cert", "health" and "pii" do
// not — those produce false positives as substrings.

// piiPatterns are name tokens that suggest PII content. Heuristic only — a bucket
// named "customer-profiles" is a strong signal; "prod-api" is not.
var piiPatterns = []string{
	"pii", "personal", "customer", "user-data", "userdata",
	"profile", "gdpr", "privacy", "dsr", "consent",
}

// financialPatterns suggest financial data.
var financialPatterns = []string{
	"payment", "billing", "invoice", "finance", "financial",
	"revenue", "stripe", "transaction", "ledger", "payroll",
}

// credentialPatterns suggest secrets/credentials.
var credentialPatterns = []string{
	"secret", "credential", "password", "passwd", "token",
	"api-key", "apikey", "private-key", "cert", "certificate", "vault",
}

// healthPatterns suggest health/medical data. Deliberately excludes the ambiguous
// short tokens "phi" (matches "graphics"), "emr" (AWS EMR / Elastic MapReduce), and
// "ehr" — they produced more infra false positives than real health-data matches.
var healthPatterns = []string{
	"healthcare", "health", "medical", "hipaa", "patient", "clinical", "pharmacy",
}

// healthExcludePatterns suppress a health name-match when the name is clearly infra,
// not medical data — "health-check"/"healthcheck" load balancers and probes are the
// dominant false positive for the broad "health" token.
//
// Substring-matched, deliberately: exclusions only ever REMOVE a guess, so the
// looser rule is the safe direction here, and "health-checker" / "healthscore"
// need it. ("healthscore" cannot reach this list via the token rule at all — it
// is a single token, so the health pattern does not fire on it either way; it
// stays listed as documentation of the false positive.)
var healthExcludePatterns = []string{
	"health-check", "healthcheck", "healthy", "healthscore",
}

// pciPatterns suggest payment-card data (PCI DSS scope).
var pciPatterns = []string{
	"pci", "cardholder", "card-data", "carddata", "pan-data", "cvv",
}

// unambiguousPatterns are the keywords safe to match as a raw substring, because
// their letters do not turn up inside unrelated infrastructure words. They exist
// so concatenated names ("exampleallpasswords", "examplebilling") are not lost to
// token matching. Every entry here is also in one of the lists above; this set
// only widens HOW it is matched, never WHICH class it maps to.
var unambiguousPatterns = map[string]bool{
	"password": true, "passwd": true, "credential": true,
	"invoice": true, "payment": true, "billing": true, "payroll": true,
	"financial": true, "revenue": true, "transaction": true, "ledger": true,
	"gdpr": true, "privacy": true,
	"medical": true, "patient": true, "clinical": true, "pharmacy": true,
	"hipaa": true, "healthcare": true, "cardholder": true,
}

// deployArtifactPatterns suppress every NAME-derived class (tags still win) when
// the name identifies a build/deploy artifact store. These buckets inherit the
// name of the stack they deploy — "demo-customer-notify-dev-serverlessdeploymentbuck-…"
// is a zip of Lambda code, not a customer database. Substring-matched:
// CloudFormation truncates the generated suffix, so there is no reliable token
// boundary.
//
// Deliberately does NOT include terraform/tfstate state buckets — those really
// do tend to contain secrets, so they stay classified.
var deployArtifactPatterns = []string{
	"serverlessdeploymentbuck", // Serverless Framework (CFN-truncated)
	"cf-templates-",            // CloudFormation console template store
	"cdk-hnb659fds-assets",     // AWS CDK bootstrap asset bucket
	"elasticbeanstalk-",        // EB application-version store
	"codepipeline-",            // CodePipeline artifact store
}

// secretStoreTypes are resource types that hold credentials BY DEFINITION — a
// Secrets Manager entry, an SSM SecureString parameter, a GCP Secret Manager
// secret. For these there is nothing to infer: the class is a property of the
// resource type, not a guess about its name — a secret named only by a UUID
// still qualifies, where a name-only rule would fall it to the `internal` floor.
//
// They carry confidence "high" and source "resource_type": asserted, not
// guessed. The DSPM summary counts them as their own population so vault
// entries cannot drown out the buckets and databases whose contents a human
// actually has to go and inspect.
var secretStoreTypes = map[string]bool{
	"secretsmanager_secret": true,
	"ssm_parameter":         true,
	"gcp_secret":            true,
}

// IsSecretStoreType reports whether an asset type is a credential store by
// definition. Exported for the DSPM summary, which counts vault entries and
// inferred data stores separately.
func IsSecretStoreType(t string) bool { return secretStoreTypes[t] }

// SecretStoreTypes returns the credential-store resource types, sorted.
func SecretStoreTypes() []string {
	out := make([]string, 0, len(secretStoreTypes))
	for t := range secretStoreTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Classification source values, stamped on the edge alongside the confidence.
const (
	sourceTag          = "tag"           // explicit operator tag
	sourceResourceType = "resource_type" // definitional: the resource type IS the class
	sourceHeuristic    = "heuristic"     // resource-name pattern match
)

// tagClassifications maps tag values to DataClass IDs.
var tagClassifications = map[string]string{
	"pii":           DataClassPII,
	"gdpr":          DataClassPII,
	"personal-data": DataClassPII,
	"financial":     DataClassFinancial,
	"credentials":   DataClassCredentials,
	"secrets":       DataClassCredentials,
	"health":        DataClassHealth,
	"hipaa":         DataClassHealth,
	"pci":           DataClassPCI,
	"pci-dss":       DataClassPCI,
}

// DataClassification heuristically classifies storage assets (S3 buckets, GCS
// buckets, databases) and emits ContainsData edges to synthetic DataClass nodes.
//
// This is a heuristic bootstrapper — it uses naming patterns and resource tags
// to estimate data sensitivity. A full DSPM would side-scan file contents.
// Even heuristic-based classification enables: "show me exposed assets that
// probably contain PII" — a query impossible without ContainsData edges.
//
// The heuristic caveat is carried in the DATA, not just in this comment: the
// `confidence` property rides on every edge and the DSPM API and UI label a
// medium-confidence class as an inference from the resource name.
type DataClassification struct{}

func (DataClassification) Name() string { return "data_classification" }

func (DataClassification) InterestedIn() []string {
	return []string{
		"s3_bucket", "gcs_bucket", "azure_blob_container",
		"rds_instance", "cloud_sql_instance", "cloudsql_instance",
		"azure_sql_server", "azure_sql_database",
		"dynamodb_table", "firestore_collection",
		"elasticache_cluster",
	}
}

func (r DataClassification) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (DataClassification) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {

		// Iterate all assets and classify storage/database types.
		for _, a := range g.storageAssets() {
			for _, c := range classifyAsset(a) {
				if !yield(asset.Edge{
					SrcID:    a.ID,
					SrcType:  a.Type,
					DstID:    c.class,
					DstType:  "data_class",
					EdgeType: EdgeContainsData,
					Properties: map[string]string{
						// origin/rule as every other correlation rule stamps them —
						// see the same note on iam_effective_permissions.
						"origin":         edgeOrigin,
						"rule":           "data_classification",
						"classification": strings.TrimPrefix(c.class, dataClassSentinelPrefix),
						"confidence":     c.confidence,
						"source":         c.source,
						"asset_name":     a.Name,
					},
				}) {
					return
				}
			}
		}
	}
}

// classification is one inferred DataClass plus how confidently it was inferred
// and which signal produced it.
type classification struct {
	class      string
	confidence string
	source     string
}

// classifyAsset returns the DataClass IDs this asset likely contains and the
// confidence of each. Explicit tags win over name patterns (higher confidence
// upgrades an already-matched class); the "internal" floor applies only when
// nothing else matched. Never returns an empty slice for a storage asset.
func classifyAsset(a asset.Asset) []classification {
	// NAME ONLY — never a.ID. See the matching-rule note above.
	name := strings.ToLower(a.Name)
	tokens := tokenize(name)
	var order []string
	conf := map[string]string{}
	src := map[string]string{}

	// add records a class at the given confidence, upgrading (never downgrading)
	// if the class was already matched by a weaker signal. The source is upgraded
	// with the confidence so the two never disagree.
	add := func(class, confidence, source string) {
		if _, ok := conf[class]; !ok {
			order = append(order, class)
		}
		if confidence == confidenceHigh || conf[class] == "" {
			conf[class] = confidence
			src[class] = source
		}
	}

	// Resource type → high confidence. A credential store is a credential store.
	if secretStoreTypes[a.Type] {
		add(DataClassCredentials, confidenceHigh, sourceResourceType)
	}

	// Name patterns → medium confidence (a guess from the resource name).
	// Suppressed entirely for build/deploy artifact stores, whose names describe
	// the stack they deploy rather than anything they hold.
	if !containsAny(name, deployArtifactPatterns) {
		if matchesAny(name, tokens, piiPatterns) {
			add(DataClassPII, confidenceMedium, sourceHeuristic)
		}
		if matchesAny(name, tokens, financialPatterns) {
			add(DataClassFinancial, confidenceMedium, sourceHeuristic)
		}
		if matchesAny(name, tokens, credentialPatterns) {
			add(DataClassCredentials, confidenceMedium, sourceHeuristic)
		}
		if matchesAny(name, tokens, healthPatterns) && !containsAny(name, healthExcludePatterns) {
			add(DataClassHealth, confidenceMedium, sourceHeuristic)
		}
		if matchesAny(name, tokens, pciPatterns) {
			add(DataClassPCI, confidenceMedium, sourceHeuristic)
		}
	}

	// Explicit operator tags → high confidence. Never suppressed: an operator who
	// tagged the bucket outranks every guess this file makes about its name.
	tagValue := strings.ToLower(
		a.Tags["data-classification"] + " " +
			a.Tags["data_classification"] + " " +
			a.Tags["sensitivity"] + " " +
			a.Tags["compliance"],
	)
	for pattern, class := range tagClassifications {
		if strings.Contains(tagValue, pattern) {
			add(class, confidenceHigh, sourceTag)
		}
	}

	// Every storage asset holds some internal data; classify as internal (low
	// confidence) when no more specific class was detected.
	if len(order) == 0 {
		add(DataClassInternal, confidenceLow, sourceHeuristic)
	}

	out := make([]classification, len(order))
	for i, class := range order {
		out[i] = classification{class: class, confidence: conf[class], source: src[class]}
	}
	return out
}

// tokenize splits a lowercased resource name into alphanumeric tokens. Any
// non-alphanumeric run is a separator, so "demo-data-privacy_v2.prod" tokenizes to
// [demo data privacy v2 prod] and "personalversion2" stays a single token.
func tokenize(name string) []string {
	return strings.FieldsFunc(name, func(r rune) bool {
		// Separator = anything outside [a-z0-9]. Written as explicit range
		// exclusions rather than a negated disjunction so it reads the same way
		// FieldsFunc uses it, and so no De Morgan rewrite rule applies.
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
}

// matchesAny reports whether any pattern matches the name. A pattern matches when
// its own tokens appear as a contiguous run in tokens (allowing a simple English
// plural on the pattern's last token), or — for the curated unambiguousPatterns
// set only — when it appears anywhere in name as a raw substring.
func matchesAny(name string, tokens []string, patterns []string) bool {
	for _, p := range patterns {
		if unambiguousPatterns[p] && strings.Contains(name, p) {
			return true
		}
		if matchesTokens(tokens, tokenize(p)) {
			return true
		}
	}
	return false
}

// matchesTokens reports whether want appears as a contiguous run in tokens. The
// final want token may be matched in plural form so "profiles" matches "profile"
// and "certificates" matches "certificate".
func matchesTokens(tokens, want []string) bool {
	if len(want) == 0 || len(want) > len(tokens) {
		return false
	}
	for i := 0; i+len(want) <= len(tokens); i++ {
		ok := true
		for j, w := range want {
			last := j == len(want)-1
			if !tokenEq(tokens[i+j], w, last) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// tokenEq compares one token to one pattern token. plural allows the common
// English suffixes so a pluralized resource name is not a miss — under-matching
// here hides sensitive data, which is the expensive direction of the error.
func tokenEq(tok, want string, plural bool) bool {
	if tok == want {
		return true
	}
	if !plural {
		return false
	}
	switch {
	case tok == want+"s", tok == want+"es":
		return true
	case strings.HasSuffix(want, "y") && tok == strings.TrimSuffix(want, "y")+"ies":
		return true
	}
	return false
}

// containsAny reports whether s contains any of the raw substrings.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// storageAssets returns all assets that could contain data (storage + databases).
// Uses the DataStoreAssets index built in NewGraph() so k8s_pod/k8s_deployment
// from Workloads() are never iterated.
func (g Graph) storageAssets() []asset.Asset {
	return g.DataStoreAssets()
}
