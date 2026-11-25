package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestClassifyAsset(t *testing.T) {
	tests := []struct {
		name      string
		asset     asset.Asset
		wantClass string // expected class (first/only)
		wantConf  string
		wantLen   int
	}{
		{
			name:      "name pattern → medium confidence",
			asset:     asset.Asset{ID: "b1", Name: "customer-profiles", Type: "s3_bucket"},
			wantClass: DataClassPII, wantConf: confidenceMedium, wantLen: 1,
		},
		{
			name:      "PCI name pattern",
			asset:     asset.Asset{ID: "b2", Name: "pci-scope-store", Type: "s3_bucket"},
			wantClass: DataClassPCI, wantConf: confidenceMedium, wantLen: 1,
		},
		{
			name: "explicit tag → high confidence",
			asset: asset.Asset{ID: "b3", Name: "prod-data", Type: "rds_instance",
				Tags: map[string]string{"data-classification": "financial"}},
			wantClass: DataClassFinancial, wantConf: confidenceHigh, wantLen: 1,
		},
		{
			name: "tag upgrades a name match to high",
			asset: asset.Asset{ID: "b4", Name: "customer-pii", Type: "s3_bucket",
				Tags: map[string]string{"sensitivity": "pii"}},
			wantClass: DataClassPII, wantConf: confidenceHigh, wantLen: 1,
		},
		{
			name:      "no signal → internal floor at low confidence",
			asset:     asset.Asset{ID: "b5", Name: "prod-logs-archive", Type: "s3_bucket"},
			wantClass: DataClassInternal, wantConf: confidenceLow, wantLen: 1,
		},
		{
			name:      "health-checker infra is NOT health data (floor to internal)",
			asset:     asset.Asset{ID: "b6", Name: "demo-lb-health-checker", Type: "s3_bucket"},
			wantClass: DataClassInternal, wantConf: confidenceLow, wantLen: 1,
		},
		{
			name:      "aws-emr is NOT health data (emr = MapReduce, floor to internal)",
			asset:     asset.Asset{ID: "b7", Name: "demo-emr-resources", Type: "s3_bucket"},
			wantClass: DataClassInternal, wantConf: confidenceLow, wantLen: 1,
		},
		{
			name:      "genuine patient-records still classifies as health",
			asset:     asset.Asset{ID: "b8", Name: "example-patient-records", Type: "rds_instance"},
			wantClass: DataClassHealth, wantConf: confidenceMedium, wantLen: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyAsset(tc.asset)
			require.Len(t, got, tc.wantLen)
			require.Equal(t, tc.wantClass, got[0].class)
			require.Equal(t, tc.wantConf, got[0].confidence)
		})
	}
}

// TestClassifyAsset_FalsePositives is the regression table for the shapes of
// misclassification this heuristic is known to produce. Each row names the
// bucket, the class it wrongly got, and the substring that produced it.
func TestClassifyAsset_FalsePositives(t *testing.T) {
	for _, tc := range []struct {
		name string
		why  string
	}{
		{"demo-personalversion-logs", `PII from "personal" inside "personalversion"`},
		{"demo-personalised.thumbnails", `PII from "personal" inside "personalised"`},
		{"demo-personalstack-builds", `PII from "personal" inside "personalstack"`},
		{"demo-healthscore-metrics", `Health from "health" inside "healthscore"`},
		{"demo-bucketcertest", `Credentials from "cert" inside "bucketcertest"`},
		{"demo-lb-health-checker", `Health from a load-balancer health check`},
		{"demo-emr-resources", `Health from "emr" (Elastic MapReduce)`},
		// Deploy-artifact buckets inherit their stack's name, so they used to be
		// counted as PII or financial.
		{"demo-customer-notify-dev-serverlessdeploymentbuck-0a1b2c3d4e5f", `PII from the stack name on a Lambda zip store`},
		{"demo-billing-dev-serverlessdeploymentbuck-0f1e2d3c4b5a", `Financial from the stack name on a Lambda zip store`},
		{"cf-templates-example123-us-east-1", `CloudFormation template store`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyAsset(asset.Asset{ID: "b/" + tc.name, Name: tc.name, Type: "s3_bucket"})
			require.Len(t, got, 1, tc.why)
			require.Equal(t, DataClassInternal, got[0].class, tc.why)
			require.Equal(t, confidenceLow, got[0].confidence)
		})
	}
}

// TestClassifyAsset_TruePositivesSurvive pins the other direction: the
// narrowing must not cost real signal. Every name here is a shape of store that
// must keep its class. Under-classifying hides sensitive data, so this table
// is the more important half of the pair.
func TestClassifyAsset_TruePositivesSurvive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		typ   string
		class string
	}{
		// Token matches.
		{"demo-accounting-invoices", "s3_bucket", DataClassFinancial},
		{"demo-payments-media", "s3_bucket", DataClassFinancial},
		{"demo-data-privacy", "s3_bucket", DataClassPII},
		{"example-customer-docs", "gcs_bucket", DataClassPII},
		{"example-events-gdpr", "gcs_bucket", DataClassPII},
		{"example-pci-scope-data", "s3_bucket", DataClassPCI},
		{"example-vault-prod", "gcs_bucket", DataClassCredentials},
		{"demo-billing-db", "rds_instance", DataClassFinancial},
		{"example-api-keys", "rds_instance", DataClassCredentials},
		{"example-transactions-archive", "gcs_bucket", DataClassFinancial},
		{"example-patient-records", "rds_instance", DataClassHealth},
		// Plural forms: strict token equality would have dropped these.
		{"example-profiles-temp", "gcs_bucket", DataClassPII},
		{"example-domain-certificates", "s3_bucket", DataClassCredentials},
		{"example-tls-certs", "s3_bucket", DataClassCredentials},
		{"example_payment_events", "gcs_bucket", DataClassFinancial},
		{"example_invoices", "gcs_bucket", DataClassFinancial},
		// Concatenated names, recovered by the unambiguousPatterns substring tier.
		{"exampleallpasswords", "s3_bucket", DataClassCredentials},
		{"examplebilling", "s3_bucket", DataClassFinancial},
		{"exampleorgbilling", "s3_bucket", DataClassFinancial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyAsset(asset.Asset{ID: "x/" + tc.name, Name: tc.name, Type: tc.typ})
			var classes []string
			for _, c := range got {
				classes = append(classes, c.class)
			}
			require.Contains(t, classes, tc.class)
		})
	}
}

// TestClassifyAsset_IgnoresResourceID is the headline fix. Every AWS Secrets
// Manager ARN contains ":secret:", so matching the ID made the credential
// pattern match every one of them by construction — most of the page's
// "sensitive stores" qualified on nothing but their own ARN.
func TestClassifyAsset_IgnoresResourceID(t *testing.T) {
	// An S3 bucket whose ARN-ish id is full of keywords its name does not carry.
	got := classifyAsset(asset.Asset{
		ID:   "arn:aws:s3:::pii-customer-payment-secret-vault-bucket",
		Name: "prod-logs-archive",
		Type: "s3_bucket",
	})
	require.Len(t, got, 1)
	require.Equal(t, DataClassInternal, got[0].class,
		"the id must not classify anything — only the name and the operator tags")

	// A secret whose NAME says nothing still classifies as credentials, but from
	// its resource TYPE (asserted), not from its ARN (a tautology).
	byType := classifyAsset(asset.Asset{
		ID:   "arn:aws:secretsmanager:eu-west-1:1:secret:opaque-guid-AbCdEf",
		Name: "3fa85f64-5717-4562-b3fc-2c963f66afa6",
		Type: "secretsmanager_secret",
	})
	require.Len(t, byType, 1)
	require.Equal(t, DataClassCredentials, byType[0].class)
	require.Equal(t, confidenceHigh, byType[0].confidence)
	require.Equal(t, sourceResourceType, byType[0].source)

	// A non-secret bucket does NOT get the type-derived class.
	require.True(t, IsSecretStoreType("ssm_parameter"))
	require.False(t, IsSecretStoreType("s3_bucket"))
}

// TestClassifyAsset_ConfidenceAndSource pins the pairing that must survive to the
// UI: an operator tag and a name guess have to be distinguishable.
func TestClassifyAsset_ConfidenceAndSource(t *testing.T) {
	guess := classifyAsset(asset.Asset{Name: "customer-profiles", Type: "s3_bucket"})
	require.Equal(t, confidenceMedium, guess[0].confidence)
	require.Equal(t, sourceHeuristic, guess[0].source)

	tagged := classifyAsset(asset.Asset{
		Name: "prod-data", Type: "rds_instance",
		Tags: map[string]string{"data-classification": "pii"},
	})
	require.Equal(t, confidenceHigh, tagged[0].confidence)
	require.Equal(t, sourceTag, tagged[0].source)

	// A tag beats the deploy-artifact suppression: an operator who says "this holds
	// PII" outranks every guess this file makes about the name.
	override := classifyAsset(asset.Asset{
		Name: "lambda-x-serverlessdeploymentbuck-abc", Type: "s3_bucket",
		Tags: map[string]string{"sensitivity": "pii"},
	})
	require.Len(t, override, 1)
	require.Equal(t, DataClassPII, override[0].class)
	require.Equal(t, confidenceHigh, override[0].confidence)
}

// TestTokenize / TestMatchesTokens pin the matching primitive itself.
func TestTokenize(t *testing.T) {
	require.Equal(t, []string{"demo", "data", "privacy", "v2", "prod"}, tokenize("demo-data-privacy_v2.prod"))
	require.Equal(t, []string{"personalversion2"}, tokenize("personalversion2"))
	require.Equal(t, []string{"demo", "thumbs2", "personalised", "cache"}, tokenize("demo-thumbs2.personalised.cache"))
	require.Empty(t, tokenize("---"))
}

func TestMatchesTokens(t *testing.T) {
	toks := tokenize("example-user-data-prod")
	require.True(t, matchesTokens(toks, tokenize("user-data")), "multi-token pattern, contiguous run")
	require.False(t, matchesTokens(tokenize("user-logs-data"), tokenize("user-data")),
		"non-contiguous tokens must not match")
	require.True(t, matchesTokens(tokenize("cert-store"), []string{"cert"}))
	require.True(t, matchesTokens(tokenize("certs-store"), []string{"cert"}), "plural")
	require.False(t, matchesTokens(tokenize("certman-store"), []string{"cert"}),
		"a longer word is not a plural")
	require.False(t, matchesTokens(nil, []string{"cert"}))
	require.False(t, matchesTokens([]string{"cert"}, nil))
}

// Correlate must emit ContainsData edges carrying the confidence property.
func TestDataClassification_EmitsConfidence(t *testing.T) {
	a := asset.Asset{ID: "b1", Name: "pii-store", Type: "s3_bucket"}
	g := NewGraph([]asset.Asset{a})
	edges := DataClassification{}.Correlate(g)
	require.NotEmpty(t, edges)
	e := edges[0]
	require.Equal(t, EdgeContainsData, e.EdgeType)
	require.Equal(t, "b1", e.SrcID)
	require.Equal(t, confidenceMedium, e.Properties["confidence"])
	require.Equal(t, "pii", e.Properties["classification"])
}

// Every correlation rule stamps origin/rule so a computed edge is
// distinguishable from a collected one; contains_data and
// allows_action were the two that did not.
func TestCorrelateEdgesCarryOriginAndRule(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "b1", Name: "customer-profiles", Type: "s3_bucket"},
		{
			ID: "arn:aws:iam::1:role/admin", Type: "iam_role", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"policies": `[{"name":"AdministratorAccess","type":"identity","managed":true,` +
				`"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}]`},
		},
	})

	for _, tc := range []struct {
		rule Rule
		want string
	}{
		{DataClassification{}, "data_classification"},
		{IAMEffectivePermissions{}, "iam_effective_permissions"},
	} {
		edges := tc.rule.Correlate(g)
		require.NotEmpty(t, edges, tc.want)
		for _, e := range edges {
			require.Equal(t, edgeOrigin, e.Properties["origin"], tc.want)
			require.Equal(t, tc.want, e.Properties["rule"])
		}
	}
}
