package asset

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyEnvironment(t *testing.T) {
	tags := func(kv ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	for _, tc := range []struct {
		name   string
		a      Asset
		env    Environment
		source string
	}{
		// ── nothing to go on ─────────────────────────────────────────────
		{"zero asset", Asset{}, EnvUnknown, ""},
		{"unrelated tags", Asset{Tags: tags("owner", "payments", "team", "core")}, EnvUnknown, ""},
		{"env key with an unrecognised value", Asset{Tags: tags("env", "blue")}, EnvUnknown, ""},
		{"empty env value", Asset{Tags: tags("env", "")}, EnvUnknown, ""},
		{"numeric AWS account id says nothing", Asset{AccountID: "123456789012"}, EnvUnknown, ""},
		{"tier=frontend is not an environment", Asset{Tags: tags("tier", "frontend")}, EnvUnknown, ""},

		// ── explicit tags: key variants ──────────────────────────────────
		{"env=prod", Asset{Tags: tags("env", "prod")}, EnvProd, "tag:env"},
		{"Environment=Production (case)", Asset{Tags: tags("Environment", "Production")}, EnvProd, "tag:Environment"},
		{"stage=prd", Asset{Tags: tags("stage", "prd")}, EnvProd, "tag:stage"},
		{"tier=live", Asset{Tags: tags("tier", "live")}, EnvProd, "tag:tier"},
		{"namespaced example.io/env", Asset{Tags: tags("example.io/env", "prod")}, EnvProd, "tag:example.io/env"},
		{"namespaced example.io/stage", Asset{Tags: tags("example.io/stage", "staging")}, EnvStaging, "tag:example.io/stage"},
		{"k8s app.kubernetes.io/environment", Asset{Tags: tags("app.kubernetes.io/environment", "dev")}, EnvDev, "tag:app.kubernetes.io/environment"},
		{"colon namespace aws:env", Asset{Tags: tags("aws:env", "dev")}, EnvDev, "tag:aws:env"},
		{"suffix acme-env", Asset{Tags: tags("acme-env", "qa")}, EnvStaging, "tag:acme-env"},
		{"suffix acme_environment", Asset{Tags: tags("acme_environment", "sandbox")}, EnvDev, "tag:acme_environment"},
		{"deployment-environment", Asset{Tags: tags("deployment-environment", "uat")}, EnvStaging, "tag:deployment-environment"},
		{"key with whitespace", Asset{Tags: tags(" env ", "prod")}, EnvProd, "tag: env "},
		{"a key merely containing env is not one", Asset{Tags: tags("envoy-version", "prod")}, EnvUnknown, ""},

		// ── explicit tags: value variants ────────────────────────────────
		{"production", Asset{Tags: tags("env", "production")}, EnvProd, "tag:env"},
		{"prod-eu (token)", Asset{Tags: tags("env", "prod-eu")}, EnvProd, "tag:env"},
		{"eu_prod (token)", Asset{Tags: tags("env", "eu_prod")}, EnvProd, "tag:env"},
		{"staging", Asset{Tags: tags("env", "staging")}, EnvStaging, "tag:env"},
		{"stg", Asset{Tags: tags("env", "stg")}, EnvStaging, "tag:env"},
		{"preprod", Asset{Tags: tags("env", "preprod")}, EnvStaging, "tag:env"},
		{"pre-prod is staging, not prod", Asset{Tags: tags("env", "pre-prod")}, EnvStaging, "tag:env"},
		{"pre-prod-eu is staging, not prod", Asset{Tags: tags("env", "pre-prod-eu")}, EnvStaging, "tag:env"},
		{"Pre-Production", Asset{Tags: tags("env", "Pre-Production")}, EnvStaging, "tag:env"},
		{"test", Asset{Tags: tags("env", "test")}, EnvStaging, "tag:env"},
		{"dev", Asset{Tags: tags("env", "dev")}, EnvDev, "tag:env"},
		{"development", Asset{Tags: tags("env", "Development")}, EnvDev, "tag:env"},
		{"dev-2 (token)", Asset{Tags: tags("env", "dev-2")}, EnvDev, "tag:env"},
		{"padded value", Asset{Tags: tags("env", "  prod  ")}, EnvProd, "tag:env"},
		{"non-prod names no stage", Asset{Tags: tags("env", "non-prod")}, EnvUnknown, ""},
		{"nonprod names no stage", Asset{Tags: tags("env", "nonprod")}, EnvUnknown, ""},
		{"not_production names no stage", Asset{Tags: tags("env", "not_production")}, EnvUnknown, ""},
		{"value naming two stages", Asset{Tags: tags("env", "dev-prod")}, EnvUnknown, ""},

		// ── several keys in one tier ─────────────────────────────────────
		{"agreeing keys pick a stable source", Asset{Tags: tags("stage", "prod", "env", "production")}, EnvProd, "tag:env"},
		{"disagreeing keys are a conflict", Asset{Tags: tags("env", "prod", "stage", "dev")}, EnvUnknown, "conflict:tag"},
		{"an unrecognised key value does not conflict", Asset{Tags: tags("env", "prod", "tier", "web")}, EnvProd, "tag:env"},

		// ── tier priority ────────────────────────────────────────────────
		{"metadata fallback", Asset{Metadata: tags("environment", "prod")}, EnvProd, "metadata:environment"},
		{"tag beats metadata", Asset{Tags: tags("env", "dev"), Metadata: tags("environment", "prod")}, EnvDev, "tag:env"},
		{"unrecognised tag falls through to metadata", Asset{Tags: tags("env", "blue"), Metadata: tags("env", "staging")}, EnvStaging, "metadata:env"},
		{"metadata conflict", Asset{Metadata: tags("env", "prod", "stage", "staging")}, EnvUnknown, "conflict:metadata"},
		{"namespace tag", Asset{Tags: tags("namespace", "production")}, EnvProd, "namespace"},
		{"namespace metadata", Asset{Metadata: tags("namespace", "payments-staging")}, EnvStaging, "namespace"},
		{"kube-system namespace says nothing", Asset{Tags: tags("namespace", "kube-system")}, EnvUnknown, ""},
		{"env tag beats namespace", Asset{Tags: tags("env", "prod", "namespace", "dev")}, EnvProd, "tag:env"},
		{"namespace beats account id", Asset{Tags: tags("namespace", "dev"), AccountID: "acme-prod-1"}, EnvDev, "namespace"},
		{"GCP project id", Asset{AccountID: "acme-prod-123"}, EnvProd, "account_id"},
		{"GCP sandbox project", Asset{AccountID: "jane-sandbox"}, EnvDev, "account_id"},
		{"project id with no stage", Asset{AccountID: "acme-platform"}, EnvUnknown, ""},
		{"product is not prod", Asset{AccountID: "product-catalog"}, EnvUnknown, ""},
		{"explicit tag beats account id", Asset{Tags: tags("env", "staging"), AccountID: "acme-prod"}, EnvStaging, "tag:env"},
		{"conflicting tags do not fall through to the account", Asset{Tags: tags("env", "prod", "stage", "dev"), AccountID: "acme-dev"}, EnvUnknown, "conflict:tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyEnvironment(tc.a)
			require.Equal(t, tc.env, got.Env)
			require.Equal(t, tc.source, got.Source)
		})
	}
}

func TestEnvironment_KnownAndTreatAsProd(t *testing.T) {
	for _, tc := range []struct {
		env         Environment
		known, prod bool
	}{
		{EnvProd, true, true},
		{EnvStaging, true, false},
		{EnvDev, true, false},
		{EnvUnknown, false, true},
		{"", false, true},      // zero value fails closed
		{"bogus", false, true}, // anything unrecognised fails closed
	} {
		t.Run(string(tc.env), func(t *testing.T) {
			require.Equal(t, tc.known, tc.env.Known())
			require.Equal(t, tc.prod, tc.env.TreatAsProd())
		})
	}
}
