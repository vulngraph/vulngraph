package main

// bootstrap reads credentials from a migration namespace's secrets and
// registers them as Vulngraph connectors via the API — useful if you're migrating
// from an existing asset-inventory tool that already has cloud credentials
// configured in Kubernetes Secrets; skip this entirely and use the API or UI
// to add connectors otherwise. Run once after first deploy:
//
//	GRAPH_API_URL=http://localhost:8080 \
//	GRAPH_ADMIN_TOKEN=<token> \
//	AWS_ORG_MANAGEMENT_ROLE_ARN=arn:aws:iam::<mgmt>:role/GraphOrgDiscovery \
//	AWS_ORG_EXTERNAL_ID=<external id> \
//	GCP_PROJECT_IDS=<comma-separated project ids> \
//	graph bootstrap
//
// BOOTSTRAP_ONLY (CSV of aws,github,gcp,kubernetes) restricts the run to a
// subset of providers; empty enables all — useful for phasing a rollout while
// other providers' credentials are still being wired up.
//
// Idempotent: connectors already present (matched by name) are skipped.
//
// AWS: standalone static-key profiles in the credentials Secret become one
// connector each. An AWS Organization becomes ONE aws_org connector
// (AWS_ORG_MANAGEMENT_ROLE_ARN + AWS_ORG_EXTERNAL_ID); Vulngraph then discovers
// the member accounts and manages their connectors itself, with no hub key
// copied into any of them (ADR 091, docs/onboarding-aws-org.md).

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"

	collectgithub "github.com/vulngraph/vulngraph/internal/collect/github"
	"github.com/vulngraph/vulngraph/pkg/log"
)

func bootstrap(ctx context.Context, getenv func(string) string) error {
	logger := log.FromContext(ctx)

	token := getenv("GRAPH_ADMIN_TOKEN")
	if token == "" {
		return fmt.Errorf("bootstrap: GRAPH_ADMIN_TOKEN is required")
	}
	apiURL := envOr(getenv, "GRAPH_API_URL", "http://localhost:8080")
	ns := envOr(getenv, "GRAPH_MIGRATION_NAMESPACE", "graph-bootstrap")
	api := newGraphAPI(apiURL, token)

	only := bootstrapScope(getenv("BOOTSTRAP_ONLY"))
	logger.Info().Strs("providers", scopeList(only)).Msg("bootstrap scope")

	if only["azure"] {
		if err := bootstrapAzure(ctx, api, ns); err != nil {
			logger.Warn().Err(err).Msg("Azure bootstrap incomplete")
		}
	}
	if only["aws"] {
		if err := bootstrapAWS(ctx, api, ns, getenv); err != nil {
			logger.Warn().Err(err).Msg("AWS bootstrap incomplete")
		}
	}
	if only["github"] {
		if err := bootstrapGitHub(ctx, api, ns); err != nil {
			logger.Warn().Err(err).Msg("GitHub bootstrap incomplete")
		}
	}
	if only["gcp"] {
		bootstrapGCP(ctx, api, getenv)
	}
	if only["kubernetes"] {
		bootstrapKubernetes(ctx, api, getenv)
	}

	return nil
}

// bootstrapScope selects which providers run. An empty BOOTSTRAP_ONLY enables
// all of them (the default); a CSV like "aws" or "aws,github" restricts the run
// — useful to phase a rollout (e.g. AWS-only before GCP Workload
// Identity and the k8s ClusterRole exist).
func bootstrapScope(csv string) map[string]bool {
	items := splitCSV(csv)
	if len(items) == 0 {
		return map[string]bool{"azure": true, "aws": true, "github": true, "gcp": true, "kubernetes": true}
	}
	scope := make(map[string]bool, len(items))
	for _, p := range items {
		scope[strings.ToLower(p)] = true
	}
	return scope
}

// scopeList returns the enabled providers in a stable order for logging.
func scopeList(scope map[string]bool) []string {
	var out []string
	for _, p := range []string{"azure", "aws", "github", "gcp", "kubernetes"} {
		if scope[p] {
			out = append(out, p)
		}
	}
	return out
}

// ── Azure ─────────────────────────────────────────────────────────────────────

// bootstrapAzure reads the Service Principal credentials from the migration
// namespace (secret graph-bootstrap-credentials, keys azure-client-tenantid /
// azure-client-clientid / azure-client-secret), lists every subscription
// accessible to that SP, and registers one connector per subscription.
// Idempotent: subscriptions already present are skipped.
func bootstrapAzure(ctx context.Context, api *graphAPI, ns string) error {
	logger := log.FromContext(ctx)

	tenantID, err := kubectlSecret(ctx, ns, "graph-bootstrap-credentials", "azure-client-tenantid")
	if err != nil {
		return fmt.Errorf("bootstrapAzure: tenant id: %w", err)
	}
	clientID, err := kubectlSecret(ctx, ns, "graph-bootstrap-credentials", "azure-client-clientid")
	if err != nil {
		return fmt.Errorf("bootstrapAzure: client id: %w", err)
	}
	clientSecret, err := kubectlSecret(ctx, ns, "graph-bootstrap-credentials", "azure-client-secret")
	if err != nil {
		return fmt.Errorf("bootstrapAzure: client secret: %w", err)
	}

	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return fmt.Errorf("bootstrapAzure: credential: %w", err)
	}

	// Read-only: never let the SDK auto-register resource providers.
	subClient, err := armsubscriptions.NewClient(cred, &arm.ClientOptions{DisableRPRegistration: true})
	if err != nil {
		return fmt.Errorf("bootstrapAzure: subscriptions client: %w", err)
	}

	pager := subClient.NewListPager(nil)
	var count int
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("bootstrapAzure: list subscriptions: %w", err)
		}
		for _, sub := range page.Value {
			if sub.SubscriptionID == nil || sub.DisplayName == nil {
				continue
			}
			subID := *sub.SubscriptionID
			name := "azure-" + subID
			if err := api.createConnector(ctx, connectorPayload{
				Type: "azure",
				Name: name,
				Config: map[string]string{
					"subscription_id": subID,
					"tenant_id":       tenantID,
					"client_id":       clientID,
					"client_secret":   clientSecret,
				},
			}); err != nil {
				logger.Warn().Str("subscription", subID).Str("name", *sub.DisplayName).Err(err).Msg("azure connector skipped")
			} else {
				logger.Info().Str("subscription", subID).Str("name", *sub.DisplayName).Msg("azure connector registered")
				count++
			}
		}
	}
	logger.Info().Int("subscriptions", count).Msg("azure bootstrap complete")
	return nil
}

// ── AWS ───────────────────────────────────────────────────────────────────────

func bootstrapAWS(ctx context.Context, api *graphAPI, ns string, getenv func(string) string) error {
	logger := log.FromContext(ctx)

	// The Secret name is whatever your old inventory tool happened to use —
	// "graph-aws-credentials" is only a placeholder default, not a convention
	// any other tool follows. Override via GRAPH_MIGRATION_AWS_SECRET_NAME if
	// yours is named differently.
	secretName := envOr(getenv, "GRAPH_MIGRATION_AWS_SECRET_NAME", "graph-aws-credentials")

	credsRaw, err := kubectlSecret(ctx, ns, secretName, "credentials")
	if err != nil && getenv("AWS_ORG_MANAGEMENT_ROLE_ARN") == "" {
		return fmt.Errorf("bootstrapAWS: %w", err)
	}
	cfgRaw, _ := kubectlSecret(ctx, ns, secretName, "config")
	creds := parseINI(credsRaw)
	cfg := parseINI(cfgRaw)
	orgHub := getenv("AWS_ORG_HUB_PROFILE")

	// 1) Direct static-key profiles → standalone connectors. The org hub
	// profile, if named, is the org connector's credential, not an account.
	for name, keyID := range creds {
		if strings.HasPrefix(name, "__") || name == orgHub {
			continue
		}
		region := orDefault(cfg["__region__"+name], "us-east-1")
		if err := api.createConnector(ctx, connectorPayload{
			Type: "aws",
			Name: "aws-" + name,
			Config: map[string]string{
				"aws_access_key_id":     keyID,
				"aws_secret_access_key": creds["__secret__"+name],
				"region":                region,
			},
		}); err != nil {
			logger.Warn().Str("profile", name).Err(err).Msg("aws profile skipped")
		} else {
			logger.Info().Str("profile", name).Str("region", region).Msg("aws connector registered")
		}
	}

	// 2) The organization → one aws_org connector. Vulngraph discovers the member
	// accounts itself and manages a child connector per account; no hub key is
	// copied into any child (ADR 091).
	payload, ok, err := orgConnectorPayload(getenv, creds)
	if err != nil {
		return fmt.Errorf("bootstrapAWS: %w", err)
	}
	if !ok {
		logger.Info().Msg("AWS_ORG_MANAGEMENT_ROLE_ARN unset — no aws_org connector registered")
		return nil
	}
	if err := api.createConnector(ctx, payload); err != nil {
		logger.Warn().Str("name", payload.Name).Err(err).Msg("aws_org connector skipped")
		return nil
	}
	logger.Info().Str("name", payload.Name).Str("hub_auth", payload.Config["hub_auth"]).Msg("aws_org connector registered")
	return nil
}

// orgConnectorPayload builds the aws_org connector bootstrap registers. ok is
// false when AWS_ORG_MANAGEMENT_ROLE_ARN is unset. The hub is Vulngraph's ambient
// identity unless AWS_ORG_HUB_PROFILE names a credentials-file profile, whose
// keys are then stored once, on the org connector only. AWS_ORG_HUB_ROLE_ARN is
// the hub role those credentials assume first (TrustType=principal); a stored
// key requires it.
func orgConnectorPayload(getenv func(string) string, creds map[string]string) (connectorPayload, bool, error) {
	mgmtRole := getenv("AWS_ORG_MANAGEMENT_ROLE_ARN")
	if mgmtRole == "" {
		return connectorPayload{}, false, nil
	}
	extID := getenv("AWS_ORG_EXTERNAL_ID")
	if extID == "" {
		return connectorPayload{}, false, fmt.Errorf("orgConnectorPayload: AWS_ORG_EXTERNAL_ID is required with AWS_ORG_MANAGEMENT_ROLE_ARN")
	}
	cfg := map[string]string{
		"management_role_arn": mgmtRole,
		"external_id":         extID,
		"member_role_name":    envOr(getenv, "AWS_READONLY_ROLE", "GraphReadOnly"),
		"region":              envOr(getenv, "AWS_REGION", "us-east-1"),
		"hub_auth":            "ambient",
	}
	if hubRole := getenv("AWS_ORG_HUB_ROLE_ARN"); hubRole != "" {
		cfg["hub_role_arn"] = hubRole
	}
	if profile := getenv("AWS_ORG_HUB_PROFILE"); profile != "" {
		key, secret := creds[profile], creds["__secret__"+profile]
		if key == "" || secret == "" {
			return connectorPayload{}, false, fmt.Errorf("orgConnectorPayload: AWS_ORG_HUB_PROFILE %q has no keys in the credentials file", profile)
		}
		if cfg["hub_role_arn"] == "" {
			return connectorPayload{}, false, fmt.Errorf("orgConnectorPayload: AWS_ORG_HUB_ROLE_ARN is required with AWS_ORG_HUB_PROFILE — an IAM user key is never a hub session")
		}
		cfg["hub_auth"], cfg["aws_access_key_id"], cfg["aws_secret_access_key"] = "access_key", key, secret
	}
	return connectorPayload{Type: "aws_org", Name: envOr(getenv, "AWS_ORG_CONNECTOR_NAME", "aws-org"), Config: cfg}, true, nil
}

// ── GitHub ─────────────────────────────────────────────────────────────────────

func bootstrapGitHub(ctx context.Context, api *graphAPI, ns string) error {
	logger := log.FromContext(ctx)

	appID, err := kubectlSecret(ctx, ns, "graph-bootstrap-credentials", "github-app-id")
	if err != nil {
		return fmt.Errorf("bootstrapGitHub: %w", err)
	}
	privKey, err := kubectlSecret(ctx, ns, "graph-bootstrap-credentials", "github-app-private-key")
	if err != nil {
		return fmt.Errorf("bootstrapGitHub: %w", err)
	}
	orgsRaw, err := kubectlSecret(ctx, ns, "graph-bootstrap-credentials", "github-orgs")
	if err != nil {
		return fmt.Errorf("bootstrapGitHub: %w", err)
	}

	for _, org := range splitCSV(orgsRaw) {
		installID, err := collectgithub.ResolveInstallationID(ctx, "", appID, privKey, org)
		if err != nil {
			logger.Warn().Str("org", org).Err(err).Msg("could not resolve installation id")
			continue
		}
		if err := api.createConnector(ctx, connectorPayload{
			Type: "github",
			Name: "github-" + org,
			Config: map[string]string{
				"app_id":          appID,
				"installation_id": installID,
				"private_key_pem": privKey,
			},
		}); err != nil {
			logger.Warn().Str("org", org).Err(err).Msg("github connector skipped")
		} else {
			logger.Info().Str("org", org).Str("installation_id", installID).Msg("github connector registered")
		}
	}
	return nil
}

// ── GCP ────────────────────────────────────────────────────────────────────────

func bootstrapGCP(ctx context.Context, api *graphAPI, getenv func(string) string) {
	logger := log.FromContext(ctx)
	for _, proj := range splitCSV(getenv("GCP_PROJECT_IDS")) {
		if err := api.createConnector(ctx, connectorPayload{
			Type:   "gcp",
			Name:   "gcp-" + proj,
			Config: map[string]string{"project_id": proj},
		}); err != nil {
			logger.Warn().Str("project", proj).Err(err).Msg("gcp connector skipped")
		} else {
			logger.Info().Str("project", proj).Msg("gcp connector registered")
		}
	}
}

// ── Kubernetes ───────────────────────────────────────────────────────────────

func bootstrapKubernetes(ctx context.Context, api *graphAPI, getenv func(string) string) {
	logger := log.FromContext(ctx)
	cluster := envOr(getenv, "K8S_CLUSTER_NAME", "in-cluster")
	if err := api.createConnector(ctx, connectorPayload{
		Type:   "kubernetes",
		Name:   "kubernetes-" + cluster,
		Config: map[string]string{"cluster_name": cluster},
	}); err != nil {
		logger.Warn().Err(err).Msg("kubernetes connector skipped")
	} else {
		logger.Info().Str("cluster", cluster).Msg("kubernetes connector registered")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// parseINI parses AWS INI credential/config format into a flat map:
// "<profile>" → access key id, "__secret__<profile>" → secret,
// "__region__<profile>" → region.
func parseINI(data string) map[string]string {
	m := make(map[string]string)
	var section string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 || section == "" {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "aws_access_key_id":
			m[section] = val
		case "aws_secret_access_key":
			m["__secret__"+section] = val
		case "region":
			m["__region__"+section] = val
		}
	}
	return m
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// base64Std decodes a kubectl-returned secret value.
func base64Std(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
