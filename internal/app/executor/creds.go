package executor

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

// The executor runs as a DIFFERENT principal from the collector. A
// connector's collection credential is, by construction, the broadest thing
// the platform holds, and its policy was never sized for writes — using it to
// mutate would make the mutation surface whatever that policy happens to
// allow.
//
// So the executor never touches the collection credential. Every provider
// path below requires an explicitly configured EXECUTION principal and fails
// closed without one (ErrNoExecutionRole): a connector with no separate,
// narrowly-scoped write role cannot mutate anything, no matter what mode it
// is in. Distinctness is checked where the connector names other principals:
// on AWS execute_role_arn must differ from role_arn and readonly_role_arn; on
// Azure execute_client_id must differ from client_id. GCP collects with the
// pod's ambient (ADC) identity, which is not in connector config, so
// execute_service_account cannot be compared against it here; the operator
// must make sure it is not that service account.
const (
	// ConfigExecuteRoleARN is the AWS role the executor assumes. Required for
	// every AWS action; must differ from role_arn and readonly_role_arn.
	ConfigExecuteRoleARN = "execute_role_arn"
	// ConfigExecuteExternalID is the optional sts:ExternalId for that role.
	ConfigExecuteExternalID = "execute_external_id"
	// ConfigExecuteServiceAccount is the GCP service account the executor
	// impersonates. Required for every GCP action.
	ConfigExecuteServiceAccount = "execute_service_account"
	// ConfigExecuteClientID / Secret / TenantID are the Azure service principal
	// the executor authenticates as. client id and secret are required for every
	// Azure action; the tenant falls back to the connector's tenant_id.
	ConfigExecuteClientID     = "execute_client_id"
	ConfigExecuteClientSecret = "execute_client_secret"
	ConfigExecuteTenantID     = "execute_tenant_id"
)

// executionAWSConfig builds an AWS config for the connector's EXECUTION role.
//
// It starts from the pod's ambient workload identity — deliberately not from the
// connector's static access keys or its collection role — and assumes
// execute_role_arn from there. A connector carrying static credentials therefore
// gains no write path from them. An org child whose hub role trusts a principal
// (hub_role_arn) first assumes that hub role from the ambient identity, since
// the execution role trusts only the hub.
func executionAWSConfig(ctx context.Context, c connector.Connector, region string) (awssdk.Config, error) {
	if region == "" {
		return awssdk.Config{}, fmt.Errorf("executionAWSConfig: region is required")
	}
	execRole := c.Config[ConfigExecuteRoleARN]
	switch execRole {
	case "":
		return awssdk.Config{}, fmt.Errorf(
			"%w: AWS connector %s has no %s — configure a write-scoped role distinct from the collection role before enabling executor actions",
			ErrNoExecutionRole, c.ID, ConfigExecuteRoleARN)
	case c.Config["role_arn"]:
		return awssdk.Config{}, fmt.Errorf(
			"%w: %s on connector %s is the collection role_arn — the executor must not run with the credentials it collects with",
			ErrNoExecutionRole, ConfigExecuteRoleARN, c.ID)
	case c.Config["readonly_role_arn"]:
		return awssdk.Config{}, fmt.Errorf(
			"%w: %s on connector %s is the readonly_role_arn — that role is the read ceiling and cannot mutate",
			ErrNoExecutionRole, ConfigExecuteRoleARN, c.ID)
	}

	base, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return awssdk.Config{}, fmt.Errorf("executionAWSConfig: load ambient config: %w", err)
	}
	if hub := c.Config[connector.OrgKeyHubRoleARN]; hub != "" {
		base.Credentials = awssdk.NewCredentialsCache(stscreds.NewAssumeRoleProvider(
			sts.NewFromConfig(base), hub, func(o *stscreds.AssumeRoleOptions) {
				o.RoleSessionName = "graph-hub"
			}))
	}
	stsClient := sts.NewFromConfig(base)
	base.Credentials = awssdk.NewCredentialsCache(
		stscreds.NewAssumeRoleProvider(stsClient, execRole, func(o *stscreds.AssumeRoleOptions) {
			if ext := c.Config[ConfigExecuteExternalID]; ext != "" {
				o.ExternalID = awssdk.String(ext)
			}
		}),
	)
	return base, nil
}

// executionGCPOptions builds client options that impersonate the connector's
// EXECUTION service account.
//
// The impersonated token is minted from the pod's ambient (ADC) credentials,
// the same identity the GCP collector uses. The client is given only the
// impersonated token source, so writes run as execute_service_account rather
// than as the ambient identity. Nothing here checks that the two differ.
func executionGCPOptions(ctx context.Context, c connector.Connector, scope string) ([]option.ClientOption, error) {
	sa := c.Config[ConfigExecuteServiceAccount]
	if sa == "" {
		return nil, fmt.Errorf(
			"%w: GCP connector %s has no %s — configure a write-scoped service account for the executor to impersonate",
			ErrNoExecutionRole, c.ID, ConfigExecuteServiceAccount)
	}
	// google.golang.org/api/impersonate rather than the deprecated
	// option.ImpersonateCredentials: same STS exchange, but it is the supported
	// path and it fails at token-source construction rather than on first call,
	// so a misconfigured execution SA surfaces here instead of mid-mutation.
	ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: sa,
		Scopes:          []string{scope},
	})
	if err != nil {
		return nil, fmt.Errorf(
			"%w: GCP connector %s cannot impersonate %s: %w",
			ErrNoExecutionRole, c.ID, sa, err)
	}
	return []option.ClientOption{option.WithTokenSource(ts)}, nil
}

// executionAzureCredential authenticates as the connector's EXECUTION service
// principal. There is no ambient fallback here on purpose: DefaultAzureCredential
// would silently hand the executor the pod's own (collection) identity, which is
// exactly the collapse this file exists to prevent.
func executionAzureCredential(c connector.Connector) (azcore.TokenCredential, error) {
	clientID := c.Config[ConfigExecuteClientID]
	secret := c.Config[ConfigExecuteClientSecret]
	tenant := c.Config[ConfigExecuteTenantID]
	if tenant == "" {
		tenant = c.Config["tenant_id"]
	}
	switch {
	case clientID == "" || secret == "":
		return nil, fmt.Errorf(
			"%w: Azure connector %s has no %s/%s — configure a write-scoped service principal for the executor",
			ErrNoExecutionRole, c.ID, ConfigExecuteClientID, ConfigExecuteClientSecret)
	case tenant == "":
		return nil, fmt.Errorf("%w: Azure connector %s has no tenant for the execution principal", ErrNoExecutionRole, c.ID)
	case clientID == c.Config["client_id"]:
		return nil, fmt.Errorf(
			"%w: %s on connector %s is the collection client_id — the executor must not run with the credentials it collects with",
			ErrNoExecutionRole, ConfigExecuteClientID, c.ID)
	}
	cred, err := azidentity.NewClientSecretCredential(tenant, clientID, secret, nil)
	if err != nil {
		return nil, fmt.Errorf("executionAzureCredential: %w", err)
	}
	return cred, nil
}

// missingExecutionPrincipal names the config key a connector lacks for an
// execution principal, or "" when one is configured. A presence check only, so
// the decision panel can say up front that nothing can run; the full
// distinctness checks above still run on the real call.
func missingExecutionPrincipal(c connector.Connector) string {
	switch c.Type {
	case connector.TypeAWS:
		if c.Config[ConfigExecuteRoleARN] == "" {
			return ConfigExecuteRoleARN
		}
	case connector.TypeGCP:
		if c.Config[ConfigExecuteServiceAccount] == "" {
			return ConfigExecuteServiceAccount
		}
	case connector.TypeAzure:
		if c.Config[ConfigExecuteClientID] == "" || c.Config[ConfigExecuteClientSecret] == "" {
			return ConfigExecuteClientID + "/" + ConfigExecuteClientSecret
		}
	}
	return ""
}
