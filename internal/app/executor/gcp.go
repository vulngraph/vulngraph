package executor

import (
	"context"
	"fmt"

	compute "google.golang.org/api/compute/v1"
	iam "google.golang.org/api/iam/v1"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// executeGCP routes a GCP remediation action to the appropriate method.
func (s *Service) executeGCP(ctx context.Context, c connector.Connector, action Action, params map[string]string) (ExecutionResult, error) {
	switch action {
	case ActionGCPSAKeyDisable:
		return s.gcpSAKeyDisable(ctx, c, params)
	case ActionGCPFirewallRemove:
		return s.gcpFirewallRemove(ctx, c, params)
	default:
		return ExecutionResult{}, fmt.Errorf("%w: unknown GCP action %q", ErrCapabilityMissing, action)
	}
}

// gcpSAKeyDisable disables a GCP service account key using the IAM API.
// Required params: service_account (SA email), key_name (full resource name).
func (s *Service) gcpSAKeyDisable(ctx context.Context, c connector.Connector, params map[string]string) (ExecutionResult, error) {
	serviceAccount := params[ParamServiceAccount]
	keyName := params[ParamKeyName]

	opts, err := executionGCPOptions(ctx, c, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("gcpSAKeyDisable: %w", err)
	}

	iamSvc, err := iam.NewService(ctx, opts...)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("gcpSAKeyDisable: build IAM service: %w", err)
	}

	_, apiErr := iamSvc.Projects.ServiceAccounts.Keys.Disable(keyName, &iam.DisableServiceAccountKeyRequest{}).Context(ctx).Do()
	if apiErr != nil {
		log.FromContext(ctx).Error().Err(apiErr).
			Str("key_name", keyName).Str("service_account", serviceAccount).
			Msg("executor: GCP DisableServiceAccountKey failed")
		return ExecutionResult{}, fmt.Errorf("%w: DisableServiceAccountKey %s: %v", ErrExecutionFailed, keyName, apiErr)
	}

	detail := fmt.Sprintf("disabled GCP service account key %s on %s", keyName, serviceAccount)
	log.FromContext(ctx).Info().
		Str("key_name", keyName).Str("service_account", serviceAccount).
		Msg("executor: GCP service account key disabled")
	return ExecutionResult{ConnectorID: c.ID, Action: ActionGCPSAKeyDisable, Detail: detail}, nil
}

// gcpFirewallRemove deletes a GCP firewall rule using the Compute API.
// Required params: firewall_rule (name of the rule); project falls back to c.Config["project_id"].
func (s *Service) gcpFirewallRemove(ctx context.Context, c connector.Connector, params map[string]string) (ExecutionResult, error) {
	project := params[ParamProject]
	firewallRule := params[ParamFirewallRule]

	opts, err := executionGCPOptions(ctx, c, "https://www.googleapis.com/auth/compute")
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("gcpFirewallRemove: %w", err)
	}

	computeSvc, err := compute.NewService(ctx, opts...)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("gcpFirewallRemove: build Compute service: %w", err)
	}

	_, apiErr := computeSvc.Firewalls.Delete(project, firewallRule).Context(ctx).Do()
	if apiErr != nil {
		log.FromContext(ctx).Error().Err(apiErr).
			Str("firewall_rule", firewallRule).Str("project", project).
			Msg("executor: GCP Firewalls.Delete failed")
		return ExecutionResult{}, fmt.Errorf("%w: Firewalls.Delete %s/%s: %v", ErrExecutionFailed, project, firewallRule, apiErr)
	}

	detail := fmt.Sprintf("deleted GCP firewall rule %s from project %s", firewallRule, project)
	log.FromContext(ctx).Info().
		Str("firewall_rule", firewallRule).Str("project", project).
		Msg("executor: GCP firewall rule deleted")
	return ExecutionResult{ConnectorID: c.ID, Action: ActionGCPFirewallRemove, Detail: detail}, nil
}
