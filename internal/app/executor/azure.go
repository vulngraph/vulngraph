package executor

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// executeAzure routes an Azure action to its implementation.
func (s *Service) executeAzure(ctx context.Context, c connector.Connector, action Action, params map[string]string) (ExecutionResult, error) {
	switch action {
	case ActionAzureNSGRuleRemove:
		return s.azureNSGRuleRemove(ctx, c, params)
	default:
		return ExecutionResult{}, fmt.Errorf("%w: unknown Azure action %q", ErrCapabilityMissing, action)
	}
}

// azureNSGRuleRemove deletes a single security rule from an Azure Network
// Security Group. Required params: resource_group, nsg_name, rule_name.
// subscription_id falls back to c.Config["subscription_id"] when not in params.
func (s *Service) azureNSGRuleRemove(ctx context.Context, c connector.Connector, params map[string]string) (ExecutionResult, error) {
	subscriptionID := params[ParamSubscriptionID]
	resourceGroup := params[ParamResourceGroup]
	nsgName := params[ParamNSGName]
	ruleName := params[ParamRuleName]

	cred, err := executionAzureCredential(c)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("azureNSGRuleRemove: %w", err)
	}

	// Provider auto-registration is a second write nobody approved: with it
	// off, MissingSubscriptionRegistration comes back as an error.
	client, err := armnetwork.NewSecurityRulesClient(subscriptionID, cred, &arm.ClientOptions{DisableRPRegistration: true})
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("azureNSGRuleRemove: create client: %w", err)
	}

	poller, err := client.BeginDelete(ctx, resourceGroup, nsgName, ruleName, nil)
	if err != nil {
		log.FromContext(ctx).Error().Err(err).
			Str("resource_group", resourceGroup).
			Str("nsg_name", nsgName).
			Str("rule_name", ruleName).
			Msg("executor: BeginDelete NSG rule failed")
		return ExecutionResult{}, fmt.Errorf("%w: BeginDelete NSG rule %s/%s/%s: %v", ErrExecutionFailed, resourceGroup, nsgName, ruleName, err)
	}

	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.FromContext(ctx).Error().Err(err).
			Str("resource_group", resourceGroup).
			Str("nsg_name", nsgName).
			Str("rule_name", ruleName).
			Msg("executor: PollUntilDone NSG rule delete failed")
		return ExecutionResult{}, fmt.Errorf("%w: PollUntilDone NSG rule %s/%s/%s: %v", ErrExecutionFailed, resourceGroup, nsgName, ruleName, err)
	}

	detail := fmt.Sprintf("deleted Azure NSG rule %s from %s in %s", ruleName, nsgName, resourceGroup)
	log.FromContext(ctx).Info().
		Str("resource_group", resourceGroup).
		Str("nsg_name", nsgName).
		Str("rule_name", ruleName).
		Msg("executor: Azure NSG rule removed")
	return ExecutionResult{ConnectorID: c.ID, Action: ActionAzureNSGRuleRemove, Detail: detail}, nil
}
