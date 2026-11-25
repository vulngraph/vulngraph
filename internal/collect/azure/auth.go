package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// credential returns an Azure token credential for the connector config.
//
// Auth priority (OIDC-first, with SP migration path):
//  1. Service Principal: if both client_id and client_secret are in cfg, use
//     ClientSecretCredential — supports migration from a prior static-key
//     credential deployment until Workload Identity Federation is configured.
//  2. Ambient: DefaultAzureCredential — picks up Azure Workload Identity on GKE
//     (in-cluster) and falls through to Azure CLI / VS Code in local dev.
func credential(ctx context.Context, cfg map[string]string) (azcore.TokenCredential, error) {
	clientID := cfg["client_id"]
	clientSecret := cfg["client_secret"]
	tenantID := cfg["tenant_id"]

	if clientID != "" && clientSecret != "" && tenantID != "" {
		cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
		if err != nil {
			return nil, fmt.Errorf("credential: service principal: %w", err)
		}
		return cred, nil
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("credential: default: %w", err)
	}
	return cred, nil
}
