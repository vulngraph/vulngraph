package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// lockSuffix separates a lock's scope from its own name in the lock ID.
const lockSuffix = "/providers/microsoft.authorization/locks/"

// readDeleteLockScopes returns the lowercased scopes (subscription, resource
// group or resource) carrying a lock that blocks deletion. Both CanNotDelete
// and ReadOnly block it. The subscription-level listing returns every lock in
// the subscription, whatever scope it sits on.
func readDeleteLockScopes(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, opts *arm.ClientOptions) (map[string]bool, error) {
	client, err := armlocks.NewManagementLocksClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("readDeleteLockScopes: client: %w", err)
	}
	scopes := map[string]bool{}
	pager := client.NewListAtSubscriptionLevelPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("readDeleteLockScopes: list: %w", err)
		}
		for _, l := range page.Value {
			if scope, ok := deleteLockScope(l); ok {
				scopes[scope] = true
			}
		}
	}
	return scopes, nil
}

func deleteLockScope(l *armlocks.ManagementLockObject) (string, bool) {
	if l == nil || l.ID == nil || l.Properties == nil || l.Properties.Level == nil {
		return "", false
	}
	if lvl := *l.Properties.Level; lvl != armlocks.LockLevelCanNotDelete && lvl != armlocks.LockLevelReadOnly {
		return "", false
	}
	id := strings.ToLower(*l.ID)
	i := strings.LastIndex(id, lockSuffix)
	if i < 0 {
		return "", false
	}
	return id[:i], true
}

// applyStorageLocks writes delete_lock on every storage account: true when a
// delete-blocking lock sits on the account, its resource group or the
// subscription, all of which Azure applies to the account.
func applyStorageLocks(assets []asset.Asset, scopes map[string]bool, subscriptionID string) {
	sub := strings.ToLower("/subscriptions/" + subscriptionID)
	for i := range assets {
		a := &assets[i]
		if a.Provider != asset.ProviderAzure || a.Type != "azure_storage_account" {
			continue
		}
		id := strings.ToLower(a.ID)
		rg := sub + "/resourcegroups/" + strings.ToLower(resourceGroup(a.ID))
		if a.Metadata == nil {
			a.Metadata = map[string]string{}
		}
		a.Metadata["delete_lock"] = boolStr(scopes[id] || scopes[rg] || scopes[sub])
	}
}
