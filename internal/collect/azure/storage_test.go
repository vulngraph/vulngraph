package azure

import (
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// The third site of the same defect as appHTTPSOnly and ec2HttpTokens: an ARM
// response that omitted EnableHTTPSTrafficOnly was written out as
// https_only="false", which is what azure-storage-https-not-enforced fires on.
// Latent wherever every storage account enforces HTTPS, which is why it went
// unnoticed.
func TestStorageAccountAsset_HTTPSOnlyObserved(t *testing.T) {
	id := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"
	yes, no := true, false
	now := time.Now()

	build := func(props *armstorage.AccountProperties) map[string]string {
		return storageAccountAsset(&armstorage.Account{ID: &id, Properties: props}, "sub", now).Metadata
	}

	require.NotContains(t, build(nil), "https_only",
		"no Properties at all must not read as plain HTTP allowed")
	require.NotContains(t, build(&armstorage.AccountProperties{}), "https_only",
		"a nil EnableHTTPSTrafficOnly means ARM omitted the field")
	require.Equal(t, "false", build(&armstorage.AccountProperties{EnableHTTPSTrafficOnly: &no})["https_only"],
		"an account that really does allow HTTP must still be reported")
	require.Equal(t, "true", build(&armstorage.AccountProperties{EnableHTTPSTrafficOnly: &yes})["https_only"])
}

// The extraction must not change the rest of the mapping.
func TestStorageAccountAsset_PublicTier(t *testing.T) {
	id := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"
	blocked := false
	now := time.Now()

	open := storageAccountAsset(&armstorage.Account{ID: &id, Properties: &armstorage.AccountProperties{}}, "sub", now)
	require.Equal(t, "true", open.Metadata["public"], "AllowBlobPublicAccess=nil is the permissive legacy default")
	require.Equal(t, asset.PublicAccessPossible, open.Metadata["public_access"])

	shut := storageAccountAsset(&armstorage.Account{ID: &id, Properties: &armstorage.AccountProperties{
		AllowBlobPublicAccess: &blocked,
	}}, "sub", now)
	require.Equal(t, "false", shut.Metadata["public"])
	require.NotContains(t, shut.Metadata, "public_access")
	require.Equal(t, "azure_storage_account", shut.Type)
	require.Equal(t, "sub", shut.AccountID)
}
