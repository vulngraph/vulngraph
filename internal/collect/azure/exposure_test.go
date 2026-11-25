package azure

import (
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/checks"
)

// A resource returned without its properties block has no observed exposure:
// "public" (or internet_exportable) is left out so its public check is not
// evaluable, and the tier is unknown rather than private.
func TestExposureWithoutPropertiesIsUnknown(t *testing.T) {
	evaluable := func(t *testing.T, checkID string, a asset.Asset) bool {
		t.Helper()
		c, ok := checks.Default().ByID(checkID)
		require.True(t, ok)
		return c.Evaluable(a)
	}
	az := func(typ string, md map[string]string) asset.Asset {
		return asset.Asset{ID: "r", Type: typ, Provider: asset.ProviderAzure, Metadata: md}
	}

	t.Run("storage account", func(t *testing.T) {
		md := storageAccountAsset(&armstorage.Account{ID: to.Ptr("acct")}, "s", time.Now()).Metadata
		require.NotContains(t, md, "public")
		require.Equal(t, publicAccessUnknown, md["public_access"])
		require.False(t, evaluable(t, "azure-storage-public-blob-access", az("azure_storage_account", md)))

		md = storageAccountAsset(&armstorage.Account{ID: to.Ptr("acct"), Properties: &armstorage.AccountProperties{
			AllowBlobPublicAccess: to.Ptr(false),
		}}, "s", time.Now()).Metadata
		require.Equal(t, "false", md["public"])
		require.NotContains(t, md, "public_access")
	})

	t.Run("sql server", func(t *testing.T) {
		md := sqlServerExposure(&armsql.Server{})
		require.NotContains(t, md, "public")
		require.Equal(t, publicAccessUnknown, md["public_access"])
		require.False(t, evaluable(t, "azure-sql-server-public-network-access", az("azure_sql_server", md)))

		md = sqlServerExposure(&armsql.Server{Properties: &armsql.ServerProperties{
			PublicNetworkAccess: to.Ptr(armsql.ServerNetworkAccessFlagDisabled),
		}})
		require.Equal(t, "false", md["public"])
		require.Empty(t, md["public_access"])
		require.Equal(t, "true", sqlServerExposure(&armsql.Server{Properties: &armsql.ServerProperties{}})["public"],
			"an unset PublicNetworkAccess is Azure's default, Enabled")
	})

	t.Run("load balancer", func(t *testing.T) {
		require.NotContains(t, lbMetadata(&armnetwork.LoadBalancer{}), "public")
		require.Equal(t, "false", lbMetadata(&armnetwork.LoadBalancer{Properties: &armnetwork.LoadBalancerPropertiesFormat{}})["public"])
		require.Equal(t, "true", lbMetadata(&armnetwork.LoadBalancer{Properties: &armnetwork.LoadBalancerPropertiesFormat{
			FrontendIPConfigurations: []*armnetwork.FrontendIPConfiguration{{Properties: &armnetwork.FrontendIPConfigurationPropertiesFormat{
				PublicIPAddress: &armnetwork.PublicIPAddress{ID: to.Ptr("pip")},
			}}},
		}})["public"])
		require.NotContains(t, lbMetadata(&armnetwork.LoadBalancer{Properties: &armnetwork.LoadBalancerPropertiesFormat{
			FrontendIPConfigurations: []*armnetwork.FrontendIPConfiguration{{}},
		}}), "public", "a frontend without properties may be the public one")
		require.Equal(t, "true", lbMetadata(&armnetwork.LoadBalancer{Properties: &armnetwork.LoadBalancerPropertiesFormat{
			FrontendIPConfigurations: []*armnetwork.FrontendIPConfiguration{{}, {Properties: &armnetwork.FrontendIPConfigurationPropertiesFormat{
				PublicIPAddress: &armnetwork.PublicIPAddress{ID: to.Ptr("pip")},
			}}},
		}})["public"])
	})

	t.Run("public ip", func(t *testing.T) {
		require.NotContains(t, publicIPMetadata(&armnetwork.PublicIPAddress{}), "public")
		require.Equal(t, "false", publicIPMetadata(&armnetwork.PublicIPAddress{
			Properties: &armnetwork.PublicIPAddressPropertiesFormat{}})["public"])
		require.Equal(t, "true", publicIPMetadata(&armnetwork.PublicIPAddress{
			Properties: &armnetwork.PublicIPAddressPropertiesFormat{IPAddress: to.Ptr("20.1.1.1")}})["public"])
	})

	t.Run("disk", func(t *testing.T) {
		md := diskMetadata(&armcompute.Disk{})
		require.NotContains(t, md, "internet_exportable")
		require.Equal(t, publicAccessUnknown, md["public_access"])
		require.False(t, evaluable(t, "azure-disk-internet-exportable", az("azure_disk", md)))

		md = diskMetadata(&armcompute.Disk{Properties: &armcompute.DiskProperties{
			PublicNetworkAccess: to.Ptr(armcompute.PublicNetworkAccessEnabled),
			NetworkAccessPolicy: to.Ptr(armcompute.NetworkAccessPolicyAllowAll),
		}})
		require.Equal(t, "true", md["internet_exportable"])
		require.Equal(t, asset.PublicAccessPossible, md["public_access"])
	})
}
