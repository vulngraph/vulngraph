package azure

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectStorage pulls all storage accounts. Accounts with public blob access
// enabled are flagged public=true and get an Endpoint set so they appear in
// ListExternal() as Nuclei scan targets.
func collectStorage(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time) ([]asset.Asset, error) {
	client, err := armstorage.NewAccountsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("collectStorage: client: %w", err)
	}

	var assets []asset.Asset
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("collectStorage: list: %w", err)
		}
		for _, acct := range page.Value {
			if acct.ID == nil {
				continue
			}
			assets = append(assets, storageAccountAsset(acct, subscriptionID, now))
		}
	}
	services, err := newARMStorageServices(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("collectStorage: %w", err)
	}
	readStorageServices(ctx, services, assets)
	return assets, nil
}

// storageAccountAsset maps one ARM storage account onto an asset. Split out of
// the pager loop so the metadata rules are unit-testable without an Azure
// endpoint, the same shape collectWebAppsWith uses.
func storageAccountAsset(acct *armstorage.Account, subscriptionID string, now time.Time) asset.Asset {
	blobEndpoint := ""
	isPublic := false
	if acct.Properties != nil {
		if acct.Properties.PrimaryEndpoints != nil {
			blobEndpoint = strVal(acct.Properties.PrimaryEndpoints.Blob)
		}
		// AllowBlobPublicAccess=nil means the default (allowed) in older accounts.
		if acct.Properties.AllowBlobPublicAccess == nil || *acct.Properties.AllowBlobPublicAccess {
			isPublic = true
		}
	}
	meta := map[string]string{
		"kind": azStorageKind(acct.Kind),
		"sku":  storageSKU(acct),
	}
	if acct.Properties == nil {
		meta["public_access"] = publicAccessUnknown
	} else {
		meta["public"] = boolStr(isPublic)
	}
	// The third instance of the same shape as appHTTPSOnly / minTLSVersion:
	// folding "ARM did not return the field" into `false` hands
	// azure-storage-https-not-enforced (`https_only == "false"`) a violation the
	// collector invented. Omitted when unobserved. Latent wherever every
	// storage account enforces HTTPS, which is how it survived.
	if acct.Properties != nil && acct.Properties.EnableHTTPSTrafficOnly != nil {
		meta["https_only"] = boolStr(*acct.Properties.EnableHTTPSTrafficOnly)
	}
	// AllowBlobPublicAccess only *permits* containers to be public — actual
	// container access levels aren't collected, so exposure is possible, not
	// confirmed (the Azure twin of S3's no-public-access-block case).
	if isPublic {
		meta["public_access"] = asset.PublicAccessPossible
	}
	if acct.Properties != nil {
		storagePosture(acct.Properties, meta)
	}
	return asset.Asset{
		ID:           *acct.ID,
		Name:         strVal(acct.Name),
		Type:         "azure_storage_account",
		Provider:     asset.ProviderAzure,
		Region:       strVal(acct.Location),
		AccountID:    subscriptionID,
		Endpoint:     blobEndpoint,
		Tags:         azTags(acct.Tags),
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// storagePosture records the CIS 9.3 account settings carried by the list
// response. A nil field is written as its documented ARM interpretation only
// where that interpretation never changed (shared key: null is true; OAuth
// default: null is false; minimum TLS: null is TLS 1.0; public network access:
// Disabled and SecuredByPerimeter are only ever set explicitly, so null is
// Enabled). Cross-tenant replication's default flipped on a documented date,
// so a nil value is resolved from the account's creation time (unknown
// without one). Fields ARM marks optional without a stated default (bypass)
// are omitted when nil, so an unset value reads as unknown rather than as a
// violation.
func storagePosture(p *armstorage.AccountProperties, meta map[string]string) {
	meta["allow_shared_key_access"] = boolStr(p.AllowSharedKeyAccess == nil || *p.AllowSharedKeyAccess)
	meta["default_to_oauth"] = boolStr(p.DefaultToOAuthAuthentication != nil && *p.DefaultToOAuthAuthentication)
	meta["minimum_tls_version"] = string(armstorage.MinimumTLSVersionTLS10)
	if p.MinimumTLSVersion != nil {
		meta["minimum_tls_version"] = string(*p.MinimumTLSVersion)
	}
	meta["public_network_access"] = string(armstorage.PublicNetworkAccessEnabled)
	if p.PublicNetworkAccess != nil {
		meta["public_network_access"] = string(*p.PublicNetworkAccess)
	}
	switch {
	case p.AllowCrossTenantReplication != nil:
		meta["allow_cross_tenant_replication"] = boolStr(*p.AllowCrossTenantReplication)
	case p.CreationTime != nil:
		meta["allow_cross_tenant_replication"] = boolStr(p.CreationTime.Before(crossTenantReplicationDefaultOff))
	}
	if rs := p.NetworkRuleSet; rs != nil {
		if rs.DefaultAction != nil {
			meta["network_default_action"] = string(*rs.DefaultAction)
		}
		if rs.Bypass != nil {
			meta["network_bypass"] = string(*rs.Bypass)
		}
	}
	// A key policy is never defaulted: absent means no expiry reminder is set.
	meta["key_expiration_days"] = ""
	if p.KeyPolicy != nil && p.KeyPolicy.KeyExpirationPeriodInDays != nil {
		meta["key_expiration_days"] = strconv.Itoa(int(*p.KeyPolicy.KeyExpirationPeriodInDays))
	}
	// Hierarchical namespace is off unless chosen at creation.
	meta["hns_enabled"] = boolStr(p.IsHnsEnabled != nil && *p.IsHnsEnabled)
	// keyCreationTime records when each key was created or last regenerated.
	// A missing object says nothing, so both keys stay unknown. Within a
	// returned object Azure documents a null key time as "not yet set" on
	// older accounts, and rotating the key is what sets it: such a key has
	// not been rotated since tracking began, so it is recorded as
	// keyUntracked rather than read as fresh.
	if kc := p.KeyCreationTime; kc != nil {
		meta["key1_created"] = keyCreated(kc.Key1)
		meta["key2_created"] = keyCreated(kc.Key2)
	}
	// A nil list means ARM did not return the field; only a returned (possibly
	// empty) list is a count.
	if p.PrivateEndpointConnections == nil {
		return
	}
	approved := 0
	for _, pec := range p.PrivateEndpointConnections {
		if pec != nil && pec.Properties != nil && pec.Properties.PrivateLinkServiceConnectionState != nil &&
			pec.Properties.PrivateLinkServiceConnectionState.Status != nil &&
			*pec.Properties.PrivateLinkServiceConnectionState.Status == armstorage.PrivateEndpointServiceConnectionStatusApproved {
			approved++
		}
	}
	meta["private_endpoint_count"] = strconv.Itoa(approved)
}

// crossTenantReplicationDefaultOff is when an unset AllowCrossTenantReplication
// started meaning false: Azure documents null as allowing cross-tenant
// replication on accounts created before 15 December 2023 and as disallowing
// it on accounts created after.
var crossTenantReplicationDefaultOff = time.Date(2023, 12, 15, 0, 0, 0, 0, time.UTC)

// keyUntracked marks an account key whose creation predates key-creation
// tracking (see storagePosture).
const keyUntracked = "untracked"

func keyCreated(t *time.Time) string {
	if t == nil {
		return keyUntracked
	}
	return t.UTC().Format(time.RFC3339)
}

// azStorageKind dereferences the account Kind, tolerating nil so one malformed
// account cannot panic and abort the whole storage sync.
func azStorageKind(k *armstorage.Kind) string {
	if k == nil {
		return ""
	}
	return string(*k)
}

func storageSKU(acct *armstorage.Account) string {
	if acct.SKU == nil || acct.SKU.Name == nil {
		return ""
	}
	return string(*acct.SKU.Name)
}
