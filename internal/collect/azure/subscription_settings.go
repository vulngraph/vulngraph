package azure

import (
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// settingsAsset accumulates the keys of a one-per-scope settings asset (the
// subscription, the Entra tenant) from several collectors. A setting that
// governs the whole subscription or tenant gets ONE finding there, never one
// per resource it happens to cover.
//
// Every key is written only from a successful read; a failed read leaves it
// absent, which the checks read as unknown. collectAll runs collectors one
// after another, so no locking is needed.
type settingsAsset struct {
	meta map[string]string
}

func newSettingsAsset() *settingsAsset {
	return &settingsAsset{meta: map[string]string{}}
}

// set merges kv into the asset. A nil map (a failed read) adds nothing.
func (s *settingsAsset) set(kv map[string]string) {
	for k, v := range kv {
		s.meta[k] = v
	}
}

// subscriptionAsset returns the azure_subscription settings asset. It is
// emitted even when every contribution failed: an asset with no keys leaves
// every subscription-wide check unevaluable, so an open finding stays open
// instead of reading as fixed because its resource vanished from the sweep.
func (s *settingsAsset) subscriptionAsset(subscriptionID string, now time.Time) asset.Asset {
	return asset.Asset{
		ID:           "/subscriptions/" + subscriptionID,
		Name:         subscriptionID,
		Type:         "azure_subscription",
		Provider:     asset.ProviderAzure,
		AccountID:    subscriptionID,
		Metadata:     s.meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// tenantAsset returns the azure_tenant_settings asset. key (tenantSettingsKey)
// is both its ID and its account ID, so every connector in one tenant that
// uses the same application writes the same asset — a tenant-wide setting is
// one finding however many subscriptions are connected — and a purge of the
// last such connector can remove it by account.
func (s *settingsAsset) tenantAsset(key, tenantID string, now time.Time) asset.Asset {
	return asset.Asset{
		ID:           key,
		Name:         "Entra tenant settings (" + tenantID + ")",
		Type:         tenantSettingsType,
		Provider:     asset.ProviderAzure,
		Region:       "global",
		AccountID:    key,
		Metadata:     s.meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// tenantSettingsAccountKey is the subscription settings key naming the tenant
// settings asset's account. internal/app/connector reads the same literal when
// purging an Azure connector, to decide whether the tenant asset goes too.
const tenantSettingsAccountKey = "tenant_settings_account"

// tenantSettingsType is the one-per-tenant asset carrying Entra ID (Microsoft
// Graph) and tenant-level ARM settings.
const tenantSettingsType = "azure_tenant_settings"
