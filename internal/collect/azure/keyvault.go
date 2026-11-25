package azure

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Key Vault (CIS Azure 8.3.x, 6.1.1.4). The vault listing is ARM; key and
// secret metadata come from ARM's vaults/keys and vaults/secrets lists, which
// return attributes only — never a secret value. Key rotation policies fall
// back to the data plane (GET /keys/{name}/rotationpolicy) when ARM omits
// them, and certificates are listed on the data plane (GET /certificates —
// ARM does not document whether its secrets list includes certificate-backed
// secrets). Those reads need a data-plane role and network reach to the vault;
// when they cannot be made the settings they back stay unknown.

const keyVaultType = "azure_key_vault"

// keyVaultConcurrency bounds the per-vault reads (keys, secrets, diagnostic
// settings, rotation policies) in flight at once.
const keyVaultConcurrency = 8

// certValidityMaxDays is CIS 8.3.11's 12 months, with a day of slack for the
// leap-year and not-before skew a 12-month certificate can carry.
const certValidityMaxDays = 367

var keyVaultDataScopes = []string{"https://vault.azure.net/.default"}

func collectKeyVaults(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time) ([]asset.Asset, error) {
	vc, err := armkeyvault.NewVaultsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("collectKeyVaults: %w", err)
	}
	var vaults []*armkeyvault.Vault
	pager := vc.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("collectKeyVaults: list vaults: %w", err)
		}
		vaults = append(vaults, page.Value...)
	}
	kc, err := armkeyvault.NewKeysClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("collectKeyVaults: %w", err)
	}
	sc, err := armkeyvault.NewSecretsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("collectKeyVaults: %w", err)
	}
	dc, err := armmonitor.NewDiagnosticSettingsClient(cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("collectKeyVaults: %w", err)
	}
	dataPlane := runtime.NewPipeline("graph-azure-collector", "v1.0.0", runtime.PipelineOptions{
		PerRetry: []policy.Policy{runtime.NewBearerTokenPolicy(cred, keyVaultDataScopes, nil)},
	}, nil)

	out := make([]asset.Asset, 0, len(vaults))
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		sem = make(chan struct{}, keyVaultConcurrency)
	)
	logger := log.FromContext(ctx)
	for _, v := range vaults {
		if v == nil || v.ID == nil {
			continue
		}
		a := keyVaultAsset(v, subscriptionID, now)
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().Any("panic", rec).Str("vault", a.ID).Msg("key vault detail read panicked; its key/secret posture is unknown")
				}
			}()
			details := vaultDetails(ctx, kc, sc, dc, dataPlane, v, now)
			mu.Lock()
			defer mu.Unlock()
			for k, val := range details {
				a.Metadata[k] = val
			}
			out = append(out, a)
		}()
	}
	wg.Wait()
	return out, nil
}

// keyVaultAsset renders the vault-level settings. Fields the ARM response
// omits take their documented defaults: RBAC authorization false, purge
// protection off (it can only ever be set true), soft delete on, public
// network access enabled, no network ACLs (allow all), no private endpoints.
func keyVaultAsset(v *armkeyvault.Vault, subscriptionID string, now time.Time) asset.Asset {
	md := map[string]string{}
	if p := v.Properties; p != nil {
		md["rbac_authorization"] = strconv.FormatBool(p.EnableRbacAuthorization != nil && *p.EnableRbacAuthorization)
		md["purge_protection"] = strconv.FormatBool(p.EnablePurgeProtection != nil && *p.EnablePurgeProtection)
		md["soft_delete"] = strconv.FormatBool(p.EnableSoftDelete == nil || *p.EnableSoftDelete)
		md["public_network_access"] = "Enabled"
		if strings.EqualFold(strVal(p.PublicNetworkAccess), "disabled") {
			md["public_network_access"] = "Disabled"
		}
		md["network_default_action"] = "Allow"
		if p.NetworkACLs != nil && p.NetworkACLs.DefaultAction != nil {
			md["network_default_action"] = string(*p.NetworkACLs.DefaultAction)
		}
		approved := 0
		for _, c := range p.PrivateEndpointConnections {
			if c != nil && c.Properties != nil && c.Properties.PrivateLinkServiceConnectionState != nil &&
				c.Properties.PrivateLinkServiceConnectionState.Status != nil &&
				*c.Properties.PrivateLinkServiceConnectionState.Status == armkeyvault.PrivateEndpointServiceConnectionStatusApproved {
				approved++
			}
		}
		md["private_endpoint_count"] = strconv.Itoa(approved)
	}
	return asset.Asset{
		ID:           *v.ID,
		Name:         strVal(v.Name),
		Type:         keyVaultType,
		Provider:     asset.ProviderAzure,
		Region:       strVal(v.Location),
		AccountID:    subscriptionID,
		Tags:         azTags(v.Tags),
		Metadata:     md,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// vaultDetails reads one vault's keys, secrets and diagnostic settings. Each
// read that fails leaves only its own keys absent.
func vaultDetails(ctx context.Context, kc *armkeyvault.KeysClient, sc *armkeyvault.SecretsClient, dc *armmonitor.DiagnosticSettingsClient, dataPlane runtime.Pipeline, v *armkeyvault.Vault, now time.Time) map[string]string {
	out := map[string]string{}
	rg, name := resourceGroup(*v.ID), strVal(v.Name)
	warn := func(read string, err error) {
		log.FromContext(ctx).Warn().Err(err).Str("vault", *v.ID).Str("read", read).Int("status", statusCode(err)).
			Msg("key vault read skipped; settings it backs are unknown")
	}
	var data *restClient
	if v.Properties != nil && strVal(v.Properties.VaultURI) != "" {
		data = &restClient{pl: dataPlane, base: strings.TrimSuffix(*v.Properties.VaultURI, "/")}
	}
	if keys, err := listVaultKeys(ctx, kc, rg, name); err != nil {
		warn("keys", err)
	} else {
		for k, val := range keySettings(ctx, keys, data) {
			out[k] = val
		}
	}
	if secrets, err := listVaultSecrets(ctx, sc, rg, name); err != nil {
		warn("secrets", err)
	} else {
		for k, val := range secretSettings(secrets) {
			out[k] = val
		}
	}
	if data != nil {
		if certs, err := listAll[vaultCertificate](ctx, data, "/certificates?api-version=7.4", nil); err != nil {
			warn("certificates (data plane)", err)
		} else {
			for k, val := range certificateSettings(certs, now) {
				out[k] = val
			}
		}
	}
	if settings, err := listDiagnosticSettings(ctx, dc, *v.ID); err != nil {
		warn("diagnostic settings", err)
	} else {
		out["audit_logging_enabled"] = strconv.FormatBool(vaultAuditLogged(settings))
		out["diagnostic_setting_count"] = strconv.Itoa(len(exportingSettings(settings)))
	}
	return out
}

func listVaultKeys(ctx context.Context, c *armkeyvault.KeysClient, rg, vault string) ([]*armkeyvault.Key, error) {
	var out []*armkeyvault.Key
	pager := c.NewListPager(rg, vault, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listVaultKeys: %w", err)
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func listVaultSecrets(ctx context.Context, c *armkeyvault.SecretsClient, rg, vault string) ([]*armkeyvault.Secret, error) {
	var out []*armkeyvault.Secret
	pager := c.NewListPager(rg, vault, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listVaultSecrets: %w", err)
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

// keySettings renders CIS 8.3.1/8.3.2 (enabled keys without an expiry) and
// 8.3.9 (enabled keys without an automatic Rotate action). A disabled key
// cannot be used, so it is not a gap; an omitted enabled flag is the default,
// enabled. Rotation is only claimed when every enabled key's policy was read.
func keySettings(ctx context.Context, keys []*armkeyvault.Key, data *restClient) map[string]string {
	var noExpiry, noRotation []string
	rotationKnown := true
	for _, k := range keys {
		if k == nil || k.Properties == nil {
			continue
		}
		attrs := k.Properties.Attributes
		if attrs != nil && attrs.Enabled != nil && !*attrs.Enabled {
			continue
		}
		name := strVal(k.Name)
		if attrs == nil || attrs.Expires == nil {
			noExpiry = append(noExpiry, name)
		}
		rotates, known := keyRotates(ctx, k, data)
		switch {
		case !known:
			rotationKnown = false
		case !rotates:
			noRotation = append(noRotation, name)
		}
	}
	out := map[string]string{
		"keys_without_expiry_count": strconv.Itoa(len(noExpiry)),
		"keys_without_expiry":       sample(noExpiry),
	}
	if rotationKnown {
		out["keys_without_rotation_count"] = strconv.Itoa(len(noRotation))
		out["keys_without_rotation"] = sample(noRotation)
	}
	return out
}

// keyRotates reports whether the key has a lifetime action of type Rotate.
// ARM returns the rotation policy on the key when one is set; when it omits
// it, the data-plane policy decides, and an unreadable data plane is unknown.
func keyRotates(ctx context.Context, k *armkeyvault.Key, data *restClient) (rotates, known bool) {
	if rp := k.Properties.RotationPolicy; rp != nil && len(rp.LifetimeActions) > 0 {
		return lifetimeRotates(rp.LifetimeActions), true
	}
	if data == nil {
		return false, false
	}
	var policy struct {
		LifetimeActions []struct {
			Action struct {
				Type string `json:"type"`
			} `json:"action"`
		} `json:"lifetimeActions"`
	}
	err := data.getJSON(ctx, "/keys/"+strVal(k.Name)+"/rotationpolicy?api-version=7.4", nil, &policy)
	if statusCode(err) == http.StatusNotFound {
		return false, true // no rotation policy on the key
	}
	if err != nil {
		return false, false
	}
	for _, la := range policy.LifetimeActions {
		if strings.EqualFold(la.Action.Type, "rotate") {
			return true, true
		}
	}
	return false, true
}

func lifetimeRotates(actions []*armkeyvault.LifetimeAction) bool {
	for _, la := range actions {
		if la != nil && la.Action != nil && la.Action.Type != nil &&
			strings.EqualFold(string(*la.Action.Type), string(armkeyvault.KeyRotationPolicyActionTypeRotate)) {
			return true
		}
	}
	return false
}

// secretSettings renders CIS 8.3.3/8.3.4: enabled secrets without an expiry.
// A disabled secret cannot be read, so it is not a gap; an omitted enabled
// flag is the default, enabled.
func secretSettings(secrets []*armkeyvault.Secret) map[string]string {
	var noExpiry []string
	for _, s := range secrets {
		if s == nil || s.Properties == nil {
			continue
		}
		attrs := s.Properties.Attributes
		if attrs != nil && attrs.Enabled != nil && !*attrs.Enabled {
			continue
		}
		if attrs == nil || attrs.Expires == nil {
			noExpiry = append(noExpiry, strVal(s.Name))
		}
	}
	return map[string]string{
		"secrets_without_expiry_count": strconv.Itoa(len(noExpiry)),
		"secrets_without_expiry":       sample(noExpiry),
	}
}

// vaultCertificate is one item of the data-plane certificate list (current
// version attributes; never key material).
type vaultCertificate struct {
	ID         string `json:"id"`
	Attributes struct {
		Enabled   *bool  `json:"enabled"`
		NotBefore *int64 `json:"nbf"`
		Expires   *int64 `json:"exp"`
		Created   *int64 `json:"created"`
	} `json:"attributes"`
}

// certificateSettings renders CIS 8.3.11: current, enabled certificates whose
// issued validity (not-before to expiry) exceeds 12 months — the outcome the
// issuance policy's validity_months produces. Read from the data-plane
// certificate list, which needs a data-plane read role and network reach;
// when that read fails the keys stay absent (unknown), never zero.
func certificateSettings(certs []vaultCertificate, now time.Time) map[string]string {
	var long []string
	for _, c := range certs {
		a := c.Attributes
		if (a.Enabled != nil && !*a.Enabled) || a.Expires == nil || time.Unix(*a.Expires, 0).Before(now) {
			continue
		}
		start := a.Created
		if a.NotBefore != nil {
			start = a.NotBefore
		}
		if start != nil && time.Unix(*a.Expires, 0).Sub(time.Unix(*start, 0)) > certValidityMaxDays*24*time.Hour {
			long = append(long, lastSegment(c.ID))
		}
	}
	return map[string]string{
		"certs_validity_over_12_months_count": strconv.Itoa(len(long)),
		"certs_validity_over_12_months":       sample(long),
	}
}

// vaultAuditLogged reports whether a diagnostic setting exports the vault's
// AuditEvent log (by name, or through the audit / allLogs category group).
func vaultAuditLogged(settings []*armmonitor.DiagnosticSettingsResource) bool {
	cats := enabledCategories(exportingSettings(settings))
	for _, c := range []string{"auditevent", "group:audit", "group:alllogs"} {
		if _, ok := cats[c]; ok {
			return true
		}
	}
	return false
}
