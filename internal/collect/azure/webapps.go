package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// webAppConfigAPI reads a single web app's site configuration. The list pager
// does NOT populate Properties.SiteConfig (even though its siblings HTTPSOnly
// and ClientCertEnabled ARE populated), so minTLSVersion
// needs this separate call.
type webAppConfigAPI interface {
	GetConfiguration(ctx context.Context, resourceGroupName, name string, options *armappservice.WebAppsClientGetConfigurationOptions) (armappservice.WebAppsClientGetConfigurationResponse, error)
}

// collectWebApps pulls all App Service web apps. Every web app has a default
// azurewebsites.net hostname making it internet-reachable by default —
// flagged public=true so InternetReachability emits exposed_to_internet edges.
func collectWebApps(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time) ([]asset.Asset, error) {
	client, err := armappservice.NewWebAppsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("collectWebApps: client: %w", err)
	}
	return collectWebAppsWith(ctx, client, client, subscriptionID, now)
}

// webAppLister is the list half of the client, split out so tests can drive
// both halves without an Azure endpoint.
type webAppLister interface {
	NewListPager(options *armappservice.WebAppsClientListOptions) *runtime.Pager[armappservice.WebAppsClientListResponse]
}

func collectWebAppsWith(ctx context.Context, lister webAppLister, cfgClient webAppConfigAPI, subscriptionID string, now time.Time) ([]asset.Asset, error) {
	var assets []asset.Asset
	pager := lister.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("collectWebApps: list: %w", err)
		}
		for _, app := range page.Value {
			if app.ID == nil {
				continue
			}
			defaultHost := ""
			if app.Properties != nil {
				defaultHost = strVal(app.Properties.DefaultHostName)
			}
			assets = append(assets, asset.Asset{
				ID:        *app.ID,
				Name:      strVal(app.Name),
				Type:      "azure_webapp",
				Provider:  asset.ProviderAzure,
				Region:    strVal(app.Location),
				AccountID: subscriptionID,
				Domain:    defaultHost,
				Endpoint:  httpsURL(defaultHost),
				Tags:      azTags(app.Tags),
				Metadata: func() map[string]string {
					m := map[string]string{
						"public":              "true", // azurewebsites.net is always internet-reachable
						"state":               appState(app),
						"client_cert_enabled": appClientCertEnabled(app),
					}
					// Omitted when ARM did not carry HTTPSOnly: an absent
					// https_only must not read as "plain HTTP allowed".
					if v, ok := appClientCertRequired(app); ok {
						m["client_cert_required"] = v
					}
					if v, ok := appHTTPSOnly(app); ok {
						m["https_only"] = v
					}
					// Omitted when the site config could not be read: an absent
					// min_tls_version must not read as "TLS 1.0 allowed".
					if v, ok := minTLSVersion(ctx, cfgClient, app); ok {
						m["min_tls_version"] = v
					}
					if app.Identity != nil && app.Identity.PrincipalID != nil && *app.Identity.PrincipalID != "" {
						m["exec_role"] = managedIdentityID(*app.Identity.PrincipalID)
					}
					return m
				}(),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
	}
	return assets, nil
}

func appState(app *armappservice.Site) string {
	if app.Properties == nil || app.Properties.State == nil {
		return ""
	}
	return *app.Properties.State
}

// appHTTPSOnly returns the app's HTTPS-only setting. HTTPSOnly is a *bool, so
// nil means ARM omitted the field — not that it is false. The bool return is
// false in that case so the caller omits the key rather than writing "false",
// which is exactly the value azure-webapp-no-https-only fires on.
func appHTTPSOnly(app *armappservice.Site) (string, bool) {
	if app.Properties == nil || app.Properties.HTTPSOnly == nil {
		return "", false
	}
	return boolStr(*app.Properties.HTTPSOnly), true
}

// minTLSVersion returns the app's configured minimum TLS version. The list
// response almost never carries SiteConfig, so it falls back to
// GetConfiguration. The bool is false when the value could not be observed —
// the caller then omits the key rather than writing a blank that the
// azure-webapp-no-tls12 check would read as a violation.
func minTLSVersion(ctx context.Context, client webAppConfigAPI, app *armappservice.Site) (string, bool) {
	if app.Properties != nil && app.Properties.SiteConfig != nil && app.Properties.SiteConfig.MinTLSVersion != nil {
		return string(*app.Properties.SiteConfig.MinTLSVersion), true
	}
	if client == nil || app.ID == nil || app.Name == nil {
		return "", false
	}
	rg := resourceGroup(*app.ID)
	if rg == "" {
		return "", false
	}
	resp, err := client.GetConfiguration(ctx, rg, *app.Name, nil)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("webapp", *app.ID).
			Msg("azure webapp site config unreadable; min_tls_version omitted")
		return "", false
	}
	if resp.Properties == nil || resp.Properties.MinTLSVersion == nil {
		return "", false
	}
	return string(*resp.Properties.MinTLSVersion), true
}

// appClientCertRequired reports whether every client must present a
// certificate (ClientCertEnabled with mode Required). It is omitted when ARM
// did not carry the flag, or carried it enabled without a mode, so an unread
// setting cannot read as "certificates not required".
func appClientCertRequired(app *armappservice.Site) (string, bool) {
	if app.Properties == nil || app.Properties.ClientCertEnabled == nil {
		return "", false
	}
	if !*app.Properties.ClientCertEnabled {
		return "false", true
	}
	if app.Properties.ClientCertMode == nil {
		return "", false
	}
	return boolStr(*app.Properties.ClientCertMode == armappservice.ClientCertModeRequired), true
}

func appClientCertEnabled(app *armappservice.Site) string {
	if app.Properties == nil || app.Properties.ClientCertEnabled == nil {
		return "false"
	}
	return boolStr(*app.Properties.ClientCertEnabled)
}
