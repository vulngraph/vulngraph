package azure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
	"github.com/stretchr/testify/require"
)

// fakeWebApps drives both halves of the App Service client: the list pager
// (which, exactly like the real API, does NOT populate SiteConfig) and the
// per-app GetConfiguration call that actually carries minTlsVersion.
type fakeWebApps struct {
	apps    []*armappservice.Site
	configs map[string]string // app name -> minTlsVersion
	errs    map[string]error  // app name -> GetConfiguration failure
	calls   int
}

func (f *fakeWebApps) NewListPager(*armappservice.WebAppsClientListOptions) *runtime.Pager[armappservice.WebAppsClientListResponse] {
	done := false
	return runtime.NewPager(runtime.PagingHandler[armappservice.WebAppsClientListResponse]{
		More: func(armappservice.WebAppsClientListResponse) bool { return !done },
		Fetcher: func(context.Context, *armappservice.WebAppsClientListResponse) (armappservice.WebAppsClientListResponse, error) {
			done = true
			return armappservice.WebAppsClientListResponse{
				WebAppCollection: armappservice.WebAppCollection{Value: f.apps},
			}, nil
		},
	})
}

func (f *fakeWebApps) GetConfiguration(_ context.Context, _, name string, _ *armappservice.WebAppsClientGetConfigurationOptions) (armappservice.WebAppsClientGetConfigurationResponse, error) {
	f.calls++
	if err, ok := f.errs[name]; ok {
		return armappservice.WebAppsClientGetConfigurationResponse{}, err
	}
	v, ok := f.configs[name]
	if !ok {
		return armappservice.WebAppsClientGetConfigurationResponse{}, nil
	}
	tls := armappservice.SupportedTLSVersions(v)
	return armappservice.WebAppsClientGetConfigurationResponse{
		SiteConfigResource: armappservice.SiteConfigResource{
			Properties: &armappservice.SiteConfig{MinTLSVersion: &tls},
		},
	}, nil
}

func site(name string) *armappservice.Site {
	id := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/" + name
	host := name + ".azurewebsites.net"
	httpsOnly := true
	return &armappservice.Site{
		ID:   &id,
		Name: &name,
		// SiteConfig deliberately nil: that is what the real list pager returns,
		// while HTTPSOnly beside it IS populated — the asymmetry that hid the bug.
		Properties: &armappservice.SiteProperties{DefaultHostName: &host, HTTPSOnly: &httpsOnly},
	}
}

// The list payload never carries SiteConfig, so min_tls_version was "" on
// every web app and azure-webapp-no-tls12 could never fire. It now comes from
// GetConfiguration, and stays OFF the asset when that call fails.
func TestCollectWebApps_MinTLSVersionFromConfiguration(t *testing.T) {
	f := &fakeWebApps{
		apps:    []*armappservice.Site{site("modern"), site("legacy"), site("denied")},
		configs: map[string]string{"modern": "1.2", "legacy": "1.0"},
		errs:    map[string]error{"denied": errors.New("AuthorizationFailed")},
	}

	got, err := collectWebAppsWith(context.Background(), f, f, "sub", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, 3, f.calls, "one configuration read per app, not per page")

	byName := map[string]map[string]string{}
	for _, a := range got {
		byName[a.Name] = a.Metadata
	}
	require.Equal(t, "1.2", byName["modern"]["min_tls_version"])
	require.Equal(t, "1.0", byName["legacy"]["min_tls_version"])
	require.NotContains(t, byName["denied"], "min_tls_version",
		"an unreadable site config must not read as a weak TLS floor")

	// The list-populated siblings are unaffected.
	require.Equal(t, "true", byName["modern"]["https_only"])
	require.Equal(t, "true", byName["modern"]["public"])
}

// When the list response does carry SiteConfig, no extra call is made.
func TestMinTLSVersion_PrefersListPayload(t *testing.T) {
	f := &fakeWebApps{configs: map[string]string{"app": "1.0"}}
	app := site("app")
	tls := armappservice.SupportedTLSVersionsOne2
	app.Properties.SiteConfig = &armappservice.SiteConfig{MinTLSVersion: &tls}

	got, ok := minTLSVersion(context.Background(), f, app)
	require.True(t, ok)
	require.Equal(t, "1.2", got)
	require.Zero(t, f.calls)
}

// A resource ID with no resource group cannot be addressed — unknown, not weak.
func TestMinTLSVersion_UnaddressableApp(t *testing.T) {
	f := &fakeWebApps{}
	name := "app"
	id := "/subscriptions/sub/providers/Microsoft.Web/sites/app"
	got, ok := minTLSVersion(context.Background(), f, &armappservice.Site{ID: &id, Name: &name})
	require.False(t, ok)
	require.Empty(t, got)
	require.Zero(t, f.calls)
}

// appHTTPSOnly is minTLSVersion's file-sibling and was left returning "false"
// for an app whose Properties (or HTTPSOnly pointer) ARM did not carry — the
// exact value azure-webapp-no-https-only fires on. HTTPSOnly is a *bool: nil
// means the field was absent from the response, not that it is false, so
// folding the two together let a thin list payload mint a High finding per app.
func TestAppHTTPSOnly_ObservedFlag(t *testing.T) {
	yes, no := true, false

	got, ok := appHTTPSOnly(&armappservice.Site{})
	require.False(t, ok, "no Properties at all is not an observation")
	require.Empty(t, got)

	got, ok = appHTTPSOnly(&armappservice.Site{Properties: &armappservice.SiteProperties{}})
	require.False(t, ok, "a nil HTTPSOnly pointer means ARM omitted the field")
	require.Empty(t, got)

	got, ok = appHTTPSOnly(&armappservice.Site{Properties: &armappservice.SiteProperties{HTTPSOnly: &no}})
	require.True(t, ok, "an explicit false IS an observation and must keep firing")
	require.Equal(t, "false", got)

	got, ok = appHTTPSOnly(&armappservice.Site{Properties: &armappservice.SiteProperties{HTTPSOnly: &yes}})
	require.True(t, ok)
	require.Equal(t, "true", got)
}

func TestCollectWebApps_HTTPSOnlyOmittedWhenUnobserved(t *testing.T) {
	quiet := site("quiet")
	quiet.Properties.HTTPSOnly = nil // ARM returned the site without the field
	plain := site("plain")
	off := false
	plain.Properties.HTTPSOnly = &off

	f := &fakeWebApps{apps: []*armappservice.Site{quiet, plain}}
	got, err := collectWebAppsWith(context.Background(), f, f, "sub", time.Now())
	require.NoError(t, err)

	byName := map[string]map[string]string{}
	for _, a := range got {
		byName[a.Name] = a.Metadata
	}
	require.NotContains(t, byName["quiet"], "https_only",
		"an absent HTTPSOnly must not read as plain HTTP allowed")
	require.Equal(t, "false", byName["plain"]["https_only"],
		"an app that really does allow HTTP must still be reported")
}

func TestAppClientCertRequired(t *testing.T) {
	site := func(enabled *bool, mode *armappservice.ClientCertMode) *armappservice.Site {
		return &armappservice.Site{Properties: &armappservice.SiteProperties{ClientCertEnabled: enabled, ClientCertMode: mode}}
	}
	yes, no := true, false
	required, optional := armappservice.ClientCertModeRequired, armappservice.ClientCertModeOptional
	tests := []struct {
		name   string
		app    *armappservice.Site
		want   string
		wantOK bool
	}{
		{"enabled and required", site(&yes, &required), "true", true},
		{"enabled but optional", site(&yes, &optional), "false", true},
		{"disabled", site(&no, nil), "false", true},
		{"flag not carried", site(nil, &required), "", false},
		{"enabled without mode", site(&yes, nil), "", false},
		{"no properties", &armappservice.Site{}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := appClientCertRequired(tt.app)
			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.want, got)
		})
	}
}
