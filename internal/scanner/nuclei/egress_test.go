package nuclei

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	updateutils "github.com/projectdiscovery/utils/update"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The SDK's version check to api.pdtm.sh runs on the first engine of every
// process whatever the options say, so it must meet the refusing transport,
// in every mode and before any request leaves the process. UpdateIgnoreFile
// goes through the same installer client as NucleiSDKVersionCheck.
func TestVersionCheckIsAlwaysRefused(t *testing.T) {
	require.IsType(t, refuseVersionCheck{}, updateutils.DefaultHttpClient.Transport)

	resp, err := updateutils.DefaultHttpClient.Get("https://api.pdtm.sh/api/v1/tools/nuclei")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.ErrorIs(t, err, errVersionCheckRefused)

	require.ErrorIs(t, installer.UpdateIgnoreFile(), errVersionCheckRefused)
}

// An invalid NUCLEI_TEMPLATES_PROXY is refused without echoing it: it may
// carry the proxy's credentials.
func TestTemplatesProxyErrorOmitsValue(t *testing.T) {
	err := CheckEgressEnv(func(k string) string {
		if k == TemplatesProxyEnv {
			return "socks5://user:s3cret-value@proxy.internal:1080"
		}
		return ""
	})
	require.ErrorContains(t, err, TemplatesProxyEnv)
	assert.NotContains(t, err.Error(), "s3cret-value")
}

func TestEgressConfigFromEnv(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	pinnedDir := filepath.Join(home, "nuclei-templates-"+pinnedTemplates.Version+"-"+pinnedTemplates.SHA256)
	const otherSum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name    string
		env     map[string]string
		want    egressConfig
		wantErr string
	}{
		{
			name: "unset: pinned release downloaded, interactsh off",
			env:  map[string]string{},
			want: egressConfig{templatesDir: pinnedDir, release: pinnedTemplates},
		},
		{
			name: "templates dir supplied: used as-is, never downloaded",
			env:  map[string]string{TemplatesDirEnv: " /opt/nuclei-templates "},
			want: egressConfig{templatesDir: "/opt/nuclei-templates", operatorDir: true, release: pinnedTemplates},
		},
		{
			name: "release override",
			env:  map[string]string{TemplatesVersionEnv: "v10.6.0", TemplatesSHA256Env: strings.ToUpper(otherSum)},
			want: egressConfig{
				templatesDir: filepath.Join(home, "nuclei-templates-v10.6.0-"+otherSum),
				release:      templateRelease{Version: "v10.6.0", SHA256: otherSum},
			},
		},
		{
			name:    "release override needs both variables; no directory, so scans fail",
			env:     map[string]string{TemplatesVersionEnv: "v10.6.0"},
			want:    egressConfig{},
			wantErr: TemplatesSHA256Env,
		},
		{
			name:    "release override with a path in the version",
			env:     map[string]string{TemplatesVersionEnv: "../v10.6.0", TemplatesSHA256Env: otherSum},
			want:    egressConfig{},
			wantErr: TemplatesVersionEnv,
		},
		{
			name:    "release override with a short checksum",
			env:     map[string]string{TemplatesVersionEnv: "v10.6.0", TemplatesSHA256Env: "abc"},
			want:    egressConfig{},
			wantErr: TemplatesSHA256Env,
		},
		{
			name:    "templates dir and release override together",
			env:     map[string]string{TemplatesDirEnv: "/opt/t", TemplatesVersionEnv: "v10.6.0", TemplatesSHA256Env: otherSum},
			want:    egressConfig{release: templateRelease{Version: "v10.6.0", SHA256: otherSum}},
			wantErr: TemplatesDirEnv,
		},
		{
			name: "download switch",
			env:  map[string]string{TemplatesDownloadDisabledEnv: "1"},
			want: egressConfig{templatesDir: pinnedDir, release: pinnedTemplates, downloadDisabled: true},
		},
		{
			name: "interactsh opt-in",
			env:  map[string]string{InteractshEnabledEnv: "YES"},
			want: egressConfig{templatesDir: pinnedDir, release: pinnedTemplates, interactsh: true},
		},
		{
			name: "offline mode: no download, no interactsh even when opted in",
			env:  map[string]string{"OFFLINE_MODE": "on", InteractshEnabledEnv: "true"},
			want: egressConfig{templatesDir: pinnedDir, release: pinnedTemplates, downloadDisabled: true},
		},
		{
			name:    "typo in the interactsh switch is an error and keeps it off",
			env:     map[string]string{InteractshEnabledEnv: "ture"},
			want:    egressConfig{templatesDir: pinnedDir, release: pinnedTemplates},
			wantErr: InteractshEnabledEnv,
		},
		{
			name:    "a retired switch is an error, not silently ignored",
			env:     map[string]string{"NUCLEI_UPDATE_DISABLED": "true"},
			want:    egressConfig{templatesDir: pinnedDir, release: pinnedTemplates},
			wantErr: TemplatesDownloadDisabledEnv,
		},
		{
			name:    "retired interactsh switch",
			env:     map[string]string{"NUCLEI_INTERACTSH_DISABLED": "false"},
			want:    egressConfig{templatesDir: pinnedDir, release: pinnedTemplates},
			wantErr: InteractshEnabledEnv,
		},
		{
			name: "templates proxy, with credentials",
			env:  map[string]string{TemplatesProxyEnv: " http://user:pass@proxy.internal:3128 "},
			want: egressConfig{templatesDir: pinnedDir, release: pinnedTemplates, templatesProxy: &url.URL{
				Scheme: "http", User: url.UserPassword("user", "pass"), Host: "proxy.internal:3128",
			}},
		},
		{
			name: "the environment's proxy is not the templates proxy",
			env:  map[string]string{"HTTPS_PROXY": "http://proxy.internal:3128", "HTTP_PROXY": "http://proxy.internal:3128"},
			want: egressConfig{templatesDir: pinnedDir, release: pinnedTemplates, envProxyVar: "HTTPS_PROXY"},
		},
		{
			name: "a lower-case environment proxy is named too",
			env:  map[string]string{"http_proxy": "http://proxy.internal:3128"},
			want: egressConfig{templatesDir: pinnedDir, release: pinnedTemplates, envProxyVar: "http_proxy"},
		},
		{
			name:    "templates proxy without a scheme",
			env:     map[string]string{TemplatesProxyEnv: "proxy.internal:3128"},
			want:    egressConfig{templatesDir: pinnedDir, release: pinnedTemplates},
			wantErr: TemplatesProxyEnv,
		},
		{
			name:    "templates proxy with an unsupported scheme",
			env:     map[string]string{TemplatesProxyEnv: "ftp://proxy.internal"},
			want:    egressConfig{templatesDir: pinnedDir, release: pinnedTemplates},
			wantErr: TemplatesProxyEnv,
		},
		{
			name:    "templates proxy with a path",
			env:     map[string]string{TemplatesProxyEnv: "http://proxy.internal:3128/x"},
			want:    egressConfig{templatesDir: pinnedDir, release: pinnedTemplates},
			wantErr: TemplatesProxyEnv,
		},
		{
			name:    "typo in OFFLINE_MODE is an error and keeps everything off",
			env:     map[string]string{"OFFLINE_MODE": "enabled", InteractshEnabledEnv: "true"},
			want:    egressConfig{templatesDir: pinnedDir, release: pinnedTemplates, downloadDisabled: true},
			wantErr: "OFFLINE_MODE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			got, err := egressConfigFromEnv(getenv)
			assert.Equal(t, tc.want, got)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.ErrorContains(t, CheckEgressEnv(getenv), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.NoError(t, CheckEgressEnv(getenv))
		})
	}
}

// Every engine turns the SDK's own template installer off (it fetches the
// latest, unpinned release) and carries interactsh options of its own, never
// the SDK's defaults, which turn it on.
func TestEgressOptions(t *testing.T) {
	assert.Len(t, egressConfig{}.options(), 2, "updates off and interactsh set")
	assert.Len(t, egressConfig{interactsh: true}.options(), 2, "updates off and interactsh set")
}

// Interactsh sends callbacks to the public oast.* servers, so the engine gets
// it only when the config opted in.
func TestInteractshOptions(t *testing.T) {
	off := egressConfig{}.interactshOptions()
	assert.True(t, off.NoInteractsh, "interactsh is off by default")
	assert.Positive(t, off.CacheSize, "the engine builds its client even when off; a zero cache panics")

	on := egressConfig{interactsh: true}.interactshOptions()
	assert.False(t, on.NoInteractsh, "interactsh is on when opted in")
	assert.Positive(t, on.CacheSize)
}

// Every engine this package builds must carry egressOptions, or one code path
// (template validation, template test, estate scan) quietly keeps downloading
// the latest templates and calling interactsh, which are off by default.
func TestEveryEngineCarriesEgressOptions(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	engines := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		chunks := strings.Split(string(src), "nucleiSdk.NewNucleiEngineCtx(")
		for _, call := range chunks[1:] {
			engines++
			end := strings.Index(call, "\n\tif err != nil")
			require.Positivef(t, end, "%s: cannot find the end of a NewNucleiEngineCtx call", f)
			assert.Containsf(t, call[:end], "egressOptions()...", "%s: a nuclei engine is built without egressOptions()", f)
		}
	}
	require.Equal(t, 3, engines, "engine count changed — check the new call site passes egressOptions()")
}
