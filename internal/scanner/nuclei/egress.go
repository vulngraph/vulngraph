package nuclei

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	nucleiSdk "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	updateutils "github.com/projectdiscovery/utils/update"

	"github.com/vulngraph/vulngraph/pkg/egress"
)

// What the nuclei SDK (v3.11.1) contacts on its own, apart from scan targets:
//
//   - api.pdtm.sh: a version check on the first engine of every process
//     (OS, arch, Go and nuclei versions, a hashed machine ID). The SDK makes this
//     call before any option is consulted (lib/sdk_private.go calls
//     installer.NucleiSDKVersionCheck unconditionally), so no SDK option stops
//     it. Always refused: init swaps the transport of the one client that call
//     uses (updateutils.DefaultHttpClient) for refuseVersionCheck.
//   - GitHub: the SDK's template manager installs and updates nuclei-templates
//     to the LATEST release, with no version pin or checksum. Every engine here
//     turns it off (DisableUpdateCheck); the templates a scan runs are the
//     pinned release that templates.go downloads and verifies itself, or the
//     operator's NUCLEI_TEMPLATES_DIR.
//   - Interactsh (oast.pro, oast.live, ...): out-of-band templates make the
//     TARGET call a ProjectDiscovery-run server and nuclei polls it. Off unless
//     NUCLEI_INTERACTSH_ENABLED, and always off under OFFLINE_MODE.
//
// Cloud upload (PDCP) needs a scan ID or explicit option and is never enabled.
const (
	// TemplatesDirEnv points nuclei at a pre-populated template directory, e.g.
	// a mounted copy of nuclei-templates. Setting it also stops the download of
	// the pinned release: an operator who supplies templates owns their version.
	TemplatesDirEnv = "NUCLEI_TEMPLATES_DIR"
	// TemplatesVersionEnv and TemplatesSHA256Env replace the pinned release
	// (pinnedTemplates) with another nuclei-templates tag and the sha256 of its
	// source archive. Both or neither.
	TemplatesVersionEnv = "NUCLEI_TEMPLATES_VERSION"
	TemplatesSHA256Env  = "NUCLEI_TEMPLATES_SHA256"
	// TemplatesDownloadDisabledEnv stops the download of the pinned release:
	// scans then need it already installed, or NUCLEI_TEMPLATES_DIR. An on/off
	// switch (egress.Disabled).
	TemplatesDownloadDisabledEnv = "NUCLEI_TEMPLATES_DOWNLOAD_DISABLED"
	// TemplatesProxyEnv is the HTTP proxy the pinned release is downloaded
	// through, read by the installer's transport alone. HTTPS_PROXY/HTTP_PROXY
	// are not used for it: nuclei's JavaScript HTTP library reads those too,
	// and through a proxy its dial-time sandbox sees the proxy, not the target.
	TemplatesProxyEnv = "NUCLEI_TEMPLATES_PROXY"
	// InteractshEnabledEnv turns on out-of-band (interactsh) testing. An on/off
	// switch that OFFLINE_MODE overrides (egress.Enabled).
	InteractshEnabledEnv = "NUCLEI_INTERACTSH_ENABLED"
)

// retiredEnv are switches earlier builds read. Each now means nothing, and
// one left set would leave its operator believing an egress is off when it is
// not, so a set one is an error naming its replacement.
var retiredEnv = []struct{ name, use string }{
	{"NUCLEI_UPDATE_DISABLED", TemplatesDownloadDisabledEnv + " (the pinned release) or " + TemplatesDirEnv},
	{"NUCLEI_INTERACTSH_DISABLED", InteractshEnabledEnv + " (interactsh is now off unless enabled)"},
}

func checkRetiredEnv(getenv func(string) string) error {
	var errs []error
	for _, r := range retiredEnv {
		if getenv(r.name) != "" {
			errs = append(errs, fmt.Errorf("%s is no longer read: use %s", r.name, r.use))
		}
	}
	return errors.Join(errs...)
}

// errVersionCheckRefused is what the SDK's version-check client gets back
// instead of a connection.
var errVersionCheckRefused = errors.New("nuclei: version check refused")

// refuseVersionCheck answers every request without dialling. The SDK ignores
// the failed check.
type refuseVersionCheck struct{}

func (refuseVersionCheck) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errVersionCheckRefused
}

// init runs before any engine exists, so the first engine's version check
// already meets the refusing transport. The installer's client holds this
// same *http.Client, so replacing its Transport covers it.
func init() {
	updateutils.DefaultHttpClient.Transport = refuseVersionCheck{}
}

// egressConfig is how the engine may reach the network outside of its targets.
type egressConfig struct {
	// templatesDir is where scans load templates from: the operator's
	// NUCLEI_TEMPLATES_DIR, or the install directory of release.
	templatesDir string
	// operatorDir says templatesDir is NUCLEI_TEMPLATES_DIR: never downloaded.
	operatorDir      bool
	release          templateRelease
	downloadDisabled bool
	// templatesProxy is NUCLEI_TEMPLATES_PROXY; nil downloads directly.
	templatesProxy *url.URL
	// envProxyVar names the HTTPS_PROXY/HTTP_PROXY variable set, if any, for
	// a failed download to say it was not used.
	envProxyVar string
	interactsh  bool
}

// egressConfigFromEnv reads the switches. An unrecognised value is returned as
// an error alongside a config with that egress off: the switches fail closed,
// so an engine built before startup validation still stays offline.
func egressConfigFromEnv(getenv func(string) string) (egressConfig, error) {
	dlOff, dlErr := egress.Disabled(getenv, TemplatesDownloadDisabledEnv)
	ish, ishErr := egress.Enabled(getenv, InteractshEnabledEnv)
	proxy, proxyErr := templatesProxyFromEnv(getenv)
	cfg := egressConfig{downloadDisabled: dlOff, templatesProxy: proxy, envProxyVar: environmentProxyVar(getenv), interactsh: ish}
	dirErr := cfg.resolveTemplates(getenv)
	if err := errors.Join(dlErr, ishErr, proxyErr, dirErr, checkRetiredEnv(getenv)); err != nil {
		return cfg, fmt.Errorf("nuclei egress: %w", err)
	}
	return cfg, nil
}

// templatesProxyFromEnv parses NUCLEI_TEMPLATES_PROXY: an http or https
// proxy URL, optionally with credentials. The value is never echoed in an
// error, since it may carry them.
func templatesProxyFromEnv(getenv func(string) string) (*url.URL, error) {
	raw := strings.TrimSpace(getenv(TemplatesProxyEnv))
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s: want a proxy URL such as http://proxy.internal:3128", TemplatesProxyEnv)
	}
	return u, nil
}

// environmentProxyVar is the first of the variables net/http's
// ProxyFromEnvironment reads for a request that is set, or "".
func environmentProxyVar(getenv func(string) string) string {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if strings.TrimSpace(getenv(k)) != "" {
			return k
		}
	}
	return ""
}

// resolveTemplates sets the template directory and release. An operator
// directory excludes a release override: setting both would leave it unclear
// which templates run.
func (c *egressConfig) resolveTemplates(getenv func(string) string) error {
	dir := strings.TrimSpace(getenv(TemplatesDirEnv))
	release, overridden, err := releaseFromEnv(getenv)
	if err != nil {
		return err
	}
	c.release = release
	if dir != "" {
		if overridden {
			return fmt.Errorf("%s and %s/%s are both set: set one", TemplatesDirEnv, TemplatesVersionEnv, TemplatesSHA256Env)
		}
		c.templatesDir, c.operatorDir = dir, true
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("nuclei templates directory: %w (set %s)", err, TemplatesDirEnv)
	}
	c.templatesDir = release.installDir(home)
	return nil
}

// CheckEgressEnv validates the nuclei egress switches, for each pod that builds
// nuclei engines to call at startup: an unrecognised value stops the pod
// instead of surfacing only when the first engine is built.
func CheckEgressEnv(getenv func(string) string) error {
	_, err := egressConfigFromEnv(getenv)
	return err
}

// templatesDirOnce applies the template directory to nuclei's process-wide
// config exactly once: SetTemplatesDir writes the global without a lock, and
// engines are built concurrently.
var templatesDirOnce sync.Once

// egressOptions turns the process environment into SDK options. Every engine
// this package builds passes them, so no engine is built with the defaults.
// CheckEgressEnv has already stopped the pod on an invalid value, and the
// config returned with the error keeps that egress off either way.
func egressOptions() []nucleiSdk.NucleiSDKOptions {
	cfg, _ := egressConfigFromEnv(os.Getenv)
	return cfg.options()
}

// options always turns off the SDK's own template installer, which fetches the
// latest unpinned release, and sets interactsh on only if it was opted in.
func (c egressConfig) options() []nucleiSdk.NucleiSDKOptions {
	if c.templatesDir != "" {
		templatesDirOnce.Do(func() { config.DefaultConfig.SetTemplatesDir(c.templatesDir) })
	}
	return []nucleiSdk.NucleiSDKOptions{
		nucleiSdk.DisableUpdateCheck(),
		nucleiSdk.WithInteractshOptions(c.interactshOptions()),
	}
}

// interactshOptions start from the SDK's defaults: the engine builds its
// interactsh client from them even when it is off, and a zero CacheSize
// panics there.
func (c egressConfig) interactshOptions() nucleiSdk.InteractshOpts {
	opts := interactsh.DefaultOptions(nil, nil, nil)
	opts.NoInteractsh = !c.interactsh
	return nucleiSdk.InteractshOpts(*opts)
}
