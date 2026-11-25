package nuclei

import (
	"archive/tar"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// slowArchiveServer serves body after a delay, so installers started together
// overlap, and counts the requests it gets.
func slowArchiveServer(t *testing.T, body []byte, delay time.Duration) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		time.Sleep(delay)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &hits
}

// installerFor is the production installer, fetching from url instead of
// GitHub and writing the ignore file to ignore.
func installerFor(url, ignore string) *templateInstaller {
	inst := newTemplateInstaller()
	inst.archiveURL = func(v string) string { return url + "/" + v + ".tar.gz" }
	inst.ignorePath = func() string { return ignore }
	return inst
}

// Installers that do not share a semaphore (as in separate processes) still
// install once, and none of them sees a partial tree.
func TestTemplateInstall_ConcurrentInstallersDownloadOnce(t *testing.T) {
	archive := goodArchive(t)
	release := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	home := t.TempDir()
	url, hits := slowArchiveServer(t, archive, 200*time.Millisecond)
	cfg := downloadConfig(home, release)

	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inst := installerFor(url, filepath.Join(home, "config", ".nuclei-ignore"))
			if errs[i] = inst.ensure(t.Context(), cfg); errs[i] == nil {
				_, errs[i] = os.ReadFile(filepath.Join(cfg.templatesDir, "http", "exposure.yaml"))
			}
		}()
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "installer %d", i)
	}
	assert.Equal(t, int32(1), hits.Load(), "the installers after the first find its tree under the lock")
	assert.Equal(t, []string{templatesLockName, "config", filepath.Base(cfg.templatesDir)}, dirNames(t, home))
}

// A tree verified for one release stays in place while another release of
// the same tag is installed beside it: a process may be scanning with it.
func TestTemplateInstall_NeverReplacesAVerifiedTree(t *testing.T) {
	archive := goodArchive(t)
	first := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	home := t.TempDir()
	inst, _ := archiveServer(t, archive)
	require.NoError(t, inst.ensure(t.Context(), downloadConfig(home, first)))
	before, err := os.Stat(first.installDir(home))
	require.NoError(t, err)

	other := tarGz(t,
		tarEntry{name: "nuclei-templates-1.2.3/", typ: tar.TypeDir},
		tarEntry{name: "nuclei-templates-1.2.3/http/other.yaml", body: "id: other\n"},
	)
	second := templateRelease{Version: "v1.2.3", SHA256: sum(other)}
	inst2, _ := archiveServer(t, other)
	require.NoError(t, inst2.ensure(t.Context(), downloadConfig(home, second)))

	after, err := os.Stat(first.installDir(home))
	require.NoError(t, err)
	assert.True(t, os.SameFile(before, after), "the first tree is the same directory")
	assertInstalled(t, first.installDir(home), first)
	assert.FileExists(t, filepath.Join(second.installDir(home), "http", "other.yaml"))
}

func TestTemplateInstall_RemovesLeftoversOfACrashedInstall(t *testing.T) {
	archive := goodArchive(t)
	release := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	home := t.TempDir()
	leftover := filepath.Join(home, templatesTempPrefix+"staging-123")
	require.NoError(t, os.MkdirAll(filepath.Join(leftover, "http"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(home, templatesTempPrefix+"archive-456.tar.gz"), []byte("x"), 0o644))
	inst, _ := archiveServer(t, archive)

	require.NoError(t, inst.ensure(t.Context(), downloadConfig(home, release)))
	assert.Equal(t, []string{templatesLockName, filepath.Base(release.installDir(home))}, dirNames(t, home))
}

// An install waiting on another process's lock gives up when its context
// ends, without downloading.
func TestTemplateInstall_WaitForLockEndsWithContext(t *testing.T) {
	archive := goodArchive(t)
	release := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	home := t.TempDir()
	unlock, err := lockTemplates(t.Context(), home)
	require.NoError(t, err)
	defer unlock()
	inst, hits := archiveServer(t, archive)

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	err = inst.ensure(ctx, downloadConfig(home, release))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Zero(t, hits.Load())
	assert.NoDirExists(t, release.installDir(home))
}

func TestCheckTemplateRedirect(t *testing.T) {
	cases := []struct {
		url string
		ok  bool
	}{
		{"https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/tags/v10.5.1", true},
		{"https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v10.5.1.tar.gz", true},
		{"http://codeload.github.com/x", false},
		{"https://codeload.github.com:8443/x", false},
		{"https://objects.githubusercontent.com/x", false},
		{"https://codeload.github.com.example.com/x", false},
		{"https://127.0.0.1/x", false},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.url, nil)
			require.NoError(t, err)
			err = checkTemplateRedirect(req, nil)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
	req, err := http.NewRequest(http.MethodGet, "https://codeload.github.com/x", nil)
	require.NoError(t, err)
	require.Error(t, checkTemplateRedirect(req, make([]*http.Request, 5)), "redirect hops are capped")
}

// The installer's own client refuses a redirect off GitHub's archive hosts.
func TestTemplateInstall_RefusesRedirectOffGitHub(t *testing.T) {
	archive := goodArchive(t)
	release := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	var served atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			served.Add(1)
			_, _ = w.Write(archive)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	home := t.TempDir()
	inst := installerFor(srv.URL, filepath.Join(home, ".nuclei-ignore"))

	err := inst.ensure(t.Context(), downloadConfig(home, release))
	require.ErrorContains(t, err, "not a GitHub archive host")
	assert.Zero(t, served.Load())
	assert.NoDirExists(t, release.installDir(home))
}

// helperEnv is set when the test binary runs as one installer process of the
// tests below.
const helperEnv = "VULNGRAPH_TEMPLATES_HELPER"

// TestTemplateInstallHelperProcess is not a test of its own: it is the body of
// a child process the tests below start. It installs the release named in its
// environment with the production client and checks the tree.
func TestTemplateInstallHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) == "" {
		t.Skip("run as a child process only")
	}
	home := os.Getenv("HOME")
	release := templateRelease{Version: "v1.2.3", SHA256: os.Getenv("HELPER_SHA256")}
	inst := installerFor(os.Getenv("HELPER_URL"), filepath.Join(home, "config-"+os.Getenv(helperEnv), ".nuclei-ignore"))
	cfg := downloadConfig(home, release)
	cfg.envProxyVar = environmentProxyVar(os.Getenv)
	require.NoError(t, inst.ensure(t.Context(), cfg))
	got, err := os.ReadFile(filepath.Join(cfg.templatesDir, "http", "exposure.yaml"))
	require.NoError(t, err)
	require.Equal(t, "id: exposure\n", string(got))
}

// helperProcess starts the test binary as an installer process with env on
// top of the parent's environment, minus any proxy settings.
func helperProcess(t *testing.T, name string, env ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTemplateInstallHelperProcess$", "-test.count=1", "-test.v")
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(key) {
		case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "REQUEST_METHOD", "HOME", "GOFLAGS":
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	cmd.Env = append(cmd.Env, append([]string{helperEnv + "=" + name}, env...)...)
	return cmd
}

// Two processes sharing one $HOME (worker and scanner run as one user) both
// end up with the verified tree, which is downloaded once.
func TestTemplateInstall_TwoProcessesShareOneInstall(t *testing.T) {
	if testing.Short() {
		t.Skip("starts child processes")
	}
	archive := goodArchive(t)
	url, hits := slowArchiveServer(t, archive, 500*time.Millisecond)
	home := t.TempDir()
	env := []string{"HOME=" + home, "HELPER_URL=" + url, "HELPER_SHA256=" + sum(archive)}

	cmds := []*exec.Cmd{helperProcess(t, "a", env...), helperProcess(t, "b", env...)}
	outs := make([][]byte, len(cmds))
	errs := make([]error, len(cmds))
	var wg sync.WaitGroup
	for i, cmd := range cmds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], errs[i] = cmd.CombinedOutput()
		}()
	}
	wg.Wait()
	for i := range cmds {
		require.NoError(t, errs[i], "process %d:\n%s", i, outs[i])
		require.Contains(t, string(outs[i]), "--- PASS: TestTemplateInstallHelperProcess", "process %d ran the helper", i)
	}
	assert.Equal(t, int32(1), hits.Load())
}

// archiveProxy is a forward proxy that answers requests for
// nuclei-templates.invalid with body, and counts them.
func archiveProxy(t *testing.T, body []byte) (*url.URL, *atomic.Int32) {
	t.Helper()
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() || r.URL.Host != "nuclei-templates.invalid" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		proxied.Add(1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(proxy.Close)
	u, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	return u, &proxied
}

// The download goes through NUCLEI_TEMPLATES_PROXY when it is set.
func TestTemplateInstall_DownloadsThroughTemplatesProxy(t *testing.T) {
	archive := goodArchive(t)
	release := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	proxy, proxied := archiveProxy(t, archive)
	home := t.TempDir()
	inst := installerFor("http://nuclei-templates.invalid", filepath.Join(home, "config", ".nuclei-ignore"))
	cfg := downloadConfig(home, release)
	cfg.templatesProxy = proxy

	require.NoError(t, inst.ensure(t.Context(), cfg))
	assert.Equal(t, int32(1), proxied.Load(), "the archive request went to the proxy")
	assertInstalled(t, cfg.templatesDir, release)
}

// HTTPS_PROXY/HTTP_PROXY are not used for the download: they belong to
// nuclei's JavaScript HTTP library as much as to the installer. It runs in a
// child process because net/http reads the proxy environment once per
// process; the archive host does not resolve, so a direct request fails.
func TestTemplateInstall_IgnoresProxyEnvironment(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a child process")
	}
	archive := goodArchive(t)
	proxy, proxied := archiveProxy(t, archive)

	cmd := helperProcess(t, "proxy-env",
		"HOME="+t.TempDir(),
		"HELPER_URL=http://nuclei-templates.invalid",
		"HELPER_SHA256="+sum(archive),
		"HTTP_PROXY="+proxy.String(),
		"HTTPS_PROXY="+proxy.String(),
	)
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "%s", out)
	require.Contains(t, string(out), "--- FAIL: TestTemplateInstallHelperProcess")
	require.Contains(t, string(out), "nuclei templates: download v1.2.3")
	require.Contains(t, string(out), "HTTPS_PROXY is set, but the templates download never uses it; set "+TemplatesProxyEnv)
	assert.Zero(t, proxied.Load(), "the environment's proxy was not used")
}

// A download that fails while HTTPS_PROXY or HTTP_PROXY is set, and
// NUCLEI_TEMPLATES_PROXY is not, says the environment's proxy was not used.
func TestTemplateInstall_DownloadErrorNamesTheUnusedProxy(t *testing.T) {
	archive := goodArchive(t)
	good := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	unreachable := httptest.NewServer(http.NotFoundHandler())
	unreachable.Close()
	const hint = "is set, but the templates download never uses it"
	cases := []struct {
		name     string
		url      string
		release  templateRelease
		envProxy string
		proxy    *url.URL
		wantErr  error
		wantHint bool
	}{
		{name: "environment proxy set", url: unreachable.URL, release: good, envProxy: "HTTPS_PROXY", wantErr: errTemplatesDownload, wantHint: true},
		{name: "no proxy anywhere", url: unreachable.URL, release: good, wantErr: errTemplatesDownload},
		{name: "templates proxy set", url: unreachable.URL, release: good, envProxy: "HTTP_PROXY",
			proxy: &url.URL{Scheme: "http", Host: unreachable.Listener.Addr().String()}, wantErr: errTemplatesDownload},
		{name: "not a download failure", release: templateRelease{Version: "v1.2.3", SHA256: sum([]byte("other"))},
			envProxy: "HTTPS_PROXY", wantErr: errTemplatesChecksum},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			inst, _ := archiveServer(t, archive)
			if tc.url != "" {
				inst = installerFor(tc.url, filepath.Join(home, ".nuclei-ignore"))
			}
			cfg := downloadConfig(home, tc.release)
			cfg.envProxyVar, cfg.templatesProxy = tc.envProxy, tc.proxy

			err := inst.ensure(t.Context(), cfg)
			require.ErrorIs(t, err, tc.wantErr)
			if tc.wantHint {
				require.ErrorContains(t, err, tc.envProxy+" "+hint+"; set "+TemplatesProxyEnv)
			} else {
				assert.NotContains(t, err.Error(), hint)
			}
		})
	}
}

// The production request is https through a CONNECT tunnel, carrying the
// credentials in NUCLEI_TEMPLATES_PROXY to the proxy and not to the origin.
// The origin is reached only through the proxy: example.com is in the test
// server's certificate and is never resolved.
func TestTemplateInstall_TunnelsHTTPSThroughAuthenticatingProxy(t *testing.T) {
	archive := goodArchive(t)
	release := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	var originSawProxyAuth atomic.Bool
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			originSawProxyAuth.Store(true)
		}
		_, _ = w.Write(archive)
	}))
	t.Cleanup(origin.Close)
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("scan:s3cret"))
	var tunnels atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "example.com:443" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Header.Get("Proxy-Authorization") != wantAuth {
			w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		tunnels.Add(1)
		tunnel(w, origin.Listener.Addr().String())
	}))
	t.Cleanup(proxy.Close)
	pool := x509.NewCertPool()
	pool.AddCert(origin.Certificate())

	for _, tc := range []struct {
		name, userinfo string
		ok             bool
	}{
		{name: "credentials from the URL", userinfo: "scan:s3cret@", ok: true},
		{name: "no credentials", ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			inst := installerFor("https://example.com", filepath.Join(home, ".nuclei-ignore"))
			inst.client = func(p *url.URL) *http.Client {
				client := templateClient(p)
				tr, ok := client.Transport.(*http.Transport)
				require.True(t, ok)
				tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
				t.Cleanup(client.CloseIdleConnections)
				return client
			}
			cfg := downloadConfig(home, release)
			var err error
			proxyURL := "http://" + tc.userinfo + proxy.Listener.Addr().String()
			cfg.templatesProxy, err = templatesProxyFromEnv(func(k string) string {
				if k == TemplatesProxyEnv {
					return proxyURL
				}
				return ""
			})
			require.NoError(t, err)

			before := tunnels.Load()
			err = inst.ensure(t.Context(), cfg)
			if !tc.ok {
				require.ErrorIs(t, err, errTemplatesDownload)
				assert.Equal(t, before, tunnels.Load())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, before+1, tunnels.Load(), "the archive came through one CONNECT tunnel the proxy accepted")
			assertInstalled(t, cfg.templatesDir, release)
		})
	}
	assert.False(t, originSawProxyAuth.Load(), "the proxy credentials stayed with the proxy")
}

// tunnel answers a CONNECT by splicing the client's connection to addr until
// either side closes.
func tunnel(w http.ResponseWriter, addr string) {
	upstream, err := net.Dial("tcp", addr)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()
	hj, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(upstream, buf)
	}()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
	<-done
}

// A marker that cannot be read is an error, not a missing install: the tree
// may be verified and in use by another process, so it is neither moved aside
// nor downloaded again, in ensure or under the install lock.
func TestTemplateInstall_UnreadableMarkerLeavesTheTree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
	archive := goodArchive(t)
	release := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	home := t.TempDir()
	first, _ := archiveServer(t, archive)
	cfg := downloadConfig(home, release)
	require.NoError(t, first.ensure(t.Context(), cfg))
	before, err := os.Stat(cfg.templatesDir)
	require.NoError(t, err)
	marker := filepath.Join(cfg.templatesDir, templatesMarker)
	require.NoError(t, os.Chmod(marker, 0))
	t.Cleanup(func() { _ = os.Chmod(marker, 0o644) })

	inst, hits := archiveServer(t, archive)
	require.ErrorIs(t, inst.ensure(t.Context(), cfg), fs.ErrPermission)
	require.ErrorIs(t, inst.install(t.Context(), cfg.templatesDir, release, inst.client(nil)), fs.ErrPermission)

	assert.Zero(t, hits.Load())
	after, err := os.Stat(cfg.templatesDir)
	require.NoError(t, err)
	assert.True(t, os.SameFile(before, after), "the tree is the same directory")
	assert.FileExists(t, filepath.Join(cfg.templatesDir, "http", "exposure.yaml"))
}
