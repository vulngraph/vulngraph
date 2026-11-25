package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

// These tests exercise the embedded SPA handler against whatever is in
// web/dist. They are meaningful only once the frontend is built (index.html
// present; CI's frontend job builds it before running them); when it is not,
// the handler degrades to 503, asserted by TestHandler_Unbuilt_503.
func built() bool {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return false
	}
	_, err = fs.Stat(sub, "index.html")
	return err == nil
}

func TestHandler_Unbuilt_503(t *testing.T) {
	rec := httptest.NewRecorder()
	spaHandler(fstest.MapFS{".gitkeep": &fstest.MapFile{}}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Contains(t, rec.Body.String(), "frontend not built")
}

func TestHandler_ServesIndexAtRoot(t *testing.T) {
	if !built() {
		t.Skip("frontend not built (web/dist has no index.html)")
	}
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `id="root"`)
}

func TestHandler_SPAFallbackForClientRoutes(t *testing.T) {
	if !built() {
		t.Skip("frontend not built")
	}
	// An unknown path (a client-side route) must serve index.html, not 404.
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/findings", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `id="root"`)
}

func TestHandler_ServesHashedAssets(t *testing.T) {
	if !built() {
		t.Skip("frontend not built")
	}
	sub, _ := fs.Sub(dist, "dist")
	var assetPath string
	_ = fs.WalkDir(sub, "assets", func(p string, d fs.DirEntry, _ error) error {
		if assetPath == "" && d != nil && !d.IsDir() {
			assetPath = "/" + p
		}
		return nil
	})
	require.NotEmpty(t, assetPath, "expected at least one built asset")

	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, assetPath, nil))
	require.Equal(t, http.StatusOK, rec.Code)
}

// The server's Content-Security-Policy is script-src 'self' with no
// 'unsafe-inline' (internal/httpsrv/security.go). An inline script, inline
// event handler or externally hosted asset in the built index.html would be
// blocked and blank the app, so the build output is pinned here.
func TestBuiltIndexHasNoInlineScript(t *testing.T) {
	if !built() {
		t.Skip("frontend not built")
	}
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	html := rec.Body.String()

	scripts := regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`).FindAllStringSubmatch(html, -1)
	require.NotEmpty(t, scripts, "expected the module entry script")
	for _, s := range scripts {
		require.Regexp(t, `\bsrc="/`, s[1], "every script must be a same-origin file: %s", s[0])
		require.Empty(t, regexp.MustCompile(`\S`).FindString(s[2]), "inline script body: %s", s[0])
	}
	require.NotRegexp(t, `(?i)\son[a-z]+\s*=`, html, "inline event handler")
	require.NotRegexp(t, `(?i)(src|href)="(https?:)?//`, html, "externally hosted asset (fonts/scripts must be bundled)")
}
