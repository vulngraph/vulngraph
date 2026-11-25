package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePurl(t *testing.T) {
	tests := []struct {
		name string
		purl string
		want pkgCoords
		ok   bool
	}{
		{
			name: "npm plain",
			purl: "pkg:npm/lodash@4.17.21",
			want: pkgCoords{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21"},
			ok:   true,
		},
		{
			name: "npm scoped percent-encoded",
			purl: "pkg:npm/%40babel/core@7.24.0",
			want: pkgCoords{Ecosystem: "npm", Name: "@babel/core", Version: "7.24.0", Purl: "pkg:npm/@babel/core@7.24.0"},
			ok:   true,
		},
		{
			name: "maven group colon artifact",
			purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			want: pkgCoords{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
			ok:   true,
		},
		{
			name: "go module path",
			purl: "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
			want: pkgCoords{Ecosystem: "Go", Name: "github.com/gin-gonic/gin", Version: "v1.9.0", Purl: "pkg:golang/github.com/gin-gonic/gin@v1.9.0"},
			ok:   true,
		},
		{
			name: "qualifiers stripped",
			purl: "pkg:pypi/requests@2.31.0?extension=tar.gz",
			want: pkgCoords{Ecosystem: "PyPI", Name: "requests", Version: "2.31.0", Purl: "pkg:pypi/requests@2.31.0"},
			ok:   true,
		},
		{name: "uncovered ecosystem", purl: "pkg:swift/github.com/apple/swift-nio@2.0.0", ok: false},
		{name: "no version", purl: "pkg:npm/lodash", ok: false},
		{name: "not a purl", purl: "lodash@4.17.21", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parsePurl(tt.purl)
			require.Equal(t, tt.ok, ok)
			if tt.ok {
				require.Equal(t, tt.want, got)
			}
		})
	}
}

// fakeGitHubWithSBOM extends the repo fixture with per-repo SBOM responses.
// Repos absent from the map get a 404, as GitHub returns when the dependency
// graph is disabled.
func fakeGitHubWithSBOM(t *testing.T, totalRepos int, sboms map[string][]string) *httptest.Server {
	t.Helper()
	srv := fakeGitHub(t, totalRepos)
	mux := srv.Config.Handler.(*http.ServeMux)
	mux.HandleFunc("GET /repos/{owner}/{repo}/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer ghs_installation_token", r.Header.Get("Authorization"))
		full := r.PathValue("owner") + "/" + r.PathValue("repo")
		purls, ok := sboms[full]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"sbom":{"packages":[`)
		for i, p := range purls {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":%q}]}`, p)
		}
		fmt.Fprint(w, `]}}`)
	})
	return srv
}

func TestCollect_Packages(t *testing.T) {
	srv := fakeGitHubWithSBOM(t, 3, map[string][]string{
		"org/repo0": {"pkg:npm/lodash@4.17.21", "pkg:npm/%40babel/core@7.24.0"},
		"org/repo1": {"pkg:npm/lodash@4.17.21", "pkg:swift/x/y@1.0.0"}, // lodash shared, swift uncovered
		// repo2 has no SBOM → 404 → skipped, collection still succeeds.
	})
	c := newTestCollector(srv)

	res, err := c.Collect(context.Background(), validConfig(t))
	require.NoError(t, err)

	var pkgs []string
	for _, a := range res.Assets {
		if a.Type == "package" {
			pkgs = append(pkgs, a.ID)
			require.Equal(t, "global", a.Region)
			require.NotEmpty(t, a.Metadata["ecosystem"])
			require.NotEmpty(t, a.Metadata["package"])
			require.NotEmpty(t, a.Metadata["version"])
		}
	}
	// lodash deduped across repos; the swift purl is uncovered and dropped.
	require.Equal(t, []string{"pkg:npm/@babel/core@7.24.0", "pkg:npm/lodash@4.17.21"}, pkgs)

	require.Len(t, res.Edges, 3, "one depends_on edge per repo→package occurrence")
	for _, e := range res.Edges {
		require.Equal(t, "depends_on", e.EdgeType)
		require.Equal(t, "github_repo", e.SrcType)
		require.Equal(t, "package", e.DstType)
	}
	require.Equal(t, "org/repo0", res.Edges[0].SrcID)
	require.Equal(t, "org/repo1", res.Edges[2].SrcID)
	require.Equal(t, "pkg:npm/lodash@4.17.21", res.Edges[2].DstID)
}

func TestCollect_ArchivedRepoSkipsSBOM(t *testing.T) {
	// All repos archived → no SBOM requests at all, so a handler that would
	// fail the test never fires.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"ghs_installation_token"}`))
	})
	mux.HandleFunc("GET /installation/repositories", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"repositories":[{"name":"old","full_name":"org/old","archived":true}]}`))
	})
	// Scoped to the SBOM endpoint, not all of /repos/: an archived repo IS
	// legitimately swept for secret-scanning alerts (a leaked credential
	// outlives archival — see TestCollectGHAS_ArchivedRepoKeepsSecretsDropsCodeScanning).
	mux.HandleFunc("GET /repos/org/old/dependency-graph/sbom", func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("archived repo must not be SBOM-fetched")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	res, err := newTestCollector(srv).Collect(context.Background(), validConfig(t))
	require.NoError(t, err)
	require.Empty(t, res.Edges)
}

// The image scanner reads Go module versions out of a compiled binary via
// debug/buildinfo, which only ever yields the canonical "vX.Y.Z" form. GitHub's
// dependency graph emits both, so without canonicalisation the same module became
// two package nodes and no image package could ever join its repo SBOM — the
// disjoint-universe bug: an unmatched Go package can differ from its SBOM twin
// by nothing but this character.
func TestParsePurl_GoVersionIsCanonicalisedInThePurl(t *testing.T) {
	withV, ok := parsePurl("pkg:golang/github.com/aws/aws-sdk-go@v1.44.0")
	require.True(t, ok)
	withoutV, ok := parsePurl("pkg:golang/github.com/aws/aws-sdk-go@1.44.0")
	require.True(t, ok)

	require.Equal(t, withV.Purl, withoutV.Purl,
		"both GitHub spellings of one Go module must be the same package node")
	require.Equal(t, "pkg:golang/github.com/aws/aws-sdk-go@v1.44.0", withoutV.Purl)

	// Version feeds the OSV query and must NOT be rewritten — the Go ecosystem's
	// advisory ranges match the unprefixed form.
	require.Equal(t, "1.44.0", withoutV.Version)
	require.Equal(t, "v1.44.0", withV.Version)
}

func TestParsePurl_GoCanonicalisationIsNarrow(t *testing.T) {
	// A pseudo-version already carries its v.
	pseudo, ok := parsePurl("pkg:golang/example.com/m@v0.0.0-20210101120000-abcdef123456")
	require.True(t, ok)
	require.Equal(t, "pkg:golang/example.com/m@v0.0.0-20210101120000-abcdef123456", pseudo.Purl)

	// Non-semver versions are not Go module versions and pass through untouched.
	sha, ok := parsePurl("pkg:golang/example.com/m@abcdef1")
	require.True(t, ok)
	require.Equal(t, "pkg:golang/example.com/m@abcdef1", sha.Purl)

	// Other ecosystems are never touched — an npm "1.2.3" must not become "v1.2.3".
	npm, ok := parsePurl("pkg:npm/lodash@1.2.3")
	require.True(t, ok)
	require.Equal(t, "pkg:npm/lodash@1.2.3", npm.Purl)
}
