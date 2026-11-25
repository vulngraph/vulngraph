package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

// TestMain silences the global zerolog logger for this package. These tests
// drive the collector over fakeGitHub estates of up to maxPages*perPage repos,
// and the per-repo debug lines the real collector emits made a single passing
// test write 7.6 MB to stdout — enough that a CI log filter truncated the
// stream mid-run, which reads as a different arbitrary set of tests "failing"
// on every run. The assertions here are all on returned values, never on log
// output, so discarding it loses nothing.
func TestMain(m *testing.M) {
	zlog.Logger = zerolog.Nop()
	os.Exit(m.Run())
}

// testKeyPEM generates a throwaway RSA private key in PEM form for signing the
// App JWT. Small key size keeps the test fast — it never leaves the process.
func testKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

// fakeGitHub serves the two endpoints Collect uses, with pageCount pages of
// repos (perPage each on full pages).
func fakeGitHub(t *testing.T, totalRepos int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		require.True(t, strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "), "must send the App JWT")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"ghs_installation_token"}`))
	})

	mux.HandleFunc("GET /installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer ghs_installation_token", r.Header.Get("Authorization"))
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		start := (page - 1) * perPage
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"repositories":[`)
		for i := start; i < start+perPage && i < totalRepos; i++ {
			if i > start {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"name":"repo%d","full_name":"org/repo%d","html_url":"https://gh/org/repo%d",`+
				`"visibility":"private","archived":false,"language":"Go","default_branch":"main"}`, i, i, i)
		}
		fmt.Fprint(w, `]}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newTestCollector points a collector at the fake server (bypassing safenet,
// which would block the loopback test address).
// resetRateLimitStates clears the package-global rate-limit registry.
//
// rateLimitStates (ratelimit.go) is keyed by installation token and never
// expires — correct in production, where each connector holds its own rotating
// token, but every test here issues the SAME literal token from its fake
// /access_tokens route, so all of them share one bucket for the life of the
// test binary. A high-volume test leaves that bucket below rateLimitThreshold
// with a reset time in the future, and the next test's requests are then killed
// by errRateLimitWait — surfacing not as a rate-limit error but as quietly
// absent metadata keys, because every per-repo read here is best-effort. That
// is a cross-test data leak with a completely misleading failure signature, so
// clear it for each collector rather than teaching the tests to expect it.
func newTestCollector(srv *httptest.Server) *Collector {
	rateLimitStates.Range(func(k, _ any) bool {
		rateLimitStates.Delete(k)
		return true
	})
	return &Collector{client: srv.Client(), baseURL: srv.URL}
}

func validConfig(t *testing.T) map[string]string {
	return map[string]string{
		"app_id":          "12345",
		"installation_id": "67890",
		"private_key_pem": testKeyPEM(t),
	}
}

func TestCollect_SinglePage(t *testing.T) {
	srv := fakeGitHub(t, 3)
	c := newTestCollector(srv)

	res, err := c.Collect(context.Background(), validConfig(t))
	require.NoError(t, err)
	require.Len(t, res.Assets, 3)

	a := res.Assets[0]
	require.Equal(t, "org/repo0", a.ID)
	require.Equal(t, "github_repo", a.Type)
	require.Equal(t, asset.ProviderGitHub, a.Provider)
	require.Equal(t, "private", a.Metadata["visibility"])
	require.Equal(t, "Go", a.Metadata["language"])
}

func TestCollect_Pagination(t *testing.T) {
	// 150 repos = one full page (100) + a partial page (50) → two requests.
	srv := fakeGitHub(t, 150)
	c := newTestCollector(srv)

	res, err := c.Collect(context.Background(), validConfig(t))
	require.NoError(t, err)
	require.Len(t, res.Assets, 150)
	require.Equal(t, "org/repo149", res.Assets[149].ID)
}

func TestCollect_NoRepos(t *testing.T) {
	srv := fakeGitHub(t, 0)
	c := newTestCollector(srv)

	res, err := c.Collect(context.Background(), validConfig(t))
	require.NoError(t, err)
	require.Empty(t, res.Assets)
}

func TestCollect_MissingCredentials(t *testing.T) {
	c := New()
	_, err := c.Collect(context.Background(), map[string]string{"app_id": "1"})
	require.ErrorContains(t, err, "private_key_pem")
}

func TestCollect_BadPrivateKey(t *testing.T) {
	c := New()
	cfg := map[string]string{"app_id": "1", "installation_id": "2", "private_key_pem": "not-a-key"}
	_, err := c.Collect(context.Background(), cfg)
	require.ErrorContains(t, err, "parse key")
}

// Collect is called concurrently on a shared collector (it is a singleton
// across sync workers), so setting base_url from cfg must not mutate the
// receiver. Only `go test -race` detects a regression (CI's race-detector step
// runs this package); a plain run passes either way.
func TestCollect_ConcurrentSafe(t *testing.T) {
	srv := fakeGitHub(t, 5)
	c := newTestCollector(srv) // shared across goroutines; uses the test client

	cfg := validConfig(t)
	cfg["base_url"] = srv.URL // exercises the per-call base_url override path

	const goroutines = 8
	errCh := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			res, err := c.Collect(context.Background(), cfg)
			if err == nil && len(res.Assets) != 5 {
				err = fmt.Errorf("got %d assets, want 5", len(res.Assets))
			}
			errCh <- err
		}()
	}
	for i := 0; i < goroutines; i++ {
		require.NoError(t, <-errCh)
	}
}

func TestCollect_TokenEndpointError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	_, err := c.Collect(context.Background(), validConfig(t))
	require.ErrorContains(t, err, "status 401")
}

// The asset must omit branch_protection entirely when unknown — writing
// "disabled" there is what a flood of open findings rested on. fakeGitHub serves no
// GraphQL route, so the protection read fails outright and every repo must come
// back with no key at all.
// completedScopes indexes a result's proven-complete enumerations by scope key.
func completedScopes(res collect.Result) map[string]collect.ScopeEnumeration {
	out := map[string]collect.ScopeEnumeration{}
	for _, se := range res.CompletedEnumerations {
		out[se.Scope] = se
	}
	return out
}

// A clean, fully-paged repo listing earns a completeness claim keyed by
// installation, with the exact repo count as its Count.
func TestCollect_FullRepoListing_MarksComplete(t *testing.T) {
	srv := fakeGitHub(t, 150) // one full page + one partial page
	c := newTestCollector(srv)

	res, err := c.Collect(context.Background(), validConfig(t))
	require.NoError(t, err)
	require.False(t, res.Partial)

	scopes := completedScopes(res)
	se, ok := scopes["installation/67890:repos"]
	require.True(t, ok, "a fully-paged repo listing must be claimed complete")
	require.Equal(t, []string{"github_repo"}, se.Types)
	require.Equal(t, 150, se.Count)
}

// A repo listing that fails mid-pagination must not be claimed complete —
// the pages beyond the failure were never read.
func TestCollect_RepoListingPageFailure_NoCompletenessClaim(t *testing.T) {
	var calls int
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"ghs_installation_token"}`))
	})
	mux.HandleFunc("GET /installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		calls++
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 1 {
			w.Header().Set("Content-Type", "application/json")
			repos := make([]string, perPage)
			for i := range repos {
				repos[i] = fmt.Sprintf(`{"name":"repo%d","full_name":"org/repo%d","html_url":"https://gh/org/repo%d",`+
					`"visibility":"private","archived":false,"language":"Go","default_branch":"main"}`, i, i, i)
			}
			fmt.Fprintf(w, `{"repositories":[%s]}`, strings.Join(repos, ","))
			return
		}
		// Every subsequent page fails; doJSON retries a 500 twice more before
		// giving up, so this must fail deterministically past the retry budget.
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	res, err := c.Collect(context.Background(), validConfig(t))
	require.NoError(t, err, "a mid-pagination failure is best-effort, not fatal")
	require.True(t, res.Partial, "the un-fetched pages must mark the sweep partial")

	scopes := completedScopes(res)
	_, ok := scopes["installation/67890:repos"]
	require.False(t, ok, "a listing that failed mid-pagination must not be claimed complete")
}

// Hitting the maxPages ceiling with a still-full last page means pages beyond
// the ceiling were never read, so the walk is truncated even though no request
// ever errored — listRepos must report that as partial.
//
// This drives listRepos directly rather than Collect. Reaching the ceiling
// needs maxPages*perPage = 5,000 repos, and putting that estate through the
// full Collect fans out per-repo reads (SBOM, branch protection, GHAS, IaC)
// across thousands of sockets — enough to exhaust the machine's ephemeral
// ports, at which point *other* tests in this package fail their next dial
// with "can't assign requested address". A different arbitrary set of them
// failed on each run, which reads as flakiness rather than as this test's
// fault. The Collect-level half of this behaviour is already covered:
// TestCollect_FullRepoListing_MarksComplete proves the claim appears when
// reposPartial is false, and TestCollect_RepoListingPageFailure_NoCompletenessClaim
// proves it is withheld when true — the `if !reposPartial` guard is the whole
// of the logic in between.
func TestListRepos_TruncatedAtMaxPagesCeiling(t *testing.T) {
	total := maxPages * perPage // every one of the maxPages pages is full
	srv := fakeGitHub(t, total)
	c := newTestCollector(srv)

	repos, partial, err := c.listRepos(context.Background(), srv.URL, "ghs_installation_token")
	require.NoError(t, err, "no page errored — the ceiling is not an error")
	require.Len(t, repos, total)
	require.True(t, partial, "a listing stopped by the ceiling on a full page is truncated, not complete")
}

// The counterpart: a listing whose last page is short genuinely reached the end
// of the installation's repos, so it is complete and must NOT be partial — this
// is the case that licenses the completeness claim.
func TestListRepos_ShortFinalPageIsComplete(t *testing.T) {
	srv := fakeGitHub(t, perPage+7) // two pages, the second short
	c := newTestCollector(srv)

	repos, partial, err := c.listRepos(context.Background(), srv.URL, "ghs_installation_token")
	require.NoError(t, err)
	require.Len(t, repos, perPage+7)
	require.False(t, partial, "a short final page proves the walk was exhaustive")
}

// A repo listing failure must not suppress an unrelated valid claim — there is
// currently only one claim in this collector, so this guards that a failure
// simply omits the claim rather than, say, panicking or corrupting the result.
func TestCollect_NoRepos_MarksCompleteWithZeroCount(t *testing.T) {
	srv := fakeGitHub(t, 0)
	c := newTestCollector(srv)

	res, err := c.Collect(context.Background(), validConfig(t))
	require.NoError(t, err)
	require.False(t, res.Partial)

	scopes := completedScopes(res)
	se, ok := scopes["installation/67890:repos"]
	require.True(t, ok, "an empty but fully-enumerated installation is still a complete listing")
	require.Equal(t, 0, se.Count)
}

func TestCollect_UnknownBranchProtection_OmitsKey(t *testing.T) {
	srv := fakeGitHub(t, 2)
	c := newTestCollector(srv)
	res, err := c.Collect(context.Background(), validConfig(t))
	require.NoError(t, err)
	require.Len(t, res.Assets, 2)
	for _, a := range res.Assets {
		require.NotContains(t, a.Metadata, "branch_protection",
			"the fake server has no graphql route — nothing was observed, so no key")
	}
}
