package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// ghasTestRepos is the standard non-archived repo fixture for direct
// collectGHAS calls (bypassing Collect's JWT/token plumbing).
func ghasTestRepos() []repo {
	return []repo{
		{Name: "repo0", FullName: "org/repo0", DefaultBranch: "main"},
		{Name: "repo1", FullName: "org/repo1", DefaultBranch: "main"},
		{Name: "old", FullName: "org/old", Archived: true},
	}
}

func codeAlertJSON(repoFullName string, number int) string {
	return fmt.Sprintf(`{"number":%d,"state":"open","created_at":"2026-01-02T03:04:05Z",`+
		`"rule":{"id":"go/sql-injection","name":"SQL injection","description":"desc","security_severity_level":"high"},`+
		`"repository":{"full_name":%q}}`, number, repoFullName)
}

func secretAlertJSON(repoFullName string, number int) string {
	return fmt.Sprintf(`{"number":%d,"state":"open","created_at":"2026-01-02T03:04:05Z",`+
		`"secret_type":"aws_access_key_id","secret_type_display_name":"AWS Access Key ID",`+
		`"repository":{"full_name":%q}}`, number, repoFullName)
}

func findingIDs(fs []finding.Finding) []string {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestCollectGHAS_OrgLevel(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orgs/org/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("state") == "closed" {
			fmt.Fprint(w, "[]")
			return
		}
		require.Equal(t, "open", r.URL.Query().Get("state"))
		// repo1 alert, plus alerts for an archived repo and a repo outside the
		// installation — both must be filtered out.
		fmt.Fprintf(w, "[%s,%s,%s]",
			codeAlertJSON("org/repo1", 7),
			codeAlertJSON("org/old", 8),
			codeAlertJSON("org/not-installed", 9))
	})
	mux.HandleFunc("GET /orgs/org/secret-scanning/alerts", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A secret on the ARCHIVED repo is kept (the credential is still live);
		// a secret on a repo outside the installation is still filtered out.
		fmt.Fprintf(w, "[%s,%s,%s]",
			secretAlertJSON("org/repo0", 3),
			secretAlertJSON("org/old", 4),
			secretAlertJSON("org/not-installed", 5))
	})
	mux.HandleFunc("GET /repos/", func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("org-level path must not fall back to per-repo call %s", r.URL.Path)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	fs, _ := c.collectGHAS(context.Background(), srv.URL, "tok-org-level", ghasTestRepos())

	require.ElementsMatch(t,
		[]string{"ghas_code_scanning:org/repo1:7", "ghas_secrets:org/repo0:3", "ghas_secrets:org/old:4"},
		findingIDs(fs))
	for _, f := range fs {
		switch f.Source {
		case "ghas_code_scanning":
			require.Equal(t, finding.SeverityHigh, f.Severity)
			require.Equal(t, "SQL injection", f.Title)
			require.Equal(t, "org/repo1", f.ResourceID)
			require.Equal(t, "repo1", f.ResourceName)
			require.Equal(t, "go/sql-injection", f.CheckID)
		case "ghas_secrets":
			require.Equal(t, finding.SeverityHigh, f.Severity)
			require.Equal(t, "Exposed secret: AWS Access Key ID", f.Title)
			require.Contains(t, []string{"org/repo0", "org/old"}, f.ResourceID)
			require.Equal(t, "aws_access_key_id", f.CheckID)
		}
		require.Equal(t, "github_repo", f.ResourceType)
	}
}

func TestCollectGHAS_OrgLevelPagination(t *testing.T) {
	// 100 alerts on page 1 (full page) + 30 on page 2.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orgs/org/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		w.Header().Set("Content-Type", "application/json")
		n := perPage
		if page == 2 {
			n = 30
		} else if page > 2 {
			n = 0
		}
		fmt.Fprint(w, "[")
		for i := 0; i < n; i++ {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprint(w, codeAlertJSON("org/repo0", (page-1)*perPage+i))
		}
		fmt.Fprint(w, "]")
	})
	mux.HandleFunc("GET /orgs/org/secret-scanning/alerts", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "[]")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	fs, _ := c.collectGHAS(context.Background(), srv.URL, "tok-org-pages", ghasTestRepos())
	require.Len(t, fs, 130)
}

// Org endpoints 404 (older GHES) → per-repo fallback produces the SAME finding
// IDs the org-level path would, so findings upsert in place either way.
func TestCollectGHAS_Org404FallsBackPerRepo(t *testing.T) {
	mux := http.NewServeMux()
	perRepoCalls := 0
	mux.HandleFunc("GET /repos/org/repo0/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") == "closed" {
			fmt.Fprint(w, "[]")
			return
		}
		perRepoCalls++
		fmt.Fprintf(w, "[%s]", codeAlertJSON("org/repo0", 7))
	})
	mux.HandleFunc("GET /repos/org/repo0/secret-scanning/alerts", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "[%s]", secretAlertJSON("org/repo0", 3))
	})
	// repo1 has GHAS disabled → 404 via the mux default. The archived repo is
	// swept for SECRETS (a leaked credential outlives archival) but never for
	// code scanning (archived code cannot ship).
	mux.HandleFunc("GET /repos/org/old/secret-scanning/alerts", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "[%s]", secretAlertJSON("org/old", 4))
	})
	mux.HandleFunc("GET /repos/org/old/code-scanning/alerts", func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("archived repo must not be swept for code scanning")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	fs, _ := c.collectGHAS(context.Background(), srv.URL, "tok-fallback", ghasTestRepos())

	require.ElementsMatch(t,
		[]string{"ghas_code_scanning:org/repo0:7", "ghas_secrets:org/repo0:3", "ghas_secrets:org/old:4"},
		findingIDs(fs))
	require.Equal(t, 1, perRepoCalls)
}

// An archived repo's leaked credential is still a live credential: archiving
// freezes commits, it does not rotate secrets. A blanket archived filter would
// drop open secret alerts for credentials that are still valid.
func TestCollectGHAS_ArchivedRepoKeepsSecretsDropsCodeScanning(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orgs/org/code-scanning/alerts", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "[%s]", codeAlertJSON("org/old", 8))
	})
	mux.HandleFunc("GET /orgs/org/secret-scanning/alerts", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "[%s]", secretAlertJSON("org/old", 9))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	fs, _ := c.collectGHAS(context.Background(), srv.URL, "tok-archived-split",
		[]repo{{Name: "old", FullName: "org/old", Archived: true}})

	require.Equal(t, []string{"ghas_secrets:org/old:9"}, findingIDs(fs))
}

// A NON-rate-limited 403 on the org endpoint is a missing org-level scope, not
// an unlicensed org: the App may still hold repo-scoped
// secret_scanning_alerts:read. Writing the whole org off instead of falling
// back would hide nearly every secret alert the installation can read.
func TestCollectGHAS_Org403FallsBackPerRepo(t *testing.T) {
	mux := http.NewServeMux()
	forbidden := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // no X-RateLimit-Remaining: 0
	}
	mux.HandleFunc("GET /orgs/org/code-scanning/alerts", forbidden)
	mux.HandleFunc("GET /orgs/org/secret-scanning/alerts", forbidden)
	mux.HandleFunc("GET /repos/org/repo0/secret-scanning/alerts", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "[%s]", secretAlertJSON("org/repo0", 3))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	fs, _ := c.collectGHAS(context.Background(), srv.URL, "tok-403-scope", ghasTestRepos())

	require.Equal(t, []string{"ghas_secrets:org/repo0:3"}, findingIDs(fs),
		"an org-scope 403 must fall back to per-repo, not write off the org")
}

func TestOrgEndpointUnavailable(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("doJSON: %w", err) }
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"404 older GHES", wrap(&apiError{status: 404}), true},
		{"403 missing org scope", wrap(&apiError{status: 403}), true},
		{"403 rate limited", wrap(&apiError{status: 403, rateLimited: true}), false},
		{"502", wrap(&apiError{status: 502}), false},
		{"rate limit wait", wrap(errRateLimitWait), false},
		{"network error", errors.New("connection refused"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, orgEndpointUnavailable(tt.err))
		})
	}
}

// A 403 with X-RateLimit-Remaining: 0 is budget exhaustion — the repos are
// skipped (no per-repo fallback hammering an empty budget), never classified
// as "GHAS not licensed".
func TestCollectGHAS_403RateLimited_NoFallback(t *testing.T) {
	mux := http.NewServeMux()
	rateLimited := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	}
	mux.HandleFunc("GET /orgs/org/code-scanning/alerts", rateLimited)
	mux.HandleFunc("GET /orgs/org/secret-scanning/alerts", rateLimited)
	mux.HandleFunc("GET /repos/", func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("rate-limited org call must not fall back per-repo: %s", r.URL.Path)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	fs, _ := c.collectGHAS(context.Background(), srv.URL, "tok-403-ratelimited", ghasTestRepos())
	require.Empty(t, fs)
}

func TestClassifyGHASErr(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("doJSON: %w", err) }
	tests := []struct {
		name string
		err  error
		want ghasSkip
	}{
		{"nil", nil, skipNone},
		{"404 not enabled", wrap(&apiError{status: 404}), skipUnlicensed},
		{"403 unlicensed", wrap(&apiError{status: 403}), skipUnlicensed},
		{"403 rate limited", wrap(&apiError{status: 403, rateLimited: true}), skipRateLimit},
		{"rate limit wait past deadline", wrap(errRateLimitWait), skipRateLimit},
		{"ctx deadline", wrap(context.DeadlineExceeded), skipRateLimit},
		{"5xx after retries", wrap(&apiError{status: 502}), skipOther},
		{"network error", errors.New("connection refused"), skipOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, classifyGHASErr(tt.err))
		})
	}
}

func TestIsGHASSkippable_RateLimited403IsNotSkippable(t *testing.T) {
	require.True(t, isGHASSkippable(fmt.Errorf("x: %w", &apiError{status: 403})))
	require.True(t, isGHASSkippable(fmt.Errorf("x: %w", &apiError{status: 404})))
	require.False(t, isGHASSkippable(fmt.Errorf("x: %w", &apiError{status: 403, rateLimited: true})))
	require.False(t, isGHASSkippable(fmt.Errorf("x: %w", errRateLimitWait)))
}

func TestDoJSON_Retries5xx(t *testing.T) {
	var calls int
	mux := http.NewServeMux()
	mux.HandleFunc("GET /flaky", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/flaky", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer tok-5xx-recover")

	var out struct {
		OK bool `json:"ok"`
	}
	require.NoError(t, c.doJSON(req, http.StatusOK, &out))
	require.True(t, out.OK)
	require.Equal(t, 3, calls)
}

func TestDoJSON_Persistent5xxFails(t *testing.T) {
	var calls int
	mux := http.NewServeMux()
	mux.HandleFunc("GET /down", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/down", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer tok-5xx-persistent")

	var out any
	err = c.doJSON(req, http.StatusOK, &out)
	require.ErrorContains(t, err, "unexpected status 502")
	require.Equal(t, 3, calls, "5xx is retried twice, then surfaced")
}

// A page-2+ failure returns the repos collected so far instead of aborting
// the connector (a late-page 502 must not throw away every repo already listed).
func TestListRepos_PartialOnLatePageFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page >= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"repositories":[`)
		for i := 0; i < perPage; i++ {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"name":"repo%d","full_name":"org/repo%d"}`, i, i)
		}
		fmt.Fprint(w, `]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	repos, partial, err := c.listRepos(context.Background(), srv.URL, "tok-partial-list")
	require.NoError(t, err)
	require.Len(t, repos, perPage)
	require.True(t, partial, "a mid-pagination failure marks the listing partial")
}

func TestListRepos_FirstPageFailureStillFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /installation/repositories", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	_, partial, err := c.listRepos(context.Background(), srv.URL, "tok-page1-fail")
	require.ErrorContains(t, err, "listRepos: page 1")
	require.False(t, partial, "a page-1 failure is fatal, not partial")
}

// GitHub returns the plaintext of every leaked secret in a secret-scanning
// listing unless hide_secret=true is passed. The collector never needs the
// secret itself, so every listing it reads (org and per-repo, open and
// resolved) asks GitHub to leave it out.
func TestSecretScanningListings_HideSecret(t *testing.T) {
	var mu sync.Mutex
	hidden := map[string]string{}
	record := func(scope string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hidden[scope+" "+r.URL.Query().Get("state")] = r.URL.Query().Get("hide_secret")
			mu.Unlock()
			fmt.Fprint(w, "[]")
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orgs/org/secret-scanning/alerts", record("org"))
	mux.HandleFunc("GET /repos/org/repo0/secret-scanning/alerts", record("repo"))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx := context.Background()
	c := newTestCollector(srv)
	r := ghasTestRepos()[0]
	cutoff := time.Now().Add(-time.Hour)

	_, err := c.orgSecretScanningFindings(ctx, srv.URL, "tok-hide", "org", map[string]repo{r.FullName: r})
	require.NoError(t, err)
	_, skip := c.repoSecretScanningAlerts(ctx, srv.URL, "tok-hide", r)
	require.Equal(t, skipNone, skip)
	c.orgClosedGHAS(ctx, srv.URL, "tok-hide", "org", false, true, nil, map[string]repo{r.FullName: r}, cutoff)
	c.repoClosedSecretScanning(ctx, srv.URL, "tok-hide", r, cutoff)

	require.Equal(t, map[string]string{
		"org open":      "true",
		"repo open":     "true",
		"org resolved":  "true",
		"repo resolved": "true",
	}, hidden)
}
