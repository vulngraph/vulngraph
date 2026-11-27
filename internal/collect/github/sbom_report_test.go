package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const (
	sbomTestAPI    = "https://api.github.com"
	sbomTestPrefix = sbomTestAPI + "/repos/org/repo/dependency-graph/sbom/"
	sbomTestReport = sbomTestPrefix + "fetch-report/" + sbomFixtureUUID
	sbomTestURL    = "https://reports.example.test/report.json?signature=fixture-do-not-log"
	sbomTestDoc    = `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","packages":[{"externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/example@1.0.0"}]}]}`
)

func sbomReply(r *http.Request, status int, body, location string) *http.Response {
	resp := collectbench.Response(r, body)
	resp.StatusCode = status
	if location != "" {
		resp.Header.Set("Location", location)
	}
	return resp
}

func sbomTestCollector(fn func(*http.Request) (*http.Response, error)) *Collector {
	rateLimitStates.Delete("sbom-fixture-token")
	c := New()
	c.client = &http.Client{Transport: collectbench.Transport(fn)}
	c.sbomWait = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	return c
}

func TestSBOMReportPendingRedirectsAndCredentialIsolation(t *testing.T) {
	var apiCalls, downloads int
	var waits []time.Duration
	c := sbomTestCollector(func(r *http.Request) (*http.Response, error) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Empty(t, r.Header.Get("Cookie"))
		require.Empty(t, r.Header.Get("Referer"))
		if r.URL.Host == "api.github.com" {
			apiCalls++
			require.Equal(t, "Bearer sbom-fixture-token", r.Header.Get("Authorization"))
			require.Equal(t, sbomAPIVersion, r.Header.Get("X-GitHub-Api-Version"))
			if strings.HasSuffix(r.URL.Path, "/generate-report") {
				return sbomReply(r, 201, jsonString(map[string]string{"sbom_url": sbomTestReport}), ""), nil
			}
			if apiCalls == 2 {
				resp := sbomReply(r, 202, "", "")
				resp.Header.Set("Retry-After", "3")
				return resp, nil
			}
			return sbomReply(r, 302, "", sbomTestURL), nil
		}
		downloads++
		require.Empty(t, r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get("X-GitHub-Api-Version"))
		if downloads == 1 {
			return sbomReply(r, 307, "", "https://cdn.example.test/ready.json?signature=fixture-other"), nil
		}
		return sbomReply(r, 200, sbomTestDoc, ""), nil
	})
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	for _, raw := range []string{sbomTestAPI, sbomTestURL} {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		jar.SetCookies(u, []*http.Cookie{{Name: "credential", Value: "must-not-forward"}})
	}
	c.client.Jar = jar
	c.client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("original redirect policy") }
	c.sbomWait = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	pkgs, err := c.fetchSBOM(t.Context(), sbomTestAPI, "sbom-fixture-token", "org/repo")
	require.NoError(t, err)
	require.Equal(t, []pkgCoords{{Ecosystem: "npm", Name: "example", Version: "1.0.0", Purl: "pkg:npm/example@1.0.0"}}, pkgs)
	require.Equal(t, 3, apiCalls)
	require.Equal(t, 2, downloads)
	require.Equal(t, []time.Duration{3 * time.Second}, waits)
	require.Same(t, jar, c.client.Jar, "per-call clone must not mutate the shared client")
	require.EqualError(t, c.client.CheckRedirect(nil, nil), "original redirect policy")
}

func TestSBOMReportRejectsUnauthorizedPollURLsAndAPIRedirects(t *testing.T) {
	for _, raw := range []string{
		"https://other.example/repos/org/repo/dependency-graph/sbom/fetch-report/" + sbomFixtureUUID,
		strings.Replace(sbomTestReport, "/org/repo/", "/org/other/", 1),
		strings.Replace(sbomTestReport, "https:", "http:", 1),
		strings.Replace(sbomTestReport, "https://", "https://user:password@", 1),
		sbomTestReport + "?token=private", sbomTestReport + "#fragment",
		strings.Replace(sbomTestReport, "fetch-report/", "fetch-report/../", 1),
		strings.Replace(sbomTestReport, sbomFixtureUUID, "not-a-uuid", 1),
		"/repos/org/repo/dependency-graph/sbom/fetch-report/" + sbomFixtureUUID,
	} {
		t.Run(raw, func(t *testing.T) {
			calls := 0
			c := sbomTestCollector(func(r *http.Request) (*http.Response, error) {
				calls++
				return sbomReply(r, 201, jsonString(map[string]string{"sbom_url": raw}), ""), nil
			})
			_, err := c.fetchSBOM(t.Context(), sbomTestAPI, "sbom-fixture-token", "org/repo")
			require.Error(t, err)
			require.NotContains(t, err.Error(), "private")
			require.Equal(t, 1, calls)
		})
	}
	calls := 0
	c := sbomTestCollector(func(r *http.Request) (*http.Response, error) {
		calls++
		return sbomReply(r, 302, "", "https://other.example/steal"), nil
	})
	_, err := c.fetchSBOM(t.Context(), sbomTestAPI, "sbom-fixture-token", "org/repo")
	require.Error(t, err)
	require.Equal(t, 1, calls, "authenticated generation redirect must not be followed")
}

func TestSBOMReportBoundsPendingAndRetries(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		wantCalls  int
		wantDelays int
	}{
		{"pending", 202, 1 + sbomMaxPolls, sbomMaxPolls - 1},
		{"rate-limit", 429, 1 + sbomMaxAttempts, sbomMaxAttempts - 1},
		{"upstream", 503, 1 + sbomMaxAttempts, sbomMaxAttempts - 1},
		{"denied", 403, 2, 0}, {"missing", 404, 2, 0}, {"old-pending-status", 201, 2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, delays := 0, 0
			c := sbomTestCollector(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return sbomReply(r, 201, jsonString(map[string]string{"sbom_url": sbomTestReport}), ""), nil
				}
				resp := sbomReply(r, tc.status, "", "")
				if tc.status == 429 {
					resp.Header.Set("Retry-After", "1")
				}
				return resp, nil
			})
			c.sbomWait = func(_ context.Context, d time.Duration) error {
				require.LessOrEqual(t, d, 8*time.Second)
				delays++
				return nil
			}
			_, err := c.fetchSBOM(t.Context(), sbomTestAPI, "sbom-fixture-token", "org/repo")
			require.Error(t, err)
			require.Equal(t, tc.wantCalls, calls)
			require.Equal(t, tc.wantDelays, delays)
		})
	}
}

func TestSBOMReportCancellationAndRetryAfterDeadline(t *testing.T) {
	for _, retryAfter := range []string{"3600", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)} {
		calls := 0
		c := sbomTestCollector(func(r *http.Request) (*http.Response, error) {
			calls++
			resp := sbomReply(r, 429, "", "")
			resp.Header.Set("Retry-After", retryAfter)
			return resp, nil
		})
		_, err := c.fetchSBOM(t.Context(), sbomTestAPI, "sbom-fixture-token", "org/repo")
		require.ErrorContains(t, err, "deadline")
		require.Equal(t, 1, calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	c := sbomTestCollector(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "generate-report") {
			return sbomReply(r, 201, jsonString(map[string]string{"sbom_url": sbomTestReport}), ""), nil
		}
		cancel()
		return sbomReply(r, 202, "", ""), nil
	})
	_, err := c.fetchSBOM(ctx, sbomTestAPI, "sbom-fixture-token", "org/repo")
	require.ErrorIs(t, err, context.Canceled)
}

func TestSBOMReportRetryRecoveryAndServerIntervals(t *testing.T) {
	for _, status := range []int{429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls, waits := 0, 0
			c := sbomTestCollector(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return sbomReply(r, status, "", ""), nil
				}
				if strings.HasSuffix(r.URL.Path, "generate-report") {
					return sbomReply(r, 201, jsonString(map[string]string{"sbom_url": sbomTestReport}), ""), nil
				}
				if r.URL.Host == "api.github.com" {
					return sbomReply(r, 302, "", sbomTestURL), nil
				}
				return sbomReply(r, 200, sbomTestDoc, ""), nil
			})
			c.sbomWait = func(_ context.Context, d time.Duration) error {
				waits++
				if status == 429 {
					require.Equal(t, time.Minute, d)
				}
				return nil
			}
			_, err := c.fetchSBOM(t.Context(), sbomTestAPI, "sbom-fixture-token", "org/repo")
			require.NoError(t, err)
			require.Equal(t, 4, calls)
			require.Equal(t, 1, waits)
		})
	}
	resp := &http.Response{StatusCode: 202, Header: http.Header{"Retry-After": {"3"}, "X-Poll-Interval": {"15"}}}
	require.Equal(t, 15*time.Second, sbomDelay(resp, 0))
	resp = &http.Response{StatusCode: 429, Header: http.Header{}}
	require.Equal(t, 2*time.Minute, sbomDelay(resp, 1))
}

func TestSBOMReportDownloadValidationAndErrorsDoNotLeakURL(t *testing.T) {
	for _, tc := range []struct {
		name, location, body string
		status               int
		wantError            bool
	}{
		{"raw", sbomTestURL, sbomTestDoc, 200, false},
		{"envelope", sbomTestURL, `{"sbom":` + sbomTestDoc + `}`, 200, false},
		{"empty", sbomTestURL, `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","packages":[]}`, 200, false},
		{"malformed", sbomTestURL, `{}`, 200, true},
		{"missing-packages", sbomTestURL, `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3"}`, 200, true},
		{"null-packages", sbomTestURL, `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","packages":null}`, 200, true},
		{"invalid-json", sbomTestURL, `{`, 200, true},
		{"expired", sbomTestURL, "", 404, true},
		{"insecure", "http://reports.example.test/report?signature=fixture-do-not-log", "", 200, true},
		{"userinfo", "https://token:password@reports.example.test/report", "", 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := sbomTestCollector(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "generate-report") {
					return sbomReply(r, 201, jsonString(map[string]string{"sbom_url": sbomTestReport}), ""), nil
				}
				if r.URL.Host == "api.github.com" {
					return sbomReply(r, 302, "", tc.location), nil
				}
				require.Empty(t, r.Header.Get("Authorization"))
				return sbomReply(r, tc.status, tc.body, ""), nil
			})
			_, err := c.fetchSBOM(t.Context(), sbomTestAPI, "sbom-fixture-token", "org/repo")
			if tc.wantError {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "fixture-do-not-log")
			} else {
				require.NoError(t, err)
			}
		})
	}
	cause := errors.New("connection failed: " + sbomTestURL)
	c := sbomTestCollector(func(*http.Request) (*http.Response, error) { return nil, cause })
	client := *c.client
	_, err := c.downloadSBOM(t.Context(), &client, sbomTestURL)
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "transport or response read failed")
	require.NotContains(t, err.Error(), "fixture-do-not-log")
}

func TestSBOMReportPrimaryRateLimitBeyondDeadline(t *testing.T) {
	calls := 0
	c := sbomTestCollector(func(r *http.Request) (*http.Response, error) {
		calls++
		resp := sbomReply(r, 201, jsonString(map[string]string{"sbom_url": sbomTestReport}), "")
		resp.Header.Set("X-RateLimit-Remaining", "0")
		resp.Header.Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(time.Hour).Unix()))
		return resp, nil
	})
	_, err := c.fetchSBOM(t.Context(), sbomTestAPI, "sbom-fixture-token", "org/repo")
	require.ErrorIs(t, err, errRateLimitWait)
	require.Equal(t, 1, calls)
	rateLimitStates.Delete("sbom-fixture-token")
}

func TestSBOMReportDownloadBoundsAndPrivateAddressGuard(t *testing.T) {
	calls := 0
	c := sbomTestCollector(func(r *http.Request) (*http.Response, error) {
		calls++
		return sbomReply(r, 302, "", sbomTestURL), nil
	})
	client := *c.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	_, err := c.downloadSBOM(t.Context(), &client, sbomTestURL)
	require.ErrorContains(t, err, "redirect limit")
	require.Equal(t, sbomMaxRedirects+1, calls)
	for _, limit := range []int64{sbomMaxGenerateBytes, sbomMaxReportBytes} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			resp := &http.Response{Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", int(limit)+1)))}
			var doc sbomDocument
			require.ErrorContains(t, decodeSBOMResponse(resp, &doc, limit), "byte limit")
		})
	}
	guarded := safenet.New(time.Second)
	_, err = c.downloadSBOM(t.Context(), guarded, "https://169.254.169.254/report?signature=fixture-do-not-log")
	require.Error(t, err, "original guarded transport must block metadata/private destinations")
	require.NotContains(t, err.Error(), "fixture-do-not-log")
	transport := guarded.Transport
	guarded.Transport = collectbench.Transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "reports.example.test" {
			return sbomReply(r, 302, "", "https://169.254.169.254/report?signature=fixture-do-not-log"), nil
		}
		return transport.RoundTrip(r)
	})
	guarded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	_, err = c.downloadSBOM(t.Context(), guarded, sbomTestURL)
	require.Error(t, err, "redirect destinations must retain dial-time protection")
	require.NotContains(t, err.Error(), "fixture-do-not-log")
}

func TestSBOMReportCoverageDistinguishesEmptyFromUnavailable(t *testing.T) {
	srv := fakeGitHubWithSBOM(t, 2, map[string][]string{"org/repo0": {}})
	result, err := newTestCollector(srv).Collect(t.Context(), validConfig(t))
	require.NoError(t, err)
	require.True(t, result.Partial)
	coverage := map[string]string{}
	for _, a := range result.Assets {
		if a.Type == "github_repo" {
			coverage[a.ID] = a.Metadata["sbom_coverage"]
		}
	}
	require.Equal(t, map[string]string{"org/repo0": "complete", "org/repo1": "unknown"}, coverage)
	for _, scope := range result.CompletedEnumerations {
		require.NotContains(t, scope.Types, "package", "incomplete reports cannot authorize package retirement")
	}
}

func TestSBOMReportCanceledBeforeAdmissionMakesNoRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c := sbomTestCollector(func(*http.Request) (*http.Response, error) {
		t.Error("canceled collection must not make a report request")
		return nil, context.Canceled
	})
	repos := make([]repo, 20)
	for i := range repos {
		repos[i].FullName = fmt.Sprintf("org/repo%d", i)
	}
	assets, edges, coverage := c.collectPackages(ctx, sbomTestAPI, "sbom-fixture-token", repos)
	require.Empty(t, assets)
	require.Empty(t, edges)
	require.Len(t, coverage, len(repos))
	for _, value := range coverage {
		require.Equal(t, "unknown", value)
	}
}
