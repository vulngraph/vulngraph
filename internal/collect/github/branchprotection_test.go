package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// bpFake serves the GraphQL branch-protection query. protected lists the
// repositories whose default branch has a rule; notFound makes a repository
// answer with a per-alias error (the shape GitHub uses for a repo the token
// cannot resolve); noDefaultBranch makes it answer with a null defaultBranchRef.
type bpFake struct {
	protected map[string]bool
	notFound  map[string]bool
	// forbidden answers with DATA (a null rule) alongside a field-level error —
	// the shape GitHub uses when a token may read the repo but not its
	// protection. The data alone is indistinguishable from "unprotected".
	forbidden       map[string]bool
	noDefaultBranch map[string]bool
	status          int // non-zero overrides the response status
	// rejectAbove makes the fake answer HTTP 200 with `data: null` and a
	// query-level error (no `path`) whenever a query asks about more than this
	// many repositories — the shape GitHub uses to reject a query for complexity,
	// timeout or secondary rate limit. Zero disables it.
	rejectAbove int
	// rejectAll rejects every query the same way, however small — the case where
	// the data is genuinely unobservable and no amount of splitting helps.
	rejectAll bool

	mu       sync.Mutex
	requests int
	rejected int
	batches  []int // repositories asked about per request
}

// bpQueryRe pulls (alias, owner, name) triples out of the generated query. The
// fake parses the real query text rather than replaying a canned response, so a
// change to the query shape shows up here.
var bpQueryRe = regexp.MustCompile(`(r\d+): repository\(owner:"([^"]+)", name:"([^"]+)"\)`)

func (f *bpFake) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Reset", "1")
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		var in struct {
			Query string `json:"query"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		require.NotEmpty(t, in.Query, "a retried request must replay its body")
		if n := len(bpQueryRe.FindAllStringSubmatch(in.Query, -1)); f.rejectAll || (f.rejectAbove > 0 && n > f.rejectAbove) {
			f.mu.Lock()
			f.requests++
			f.rejected++
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"data":   nil,
				"errors": []map[string]any{{"message": "Query has complexity of 200100, which exceeds max complexity of 500000"}},
			}))
			return
		}

		type errEntry struct {
			Type string `json:"type"`
			Path []any  `json:"path"`
		}
		data := map[string]any{}
		var errs []errEntry
		matches := bpQueryRe.FindAllStringSubmatch(in.Query, -1)
		for _, m := range matches {
			alias, full := m[1], m[2]+"/"+m[3]
			switch {
			case f.notFound[full]:
				data[alias] = nil
				errs = append(errs, errEntry{Type: "NOT_FOUND", Path: []any{alias}})
			case f.forbidden[full]:
				data[alias] = map[string]any{"nameWithOwner": full,
					"defaultBranchRef": map[string]any{"branchProtectionRule": nil}}
				errs = append(errs, errEntry{Type: "FORBIDDEN",
					Path: []any{alias, "defaultBranchRef", "branchProtectionRule"}})
			case f.noDefaultBranch[full]:
				data[alias] = map[string]any{"nameWithOwner": full, "defaultBranchRef": nil}
			case f.protected[full]:
				data[alias] = map[string]any{"nameWithOwner": full,
					"defaultBranchRef": map[string]any{"branchProtectionRule": map[string]any{"id": "BPR_1"}}}
			default:
				data[alias] = map[string]any{"nameWithOwner": full,
					"defaultBranchRef": map[string]any{"branchProtectionRule": nil}}
			}
		}

		f.mu.Lock()
		f.requests++
		f.batches = append(f.batches, len(matches))
		f.mu.Unlock()

		out := map[string]any{"data": data}
		if len(errs) > 0 {
			out["errors"] = errs
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(out))
	}
}

func bpServer(t *testing.T, f *bpFake) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /graphql", f.handler(t))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func bpRepos(names ...string) []repo {
	out := make([]repo, 0, len(names))
	for _, n := range names {
		out = append(out, repo{FullName: n, DefaultBranch: "main"})
	}
	return out
}

// TestCollectBranchProtection_OnlyRecordsObservations is the fail-unknown
// contract: a rule present is "enabled", a rule genuinely absent is "disabled",
// and anything we could not read carries NO state at all. Mapping an unreadable
// repo to "unprotected" is what turned a missing administration:read permission
// into a flood of false findings.
func TestCollectBranchProtection_OnlyRecordsObservations(t *testing.T) {
	f := &bpFake{
		protected:       map[string]bool{"org/protected": true},
		notFound:        map[string]bool{"org/gone": true},
		forbidden:       map[string]bool{"org/no-permission": true},
		noDefaultBranch: map[string]bool{"org/empty": true},
	}
	srv := bpServer(t, f)
	c := newTestCollector(srv)

	repos := append(bpRepos("org/protected", "org/unprotected", "org/gone", "org/no-permission", "org/empty"),
		repo{FullName: "org/archived", DefaultBranch: "main", Archived: true},
		repo{FullName: "org/no-branch"})

	got := c.collectBranchProtection(context.Background(), srv.URL, "tok", repos)

	require.Equal(t, branchProtectionEnabled, got["org/protected"])
	require.Equal(t, branchProtectionDisabled, got["org/unprotected"], "a null rule on a readable repo IS an observation")
	for _, unknown := range []string{"org/gone", "org/no-permission", "org/empty", "org/archived", "org/no-branch"} {
		require.NotContains(t, got, unknown, "%s was never observed and must carry no state", unknown)
	}
	require.Len(t, got, 2)
}

// TestCollectBranchProtection_BatchesByHundred is the rate-limit budget itself:
// the per-repo REST endpoint spent one call per repo (thousands per sweep against a
// 5,000/hour budget) and starved. 250 repos must cost 3 requests, not 250.
func TestCollectBranchProtection_BatchesByHundred(t *testing.T) {
	names := make([]string, 0, 250)
	protected := map[string]bool{}
	for i := range 250 {
		n := fmt.Sprintf("org/repo%d", i)
		names = append(names, n)
		if i%2 == 0 {
			protected[n] = true
		}
	}
	f := &bpFake{protected: protected}
	srv := bpServer(t, f)
	c := newTestCollector(srv)

	got := c.collectBranchProtection(context.Background(), srv.URL, "tok", bpRepos(names...))

	require.Len(t, got, 250)
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Equal(t, 3, f.requests, "250 repos must cost 3 GraphQL requests")
	require.Equal(t, []int{100, 100, 50}, f.batches)
}

// TestCollectBranchProtection_UniformAbsenceIsAPermissionGap guards the one
// failure mode GraphQL introduces that REST did not have: a token without
// administration:read does not error, it answers branchProtectionRule: null —
// byte-identical to a genuinely unprotected branch. Across a large estate a
// uniform zero is not credible, so it must read as unknown, not as an estate of
// entirely unprotected repositories.
func TestCollectBranchProtection_UniformAbsenceIsAPermissionGap(t *testing.T) {
	names := make([]string, 0, 200)
	for i := range 200 {
		names = append(names, fmt.Sprintf("org/repo%d", i))
	}
	f := &bpFake{} // nothing protected anywhere
	srv := bpServer(t, f)
	c := newTestCollector(srv)

	got := c.collectBranchProtection(context.Background(), srv.URL, "tok", bpRepos(names...))
	require.Empty(t, got, "0 protected of 200 is a broken read, not 200 findings")
}

// …and the same shape on a small installation is a real answer: a handful of
// repositories genuinely can all be unprotected, and suppressing that would be
// a false negative.
func TestCollectBranchProtection_SmallEstateAllUnprotectedIsObserved(t *testing.T) {
	names := make([]string, 0, 10)
	for i := range 10 {
		names = append(names, fmt.Sprintf("org/repo%d", i))
	}
	srv := bpServer(t, &bpFake{})
	c := newTestCollector(srv)

	got := c.collectBranchProtection(context.Background(), srv.URL, "tok", bpRepos(names...))
	require.Len(t, got, 10)
	for _, state := range got {
		require.Equal(t, branchProtectionDisabled, state)
	}
}

// A failed batch leaves its whole batch unobserved — never 100 repos silently
// stamped "disabled".
func TestCollectBranchProtection_FailedBatchOmitsKeys(t *testing.T) {
	srv := bpServer(t, &bpFake{status: http.StatusForbidden})
	c := newTestCollector(srv)

	got := c.collectBranchProtection(context.Background(), srv.URL, "tok", bpRepos("org/a", "org/b"))
	require.Empty(t, got)
}

func TestGraphQLURL(t *testing.T) {
	require.Equal(t, "https://api.github.com/graphql", graphQLURL("https://api.github.com"))
	require.Equal(t, "https://api.github.com/graphql", graphQLURL("https://api.github.com/"))
	require.Equal(t, "https://ghe.corp/api/graphql", graphQLURL("https://ghe.corp/api/v3"))
}

// retryClone must rewind the body: doJSON retries by cloning the request, and a
// clone of a consumed POST body would send the GraphQL query as an empty
// document.
func TestRetryCloneReplaysBody(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.test",
		strings.NewReader(`{"query":"x"}`))
	require.NoError(t, err)

	first, err := readAllBody(req)
	require.NoError(t, err)
	require.Equal(t, `{"query":"x"}`, first)

	again, err := readAllBody(retryClone(req))
	require.NoError(t, err)
	require.Equal(t, `{"query":"x"}`, again, "the retried request must carry the same body")
}

func readAllBody(req *http.Request) (string, error) {
	if req.Body == nil {
		return "", nil
	}
	defer func() { _ = req.Body.Close() }()
	b, err := io.ReadAll(req.Body)
	return string(b), err
}

// A query-level GraphQL rejection is HTTP 200 with `data: null` and an error
// carrying no `path`. Read alias-by-alias that is indistinguishable from "every
// repository in this batch returned nothing", so without this guard the batch
// returns an empty map and a NIL ERROR: nothing is logged, nothing is retried,
// and branch_protection stays absent on every repository of a large connector
// while a small connector works fine.
func TestCollectBranchProtection_QueryLevelRejectionIsNotAnObservation(t *testing.T) {
	f := &bpFake{rejectAll: true}
	srv := bpServer(t, f)
	c := newTestCollector(srv)

	// Rejected however small, so nothing is observable and nothing may be guessed.
	got := c.collectBranchProtection(context.Background(), srv.URL, "tok", bpRepos("org/a", "org/b"))
	require.Empty(t, got, "a rejected query must never be read as 'unprotected'")
	require.Positive(t, f.rejected)
}

// And the recovery: a batch too large for the API is halved until it is accepted,
// so a large estate is fully observed rather than blacked out.
func TestCollectBranchProtection_SplitsUntilTheQueryIsAccepted(t *testing.T) {
	names := make([]string, 0, 250)
	protected := map[string]bool{}
	for i := range 250 {
		n := fmt.Sprintf("org/r%d", i)
		names = append(names, n)
		if i%2 == 0 {
			protected[n] = true
		}
	}
	f := &bpFake{protected: protected, rejectAbove: 40}
	srv := bpServer(t, f)
	c := newTestCollector(srv)

	got := c.collectBranchProtection(context.Background(), srv.URL, "tok", bpRepos(names...))

	require.Len(t, got, 250, "every repository must be observed once the batches are small enough")
	require.Equal(t, branchProtectionEnabled, got["org/r0"])
	require.Equal(t, branchProtectionDisabled, got["org/r1"])
	// Splitting must stay near the batched ideal, not degrade to one call per
	// repo — that is the rate-limit budget this whole path exists to protect.
	require.Less(t, f.requests, 40, "splitting cost %d requests for 250 repos", f.requests)
}

// An App without `administration: read` gets DATA for every repository plus a
// FIELD-level error on branchProtectionRule, so every alias is correctly
// refused and correctly not guessed at — and, without the drop accounting,
// silently discarded. The estate then observed nothing, which is below the
// uniform-null floor, so not even that guard speaks, and nothing reaches the
// logs.
//
// The contract asserted here is the one that matters for scoring: an unreadable
// estate yields NO keys, so `github-no-branch-protection` sees missing data
// rather than a clean result.
func TestCollectBranchProtection_ForbiddenEstateObservesNothing(t *testing.T) {
	names := make([]string, 0, 120)
	forbidden := map[string]bool{}
	for i := range 120 {
		n := fmt.Sprintf("org/r%d", i)
		names = append(names, n)
		forbidden[n] = true
	}
	srv := bpServer(t, &bpFake{forbidden: forbidden})
	c := newTestCollector(srv)

	got := c.collectBranchProtection(context.Background(), srv.URL, "tok", bpRepos(names...))
	require.Empty(t, got,
		"a repo whose protection the token may not read must carry no state — reading the null rule as 'disabled' is what produced a flood of false findings")
}
