package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepositoryReadCacheBoundariesAndMutationIsolation(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if strings.Contains(r.URL.Path, "/git/trees/") {
			_, _ = w.Write([]byte(`{"tree":[{"path":"a.yml","type":"blob"}],"truncated":false}`))
			return
		}
		_ = json.NewEncoder(w).Encode(contentResponse{Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte(r.Header.Get("Authorization") + r.URL.String()))})
	}))
	defer srv.Close()
	c := New()
	c.client = srv.Client()
	ctx, cache := withRepositoryReadCache(t.Context())
	defer cache.close()
	r := repo{FullName: "org/repo", DefaultBranch: "main"}
	tree, ok := c.repoTree(ctx, srv.URL, "token", r)
	require.True(t, ok)
	tree.Tree[0].Path = "mutated"
	tree, ok = c.repoTree(ctx, srv.URL, "token", r)
	require.True(t, ok)
	require.Equal(t, "a.yml", tree.Tree[0].Path)
	require.EqualValues(t, 1, calls.Load())
	for _, tc := range []struct{ base, token, repo, ref, path string }{
		{srv.URL, "token", "org/repo", "main", "a.yml"},
		{srv.URL, "different-token", "org/repo", "main", "a.yml"},
		{srv.URL + "/api/v3", "token", "org/repo", "main", "a.yml"},
		{srv.URL, "token", "org/other", "main", "a.yml"},
		{srv.URL, "token", "org/repo", "other-ref", "a.yml"},
		{srv.URL, "token", "org/repo", "main", "other.yml"},
	} {
		before := calls.Load()
		input := repo{FullName: tc.repo, DefaultBranch: tc.ref}
		first, ok := c.fetchFileContent(ctx, tc.base, tc.token, input, tc.path)
		require.True(t, ok)
		second, ok := c.fetchFileContent(ctx, tc.base, tc.token, input, tc.path)
		require.True(t, ok)
		require.Equal(t, first, second)
		require.Equal(t, before+1, calls.Load(), "authorization/base/repo/ref/path must partition reuse")
	}
	before := calls.Load()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, ok = c.fetchFileContent(cancelled, srv.URL, "token", r, "a.yml")
	require.False(t, ok)
	_, ok = c.repoTree(cancelled, srv.URL, "token", r)
	require.False(t, ok)
	require.Equal(t, before, calls.Load(), "cancelled callers cannot consume cached success")
	cache.close()
	require.Nil(t, cache.files)
	require.Nil(t, cache.trees)
	fresh, next := withRepositoryReadCache(t.Context())
	defer next.close()
	_, ok = c.fetchFileContent(fresh, srv.URL, "token", r, "a.yml")
	require.True(t, ok)
	require.Equal(t, before+1, calls.Load(), "a new repository/sync must read again")
}

func TestRepositoryReadCacheDoesNotRetainFailedOrPartialReads(t *testing.T) {
	for _, first := range []string{"denied", "malformed", "invalid-base64", "oversized", "truncated", "missing-tree"} {
		t.Run(first, func(t *testing.T) {
			var calls atomic.Int64
			treeCase := first == "truncated" || first == "missing-tree"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 {
					switch first {
					case "denied":
						w.WriteHeader(http.StatusForbidden)
					case "malformed":
						_, _ = w.Write([]byte(`{"content":`))
					case "invalid-base64":
						_, _ = w.Write([]byte(`{"encoding":"base64","content":"!!!"}`))
					case "oversized":
						_ = json.NewEncoder(w).Encode(contentResponse{Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", iacMaxFileBytes+1)))})
					case "truncated":
						_, _ = w.Write([]byte(`{"tree":[],"truncated":true}`))
					case "missing-tree":
						_, _ = w.Write([]byte(`{}`))
					}
					return
				}
				if treeCase {
					_, _ = w.Write([]byte(`{"tree":[],"truncated":false}`))
				} else {
					_, _ = w.Write([]byte(`{"encoding":"base64","content":"b2s="}`))
				}
			}))
			defer srv.Close()
			c := New()
			c.client = srv.Client()
			ctx, cache := withRepositoryReadCache(t.Context())
			defer cache.close()
			r := repo{FullName: "org/repo", DefaultBranch: "main"}
			read := func() bool {
				if treeCase {
					_, complete := c.workflowPathsChecked(ctx, srv.URL, "token", r)
					return complete
				}
				_, ok := c.fetchFileContent(ctx, srv.URL, "token", r, "a.yml")
				return ok
			}
			require.False(t, read())
			require.True(t, read(), "later reader must be able to recover")
			require.True(t, read())
			require.EqualValues(t, 2, calls.Load())
		})
	}
}

func TestRepositoryReadCacheBoundsBypassRetention(t *testing.T) {
	for _, size := range []int{1, iacMaxFileBytes} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var calls atomic.Int64
			body := jsonString(contentResponse{Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", size)))})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = w.Write([]byte(body)) }))
			defer srv.Close()
			c := New()
			c.client = srv.Client()
			ctx, cache := withRepositoryReadCache(t.Context())
			defer cache.close()
			r := repo{FullName: "org/repo", DefaultBranch: "main"}
			n := repositoryCacheEntries + 1
			if size > 1 {
				n = repositoryCacheBytes/size + 1
			}
			for i := range n {
				content, ok := c.fetchFileContent(ctx, srv.URL, "token", r, fmt.Sprint(i))
				require.True(t, ok)
				require.Len(t, content, size)
			}
			require.LessOrEqual(t, cache.bytes, repositoryCacheBytes)
			require.LessOrEqual(t, cache.entries, repositoryCacheEntries)
			_, ok := c.fetchFileContent(ctx, srv.URL, "token", r, fmt.Sprint(n-1))
			require.True(t, ok)
			require.EqualValues(t, n+1, calls.Load(), "overflow is fetched normally, never silently omitted")
		})
	}
}

func TestRepositorySourcesShareReadsAndReleaseRawContent(t *testing.T) {
	var trees, files atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/git/trees/") {
			trees.Add(1)
			_, _ = w.Write([]byte(`{"tree":[{"path":".github/workflows/ci.yml","type":"blob"}],"truncated":false}`))
		} else {
			files.Add(1)
			_ = json.NewEncoder(w).Encode(contentResponse{Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte(scaleWorkflow))})
		}
	}))
	defer srv.Close()
	c := New()
	c.client = srv.Client()
	var retained *repositoryReadCache
	c.workflowFile = func(ctx context.Context, base, token string, r repo, path string) (string, bool) {
		retained = repositoryCache(ctx)
		return c.fetchFileContent(ctx, base, token, r, path)
	}
	for iteration := range 2 {
		result := c.collectRepositorySources(t.Context(), srv.URL, "token", []repo{{FullName: "org/repo", DefaultBranch: "main"}}, nil, appInventory{}, "")
		require.True(t, result.Workflows.Complete)
		require.NotEmpty(t, result.Workflows.Assets)
		require.EqualValues(t, iteration+1, trees.Load())
		require.EqualValues(t, iteration+1, files.Load())
		require.True(t, retained.closed)
		require.Nil(t, retained.files)
		require.Nil(t, retained.trees)
	}
}
