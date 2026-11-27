package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
)

func TestConnectorScale(t *testing.T) {
	sizes := collectbench.Sizes(t)
	old := maxPages
	maxPages = 101
	t.Cleanup(func() { maxPages = old })
	for _, denied := range []bool{false, true} {
		name, scope := "github", "paginated repositories, SBOM, branch protection, CODEOWNERS, populated workflows, App installation grants and narrowed token scopes"
		if denied {
			name, scope = "github_denied", "installation pagination, SBOM and populated workflows, App installation grants and narrowed token scopes; denied GraphQL"
		}
		for _, n := range sizes {
			t.Run(fmt.Sprintf("%s/%d", name, n), func(t *testing.T) {
				var calls atomic.Int64
				prior := map[string]map[string]string{}
				transport := collectbench.Transport(func(req *http.Request) (*http.Response, error) {
					calls.Add(1)
					if req.URL.Host != "api.github.com" {
						return nil, fmt.Errorf("unexpected fixture host %s", req.URL.Host)
					}
					path := req.URL.Path
					body := "[]"
					status := http.StatusOK
					switch {
					case strings.HasSuffix(path, "/access_tokens"):
						body = `{"token":"fixture-scale"}`
						status = http.StatusCreated
					case path == "/app":
						body = `{"id":123,"slug":"fixture","owner":{"login":"builder"}}`
					case path == "/app/installations":
						body = `[{"id":456,"app_id":123,"app_slug":"fixture","account":{"login":"org","type":"Organization"},"repository_selection":"selected","permissions":{"contents":"write","metadata":"read"},"suspended_at":null}]`
					case path == "/orgs/org/installations":
						body = `{"installations":[{"id":456,"app_id":123,"app_slug":"fixture","account":{"login":"org","type":"Organization"},"repository_selection":"selected","permissions":{"contents":"write","metadata":"read"},"suspended_at":null}]}`
					case path == "/installation/repositories":
						page, _ := strconv.Atoi(req.URL.Query().Get("page"))
						start := (page - 1) * perPage
						repos := make([]map[string]any, 0)
						for i := start; i < min(start+perPage, n); i++ {
							visibility := "private"
							if i%2 == 0 {
								visibility = "public"
							}
							repos = append(repos, map[string]any{"name": fmt.Sprintf("repo%d", i), "full_name": fmt.Sprintf("org/repo%d", i), "default_branch": "main", "visibility": visibility, "language": "Go", "owner": map[string]string{"login": "org", "type": "Organization"}})
						}
						b, err := json.Marshal(map[string]any{"repositories": repos})
						if err != nil {
							return nil, err
						}
						body = string(b)
					case strings.HasSuffix(path, "/dependency-graph/sbom"):
						body = `{"sbom":{"packages":[{"externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/example.com/lib@v1.0.0"}]}]}}`
					case strings.Contains(path, "/git/trees/"):
						body = `{"tree":[{"path":".github/workflows/ci.yml","type":"blob"}],"truncated":false}`
					case strings.Contains(path, "/branches/"):
						body = `{"protected":true}`
					case path == "/graphql":
						if denied {
							status = http.StatusForbidden
							body = `{"message":"GraphQL unavailable in fixture"}`
						} else {
							var in struct {
								Query string `json:"query"`
							}
							if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
								return nil, err
							}
							data := map[string]any{}
							for _, m := range bpQueryRe.FindAllStringSubmatch(in.Query, -1) {
								if strings.Contains(in.Query, "branchProtectionRule") {
									data[m[1]] = map[string]any{"nameWithOwner": m[2] + "/" + m[3], "defaultBranchRef": map[string]any{"branchProtectionRule": map[string]string{"id": "protected"}}}
								} else {
									data[m[1]] = map[string]any{"f0": map[string]any{"text": "* @org/platform", "byteSize": 15, "isTruncated": false}}
								}
							}
							b, err := json.Marshal(map[string]any{"data": data})
							if err != nil {
								return nil, err
							}
							body = string(b)
						}
					case strings.HasSuffix(path, "/contents/.github/workflows/ci.yml"):
						body = jsonString(map[string]any{"encoding": "base64", "size": len(scaleWorkflow), "content": base64.StdEncoding.EncodeToString([]byte(scaleWorkflow))})
					case strings.Contains(path, "/contents/"):
						status = http.StatusNotFound
						body = `{"message":"Not Found"}`
					}
					resp := collectbench.Response(req, body)
					resp.StatusCode = status
					return resp, nil
				})
				cfg := map[string]string{"app_id": "123", "installation_id": "456", "private_key_pem": collectbench.PrivateKey(t)}
				collectbench.Run(t, name, scope, "github_repo", n, func() { calls.Store(0); rateLimitStates.Delete("fixture-scale") }, func() (collect.Result, int, error) {
					var before, after runtime.MemStats
					runtime.ReadMemStats(&before)
					c := New()
					c.client = &http.Client{Transport: transport}
					c.SetPriorRepoMetadata(func(_ context.Context, ids []string) (map[string]map[string]string, error) {
						selected := make(map[string]map[string]string, len(ids))
						for _, id := range ids {
							if value, ok := prior[id]; ok {
								selected[id] = value
							}
						}
						return selected, nil
					})
					r, err := c.Collect(context.Background(), cfg)
					runtime.ReadMemStats(&after)
					require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(n)*384*1024+16*1024*1024, "allocation budget must remain linear")
					require.Less(t, int(calls.Load()), 4*n+200, "request count must remain linear")
					require.NoError(t, err)
					counts := map[string]int{}
					for _, a := range r.Assets {
						counts[a.Type]++
					}
					edgeCounts := map[string]int{}
					for _, e := range r.Edges {
						edgeCounts[e.EdgeType]++
					}
					require.Equal(t, n, counts["github_workflow"])
					require.Equal(t, 2*n, counts["github_app_token_scope"])
					require.Equal(t, n, counts["declared_ci_access"])
					require.Equal(t, n, edgeCounts["github_grant_repository"])
					require.Equal(t, n, edgeCounts["github_token_grant"])
					require.Equal(t, n, edgeCounts["github_token_repository"])
					require.Equal(t, 7*n+2, len(r.Edges), "exact fixture relationships; no all-to-all App relationships")
					require.Equal(t, 6*n+5, len(r.Assets), "all populated fixture assets must survive")
					potential := 0
					for _, f := range r.Findings {
						if f.CheckID == "github-app-public-input-private-access" {
							potential++
						}
					}
					require.Equal(t, n, potential)
					if !denied {
						for _, a := range r.Assets {
							if a.Type == "github_repo" {
								require.Equal(t, branchProtectionEnabled, a.Metadata["branch_protection"])
							}
						}
					}
					prior = map[string]map[string]string{}
					for _, a := range r.Assets {
						if a.Type == "github_repo" || a.Type == "github_visibility_snapshot" {
							prior[a.ID] = a.Metadata
						}
					}
					return r, int(calls.Load()), err
				})
			})
		}
	}

}

const scaleWorkflow = `on: pull_request_target
jobs:
  build:
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./test.sh
      - uses: actions/create-github-app-token@v3
        with:
          app-id: 123
          owner: org
          private-key: ${{ secrets.APP_KEY }}
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
  narrowed:
    steps:
      - uses: actions/create-github-app-token@v3
        with:
          app-id: 123
          private-key: ${{ secrets.APP_KEY }}
          permission-contents: read
`
