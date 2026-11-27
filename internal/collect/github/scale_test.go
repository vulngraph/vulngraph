package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
		name, scope := "github", "paginated repositories, SBOM, branch protection, CODEOWNERS, empty source trees"
		if denied {
			name, scope = "github_denied", "installation pagination, SBOM and empty source trees; denied GraphQL"
		}
		for _, n := range sizes {
			t.Run(fmt.Sprintf("%s/%d", name, n), func(t *testing.T) {
				var calls atomic.Int64
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
					case path == "/installation/repositories":
						page, _ := strconv.Atoi(req.URL.Query().Get("page"))
						start := (page - 1) * perPage
						repos := make([]map[string]any, 0)
						for i := start; i < min(start+perPage, n); i++ {
							repos = append(repos, map[string]any{"name": fmt.Sprintf("repo%d", i), "full_name": fmt.Sprintf("org/repo%d", i), "default_branch": "main", "visibility": "private", "language": "Go"})
						}
						b, err := json.Marshal(map[string]any{"repositories": repos})
						if err != nil {
							return nil, err
						}
						body = string(b)
					case strings.HasSuffix(path, "/dependency-graph/sbom"):
						body = `{"sbom":{"packages":[{"externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/example.com/lib@v1.0.0"}]}]}}`
					case strings.Contains(path, "/git/trees/"):
						body = `{"tree":[],"truncated":false}`
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
					c := &Collector{client: &http.Client{Transport: transport}, baseURL: "https://api.github.com"}
					r, err := c.Collect(context.Background(), cfg)
					require.Less(t, int(calls.Load()), 3*n+200, "request count must remain linear")
					if !denied {
						for _, a := range r.Assets {
							if a.Type == "github_repo" {
								require.Equal(t, branchProtectionEnabled, a.Metadata["branch_protection"])
							}
						}
					}
					return r, int(calls.Load()), err
				})
			})
		}
	}

}
