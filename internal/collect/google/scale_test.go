package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
)

func workspaceFixture(t *testing.T, n int) (*Collector, *int, map[string]string) {
	t.Helper()
	calls := 0
	client := &http.Client{Transport: collectbench.Transport(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Host == "oauth2.googleapis.com" {
			return collectbench.Response(req, `{"access_token":"fixture"}`), nil
		}
		if req.URL.Host != "admin.googleapis.com" {
			return nil, fmt.Errorf("unexpected fixture host %s", req.URL.Host)
		}
		start, _ := strconv.Atoi(req.URL.Query().Get("pageToken"))
		users := make([]map[string]any, 0, maxResults)
		for i := start; i < min(start+maxResults, n); i++ {
			users = append(users, map[string]any{"id": fmt.Sprint(i), "primaryEmail": fmt.Sprintf("user-%d@example.test", i), "isEnrolledIn2Sv": i%2 == 0})
		}
		page := map[string]any{"users": users}
		if start+maxResults < n {
			page["nextPageToken"] = fmt.Sprint(start + maxResults)
		}
		body, err := json.Marshal(page)
		return collectbench.Response(req, string(body)), err
	})}
	key, err := json.Marshal(map[string]string{"client_email": "fixture@example.test", "private_key": collectbench.PrivateKey(t)})
	require.NoError(t, err)
	return &Collector{client: client}, &calls, map[string]string{"service_account_json": string(key), "admin_email": "admin@example.test"}
}

func TestConnectorScale(t *testing.T) {
	for _, n := range collectbench.Sizes(t) {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			c, calls, cfg := workspaceFixture(t, n)
			collectbench.Run(t, "google_workspace", "OAuth signing, paginated JSON, identity and MFA mapping", "human_identity", n, func() { *calls = 0 }, func() (collect.Result, int, error) {
				r, err := c.Collect(context.Background(), cfg)
				require.Equal(t, 1+(n+maxResults-1)/maxResults, *calls)
				return r, *calls, err
			})
		})
	}
}

func TestWorkspacePaginationCapIsNotACompleteInventory(t *testing.T) {
	old := maxPages
	maxPages = 1
	t.Cleanup(func() { maxPages = old })
	c, _, cfg := workspaceFixture(t, maxResults+1)
	_, err := c.Collect(context.Background(), cfg)
	require.ErrorContains(t, err, "page limit")
}
