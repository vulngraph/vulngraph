package okta

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

func oktaScaleFixture(n int) (*Collector, *atomic.Int64) {
	calls := &atomic.Int64{}
	client := &http.Client{Transport: collectbench.Transport(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		path := req.URL.Path
		if req.URL.Host != "fixture.okta.com" {
			return nil, fmt.Errorf("unexpected fixture host %s", req.URL.Host)
		}
		start, _ := strconv.Atoi(req.URL.Query().Get("after"))
		var values []map[string]any
		total := 0
		switch {
		case strings.HasSuffix(path, "/factors"):
			return collectbench.Response(req, `[{"id":"factor","factorType":"webauthn","status":"ACTIVE"}]`), nil
		case path == "/api/v1/users":
			total = n
			for i := start; i < min(start+pageLimit, n); i++ {
				values = append(values, map[string]any{"id": fmt.Sprint(i), "status": "ACTIVE", "profile": map[string]string{"email": fmt.Sprintf("u-%d@example.test", i)}})
			}
		case path == "/api/v1/groups":
			total = n / 100
			for i := start; i < min(start+pageLimit, total); i++ {
				values = append(values, map[string]any{"id": fmt.Sprint(i), "profile": map[string]string{"name": fmt.Sprintf("group-%d", i)}})
			}
		case strings.HasPrefix(path, "/api/v1/groups/"):
			group, _ := strconv.Atoi(strings.Split(path, "/")[4])
			for i := range 100 {
				values = append(values, map[string]any{"id": fmt.Sprint(group*100 + i)})
			}
		case path == "/api/v1/policies":
			return collectbench.Response(req, `[]`), nil
		default:
			return nil, fmt.Errorf("unexpected fixture route %s", path)
		}
		body, err := json.Marshal(values)
		resp := collectbench.Response(req, string(body))
		if start+pageLimit < total {
			next := *req.URL
			q := next.Query()
			q.Set("after", fmt.Sprint(start+pageLimit))
			next.RawQuery = q.Encode()
			resp.Header.Set("Link", "<"+next.String()+">; rel=\"next\"")
		}
		return resp, err
	})}
	return &Collector{client: client}, calls
}

func TestConnectorScale(t *testing.T) {
	for _, n := range collectbench.Sizes(t) {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			c, calls := oktaScaleFixture(n)
			collectbench.Run(t, "okta", "paginated JSON, factors, groups, membership and policy reads", "human_identity", n, func() { calls.Store(0) }, func() (collect.Result, int, error) {
				r, err := c.Collect(context.Background(), map[string]string{"domain": "fixture.okta.com", "api_token": "fixture"})
				require.Equal(t, n+(n+199)/200+1+n/100+2, int(calls.Load()))
				return r, int(calls.Load()), err
			})
		})
	}
}

func TestOktaPaginationCapIsNotACompleteInventory(t *testing.T) {
	old := maxPages
	maxPages = 1
	t.Cleanup(func() { maxPages = old })
	c, _ := oktaScaleFixture(pageLimit + 1)
	_, err := c.listUsers(context.Background(), "https://fixture.okta.com", "fixture")
	require.ErrorContains(t, err, "page limit")
}
