package okta

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
)

func TestEveryInventoryListRejectsPaginationCap(t *testing.T) {
	old := maxPages
	t.Cleanup(func() { maxPages = old })
	for _, kind := range []string{"users", "groups", "members", "policies", "rules"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			c := &Collector{client: &http.Client{Transport: collectbench.Transport(func(r *http.Request) (*http.Response, error) {
				calls++
				resp := collectbench.Response(r, `[{"id":"observed","status":"ACTIVE"}]`)
				if calls == 1 {
					resp.Header.Set("Link", "<https://fixture.okta.com/api/v1/next>; rel=\"next\"")
				}
				return resp, nil
			})}}
			read := func() (int, error) {
				ctx := context.Background()
				domain := "https://fixture.okta.com"
				switch kind {
				case "users":
					rows, err := c.listUsers(ctx, domain, "token")
					return len(rows), err
				case "groups":
					rows, err := c.listGroups(ctx, domain, "token")
					return len(rows), err
				case "members":
					rows, err := c.groupMembers(ctx, domain, "token", "group")
					return len(rows), err
				case "policies":
					rows, err := c.listPolicies(ctx, domain, "token", policyTypeAccess)
					return len(rows), err
				default:
					rows, err := c.policyRules(ctx, domain, "token", "policy")
					return len(rows), err
				}
			}
			maxPages = 1
			n, err := read()
			require.ErrorContains(t, err, "page limit")
			require.Zero(t, n)
			maxPages = 2
			calls = 0
			n, err = read()
			require.NoError(t, err)
			require.Equal(t, 2, n)
			require.Equal(t, 2, calls)
		})
	}
}
