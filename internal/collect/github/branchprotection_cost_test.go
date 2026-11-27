package github

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
)

func TestBranchProtectionForbiddenDoesNotSplitIntoPerRepoRequests(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"http_forbidden", `{"message":"Forbidden"}`, 403},
		{"graphql_forbidden", `{"data":null,"errors":[{"type":"FORBIDDEN","message":"denied"}]}`, 200},
		{"graphql_rate_limit", `{"data":null,"errors":[{"type":"RATE_LIMITED","message":"exhausted"}]}`, 200},
		{"missing_data", `{"data":null}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := &Collector{client: &http.Client{Transport: collectbench.Transport(func(r *http.Request) (*http.Response, error) {
				calls++
				resp := collectbench.Response(r, tc.body)
				resp.StatusCode = tc.status
				return resp, nil
			})}}
			repos := make([]repo, 0)
			for i := range 1000 {
				repos = append(repos, repo{FullName: fmt.Sprintf("org/repo%d", i), DefaultBranch: "main"})
			}
			got := c.collectBranchProtection(context.Background(), "https://api.github.com", "cost-fixture", repos)
			require.Empty(t, got, "unread protection must remain unknown")
			require.Equal(t, (len(repos)+bpBatchSize-1)/bpBatchSize, calls)
		})
	}
}
