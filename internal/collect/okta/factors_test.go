package okta

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// userIDs returns n synthetic Okta user IDs.
func userIDs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("u%d", i))
	}
	return out
}

// TestUserFactors_ForbiddenAbortsFanOut pins the permanent-failure short circuit.
// A token whose scope does not cover the factors endpoint rejects every call
// identically; repeating it once per user burns the org's whole rate-limit
// budget and delays the rest of the sweep for no information. Every unfetched
// user stays UNKNOWN, which is the same answer they would have got anyway.
func TestUserFactors_ForbiddenAbortsFanOut(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := &Collector{client: srv.Client()}
	ids := userIDs(500)
	states, failed := c.userFactors(context.Background(), srv.URL, "t", ids)

	require.Empty(t, states, "a rejected read publishes no factor state at all")
	require.Equal(t, len(ids), failed, "every user is unknown, and counted as such")
	require.Less(t, int(atomic.LoadInt32(&calls)), len(ids)/2,
		"a permanent rejection must abort the fan-out, not repeat once per user")
}

// TestUserFactors_PartialFailureIsPerUser checks the granularity of the unknown:
// one user's failure must not erase another user's observed state.
func TestUserFactors_PartialFailureIsPerUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users/u1/factors" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"factorType":"push","provider":"OKTA","status":"ACTIVE"}]`))
	}))
	defer srv.Close()

	c := &Collector{client: srv.Client()}
	states, failed := c.userFactors(context.Background(), srv.URL, "t", []string{"u0", "u1", "u2"})

	require.Equal(t, 1, failed)
	require.Len(t, states, 2)
	_, present := states["u1"]
	require.False(t, present, "the failed user must be absent, not present-and-false")
	require.True(t, states["u0"].enrolled())
	require.True(t, states["u2"].enrolled())
}

// TestUserFactors_CancelledContextIsUnknown: a cancelled sweep must not publish
// "no factors enrolled" for the users it never reached.
func TestUserFactors_CancelledContextIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := &Collector{client: srv.Client()}
	states, failed := c.userFactors(ctx, srv.URL, "t", userIDs(50))
	require.Empty(t, states)
	require.Equal(t, 50, failed)
}
