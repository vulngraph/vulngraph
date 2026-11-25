package findingctx

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
)

type fakeSuppressions struct {
	st  suppress.State
	err error
}

func (f fakeSuppressions) State(context.Context, string) (suppress.State, error) { return f.st, f.err }

func TestContext_SuppressionStanding(t *testing.T) {
	find := fakeFindings{f: finding.Finding{ID: "f1"}}
	expires := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	active := suppress.State{Suppressed: true, Suppression: suppress.Suppression{
		FindingID: "f1", Reason: "accepted risk", SuppressedBy: "a@b.example", ExpiresAt: expires,
	}}

	t.Run("read through", func(t *testing.T) {
		fc, err := svc(find, fakeReason{}, fakeFactors{}).WithSuppressions(fakeSuppressions{st: active}).
			Context(context.Background(), "f1")
		require.NoError(t, err)
		require.True(t, fc.SuppressionKnown)
		require.True(t, fc.Suppression.Suppressed)
	})
	t.Run("read failure is unknown, not unsuppressed", func(t *testing.T) {
		fc, err := svc(find, fakeReason{}, fakeFactors{}).WithSuppressions(fakeSuppressions{err: errors.New("pg down")}).
			Context(context.Background(), "f1")
		require.NoError(t, err, "a suppression read failure must not fail the detail view")
		require.False(t, fc.SuppressionKnown)
	})
	t.Run("not wired is unknown", func(t *testing.T) {
		fc, err := svc(find, fakeReason{}, fakeFactors{}).Context(context.Background(), "f1")
		require.NoError(t, err)
		require.False(t, fc.SuppressionKnown)
	})
}

func TestToResponse_SuppressionAndRouting(t *testing.T) {
	expires := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	fc := FindingContext{SuppressionKnown: true, Suppression: suppress.State{Expired: true, Suppression: suppress.Suppression{
		Reason: "accepted risk", SuppressedBy: "a@b.example", ExpiresAt: expires,
	}}}
	fc.Finding = finding.Finding{ID: "f1", OwnerTeam: "payments", OwnerSource: "codeowners",
		OwnerConfidence: "high", Environment: "prod"}

	b, err := json.Marshal(toResponse(fc))
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(b, &got))

	require.Equal(t, true, got["suppression_known"])
	require.Equal(t, false, got["is_suppressed"])
	require.Equal(t, true, got["exception_expired"])
	require.Equal(t, "2026-12-01T00:00:00Z", got["suppression_expires_at"])
	require.Equal(t, "accepted risk", got["suppression_reason"])
	require.Equal(t, "a@b.example", got["suppressed_by"])
	require.Equal(t, "payments", got["owner_team"])
	require.Equal(t, "codeowners", got["owner_source"])
	require.Equal(t, "prod", got["environment"])

	// No suppression ever: flags present and false, no expiry.
	b, err = json.Marshal(toResponse(FindingContext{SuppressionKnown: true}))
	require.NoError(t, err)
	got = map[string]any{}
	require.NoError(t, json.Unmarshal(b, &got))
	require.Equal(t, false, got["is_suppressed"])
	require.NotContains(t, got, "suppression_expires_at")
	require.Contains(t, got, "owner_source", "unstamped is spelled out, never absent")
}
