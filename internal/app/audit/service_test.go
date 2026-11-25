package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

type fakeWriter struct {
	events []Event
	err    error
}

func (f *fakeWriter) Write(_ context.Context, e Event) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, e)
	return nil
}

func details(t *testing.T, e Event) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(e.Details), &out))
	return out
}

func TestRecord_AttributesTheSignedInUser(t *testing.T) {
	w := &fakeWriter{}
	s := NewService(w)
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.now = func() time.Time { return at }

	ctx := auth.ContextWithUser(context.Background(), auth.User{ID: "u-1", Email: "admin@example.com"})
	ctx = auth.ContextWithAPIKey(ctx, auth.APIKeyRecord{ID: "k-1"})
	ctx = auth.ContextWithClientIP(ctx, "198.51.100.7")
	in := map[string]any{"before": "read_only", "after": "read_write"}
	s.Record(ctx, "connector.mode_change", "connector", "c-1", in)

	require.Len(t, w.events, 1)
	e := w.events[0]
	require.Equal(t, Event{
		TS: at, Actor: "admin@example.com", Action: "connector.mode_change",
		TargetType: "connector", TargetID: "c-1", Details: e.Details,
	}, e)
	require.Equal(t, map[string]any{
		"before": "read_only", "after": "read_write",
		"actor_user_id": "u-1", "api_key_id": "k-1", "client_ip": "198.51.100.7",
	}, details(t, e))
	require.Len(t, in, 2, "the caller's details map is not modified")
}

// No principal on the context is written as the fallback actor, never dropped.
func TestRecord_NoPrincipalIsWrittenAsTheFallbackActor(t *testing.T) {
	w := &fakeWriter{}
	NewService(w).Record(context.Background(), "auth.user_create", "user", "u-2", nil)
	NewService(w).WithFallbackActor(ActorCLI).Record(context.Background(), "auth.totp_enroll", "user", "u-2", nil)

	require.Len(t, w.events, 2)
	require.Equal(t, ActorUnknown, w.events[0].Actor)
	require.Equal(t, ActorCLI, w.events[1].Actor)
	require.Empty(t, details(t, w.events[0]))
}

// A failed write is logged as the line to alert on, not returned: the action
// it records is already committed.
func TestRecord_WriteFailureIsLoggedAsAuditWriteFailed(t *testing.T) {
	var buf bytes.Buffer
	orig := zlog.Logger
	zlog.Logger = zerolog.New(&buf)
	t.Cleanup(func() { zlog.Logger = orig })

	w := &fakeWriter{err: errors.New("clickhouse down")}
	NewService(w).Record(context.Background(), "connector.delete", "connector", "c-1", nil)

	require.Empty(t, w.events)
	require.Contains(t, buf.String(), "AUDIT WRITE FAILED")
	require.Contains(t, buf.String(), `"action":"connector.delete"`)
	require.Contains(t, buf.String(), `"level":"error"`)
}
