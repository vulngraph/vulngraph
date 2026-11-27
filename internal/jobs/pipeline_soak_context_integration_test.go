//go:build integration

package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSoakDeadlineBecomesCancellation(t *testing.T) {
	type key struct{}
	parent, cancelParent := context.WithTimeout(context.WithValue(t.Context(), key{}, "query settings"), 10*time.Millisecond)
	defer cancelParent()
	ctx, cancel := soakRiverContext(parent)
	defer cancel()
	_, hasDeadline := ctx.Deadline()
	require.False(t, hasDeadline, "the River context must terminate with cancellation, not deadline exceeded")
	require.Equal(t, "query settings", ctx.Value(key{}))
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("parent deadline did not stop the River context")
	}
	require.ErrorIs(t, parent.Err(), context.DeadlineExceeded)
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	manual, stop := soakRiverContext(t.Context())
	stop()
	require.ErrorIs(t, manual.Err(), context.Canceled)
}
