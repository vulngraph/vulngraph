package webhook

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplayGuard_SeenBefore(t *testing.T) {
	g := newReplayGuard(4)

	require.False(t, g.seenBefore("a"), "first sighting is not a replay")
	require.True(t, g.seenBefore("a"), "second sighting of the same key is a replay")
	require.False(t, g.seenBefore("b"), "a different key is never a replay")
}

// TestReplayGuard_BoundedCapacity pins requirement 2: the guard must never
// grow without bound. Inserting far more keys than the capacity must not
// leave more than `capacity` keys resident, and the oldest keys must be the
// ones evicted (FIFO), so a genuine near-term replay of a recent delivery is
// still caught even after the guard has cycled through many keys.
func TestReplayGuard_BoundedCapacity(t *testing.T) {
	const capacity = 8
	g := newReplayGuard(capacity)

	for i := 0; i < capacity*10; i++ {
		key := fmt.Sprintf("key-%d", i)
		require.False(t, g.seenBefore(key), "each new key must be reported as first-seen")
	}

	require.LessOrEqual(t, len(g.seen), capacity, "resident set must never exceed capacity")
	require.LessOrEqual(t, len(g.order), capacity)

	// The oldest keys were evicted, so they no longer count as a replay —
	// this is the accepted trade-off of a bounded guard, not a bug.
	require.False(t, g.seenBefore("key-0"), "evicted key is treated as new again")

	// The most recently inserted keys are still resident and still caught.
	last := fmt.Sprintf("key-%d", capacity*10-1)
	require.True(t, g.seenBefore(last), "a recent key must still be recognized as a replay")
}

func TestReplayGuard_ConcurrentUse(t *testing.T) {
	g := newReplayGuard(1024)
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			g.seenBefore(fmt.Sprintf("k-%d", i%10))
		}(i)
	}
	for i := 0; i < 50; i++ {
		<-done
	}
	require.LessOrEqual(t, len(g.seen), 10)
}
