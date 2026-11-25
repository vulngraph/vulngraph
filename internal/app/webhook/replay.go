package webhook

import "sync"

// replayGuardCapacity bounds the number of delivery keys replayGuard remembers.
// GitHub webhook volume for a single connector on this platform is low (pushes
// and a handful of other content events, not a firehose), so this comfortably
// covers a long window of distinct deliveries per pod while still being a hard
// cap — the whole point of choosing an in-memory set over persisting every ID
// is that it must never grow without bound. Keys are connector id + SHA-256 of
// the signed body (see Handler.GitHub).
const replayGuardCapacity = 4096

// replayGuard is a bounded, in-memory set of "already seen" keys, used to
// reject a replayed webhook delivery. It is NOT a distributed dedup: each
// graph-serve replica holds its own guard, so a delivery replayed against a
// DIFFERENT pod than the one that saw the original is not caught here. See
// the doc comment on Handler.GitHub's replay check for why that gap is
// accepted rather than closed with a shared store.
//
// Eviction is strict FIFO by insertion order, not recency of access — this is
// a replay guard, not an LRU cache, so "seen most recently" isn't the right
// eviction signal; "seen longest ago" is, since a genuine redelivery replay
// is expected to arrive shortly after the original, not after thousands of
// other deliveries have cycled through.
type replayGuard struct {
	mu       sync.Mutex
	capacity int
	seen     map[string]struct{}
	order    []string
}

func newReplayGuard(capacity int) *replayGuard {
	return &replayGuard{
		capacity: capacity,
		seen:     make(map[string]struct{}, capacity),
	}
}

// seenBefore records key if it is new, and reports whether it was already
// present. Safe for concurrent use.
func (g *replayGuard) seenBefore(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.seen[key]; ok {
		return true
	}
	if len(g.order) >= g.capacity {
		oldest := g.order[0]
		g.order = g.order[1:]
		delete(g.seen, oldest)
	}
	g.seen[key] = struct{}{}
	g.order = append(g.order, key)
	return false
}
