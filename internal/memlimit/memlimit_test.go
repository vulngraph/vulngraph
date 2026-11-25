package memlimit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// referenceContainerMiB/referenceGoMemLimitMiB/referenceLadybugMiB are an example
// large-worker sizing of worker.resources.limits.memory / worker.goMemLimit /
// ladybug.bufferPoolMB, the same one internal/app/graphstore's NodeBudget is
// derived from. The chart ships small defaults, so no values file holds this
// configuration; keep the two tests' copies in step by hand.
const (
	referenceContainerMiB  = 20480
	referenceGoMemLimitMiB = 8192
	referenceLadybugMiB    = 2048
)

// TestDerive_ReferenceConfiguration asserts the two properties this package
// actually promises against that reference configuration: deriving must never
// RAISE the ceiling an explicit GOMEMLIMIT already set, and the derived budget
// (had no explicit override been set) must still fit inside the container.
func TestDerive_ReferenceConfiguration(t *testing.T) {
	containerMiB := int64(referenceContainerMiB)
	envLimitMiB := int64(referenceGoMemLimitMiB)
	ladybugMiB := int64(referenceLadybugMiB)

	container := containerMiB * MiB
	ladybug := ladybugMiB * MiB
	reserve := DefaultReserveMiB * MiB
	envLimit := envLimitMiB * MiB

	t.Run("the deployed explicit GOMEMLIMIT is tighter than derived, and wins", func(t *testing.T) {
		derived := container - ladybug - reserve
		require.Lessf(t, envLimit, derived,
			"worker.goMemLimit %dMiB is no longer tighter than the derived budget %dMiB — if the container "+
				"limit was raised without raising goMemLimit to match, memlimit.Derive will silently start "+
				"applying the (looser) derived value instead of the explicit one an operator set",
			envLimitMiB, derived/MiB)
		b := Derive(container, ladybug, reserve, envLimit)
		require.True(t, b.Applied)
		require.Equal(t, envLimit, b.GoLimit,
			"deriving must never RAISE the ceiling an operator already set")
		require.Contains(t, b.Reason, "tighter")
	})

	t.Run("with no explicit limit the derived budget still fits the deployed container", func(t *testing.T) {
		b := Derive(container, ladybug, reserve, 0)
		require.True(t, b.Applied)
		require.LessOrEqual(t, b.GoLimit+ladybug+reserve, container)
	})

	t.Run("raising the buffer pool automatically claws back Go budget", func(t *testing.T) {
		// The drift scenario: someone raises LADYBUG_BUFFER_MB and, before this package,
		// nothing reduced the Go ceiling to pay for it.
		before := Derive(container, ladybug, reserve, 0).GoLimit
		after := Derive(container, ladybug+4096*MiB, reserve, 0).GoLimit
		require.Equal(t, before-4096*MiB, after,
			"every MiB given to the cgo pool must come out of the Go budget")
		require.LessOrEqual(t, after+ladybug+4096*MiB+reserve, container)
	})
}

func TestDerive(t *testing.T) {
	tests := []struct {
		name                               string
		cgroup, ladybug, reserve, envLimit int64
		wantApplied                        bool
		wantLimit                          int64
		wantReason                         string
	}{
		{
			name:    "no cgroup limit visible → leave the runtime alone",
			ladybug: 2048 * MiB, reserve: 1024 * MiB,
			wantApplied: false, wantReason: "no cgroup memory limit visible",
		},
		{
			name:   "an explicit limit LOOSER than derived is tightened to derived",
			cgroup: 8192 * MiB, ladybug: 1280 * MiB, reserve: 1024 * MiB, envLimit: 100000 * MiB,
			wantApplied: true, wantLimit: 5888 * MiB,
		},
		{
			name:   "derived budget subtracts both the pool and the reserve",
			cgroup: 8192 * MiB, ladybug: 1280 * MiB, reserve: 1024 * MiB,
			wantApplied: true, wantLimit: 5888 * MiB,
		},
		{
			name:   "a larger buffer pool automatically shrinks the Go budget",
			cgroup: 8192 * MiB, ladybug: 4096 * MiB, reserve: 1024 * MiB,
			wantApplied: true, wantLimit: 3072 * MiB,
		},
		{
			name:   "a derived budget under the floor is refused, not applied",
			cgroup: 2048 * MiB, ladybug: 1280 * MiB, reserve: 1024 * MiB,
			wantApplied: false, wantReason: "below the",
		},
		{
			name:   "an explicit limit tighter than derived is honoured",
			cgroup: 16384 * MiB, ladybug: 2048 * MiB, reserve: 1024 * MiB, envLimit: 8192 * MiB,
			wantApplied: true, wantLimit: 8192 * MiB, wantReason: "tighter",
		},
		{
			name:    "an explicit limit with no cgroup limit stands as-is, unapplied",
			ladybug: 2048 * MiB, reserve: 1024 * MiB, envLimit: 8192 * MiB,
			wantApplied: false, wantReason: "nothing to derive from",
		},
		{
			name:   "no ladybug buffer pool (graph engine disabled) still reserves non-heap",
			cgroup: 4096 * MiB, ladybug: 0, reserve: 1024 * MiB,
			wantApplied: true, wantLimit: 3072 * MiB,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := Derive(tc.cgroup, tc.ladybug, tc.reserve, tc.envLimit)
			require.Equal(t, tc.wantApplied, b.Applied)
			if tc.wantLimit != 0 {
				require.Equal(t, tc.wantLimit, b.GoLimit)
			}
			if tc.wantReason != "" {
				require.Contains(t, b.Reason, tc.wantReason)
			}
			require.NotEmpty(t, b.Reason, "every outcome must explain itself")
			if b.Applied && tc.cgroup > 0 {
				require.LessOrEqual(t, b.GoLimit+tc.ladybug+tc.reserve, tc.cgroup,
					"an applied budget must never oversubscribe the container")
			}
		})
	}
}

// Derive must never hand the runtime a non-positive limit, which would be an
// immediate GC death spiral.
func TestDerive_NeverAppliesNonPositive(t *testing.T) {
	for _, ladybug := range []int64{4096, 8192, 16384, 32768} {
		b := Derive(4096*MiB, ladybug*MiB, 1024*MiB, 0)
		if b.Applied {
			require.Greater(t, b.GoLimit, int64(0))
		}
	}
}

func TestParseGoMemLimit(t *testing.T) {
	tests := map[string]int64{
		"":           0,
		"off":        0,
		"12800MiB":   12800 * MiB,
		" 12800MiB ": 12800 * MiB,
		"4GiB":       4 << 30,
		"1TiB":       1 << 40,
		"1024KiB":    1 << 20,
		"1048576B":   1 << 20,
		"1048576":    1 << 20, // bare byte count, as the runtime accepts
		"garbage":    0,
		"-5MiB":      0,
		"0":          0,
		"12800 MiB":  12800 * MiB,
	}
	for in, want := range tests {
		t.Run(in, func(t *testing.T) {
			require.Equal(t, want, parseGoMemLimit(in))
		})
	}
}

func TestReserveFromEnv(t *testing.T) {
	require.Equal(t, DefaultReserveMiB*MiB, reserveFromEnv(func(string) string { return "" }))
	require.Equal(t, int64(2048)*MiB, reserveFromEnv(func(string) string { return "2048" }))
	require.Equal(t, DefaultReserveMiB*MiB, reserveFromEnv(func(string) string { return "nonsense" }),
		"a malformed override falls back to the default rather than to zero")
	require.Equal(t, DefaultReserveMiB*MiB, reserveFromEnv(func(string) string { return "-1" }))
}

func TestBudgetString(t *testing.T) {
	b := Derive(16384*MiB, 2048*MiB, 1024*MiB, 0)
	require.Contains(t, b.String(), "cgroup=16384MiB")
	require.Contains(t, b.String(), "go_limit=13312MiB")
	require.Contains(t, b.String(), "gogc=")
	require.Contains(t, b.String(), "applied=true")
}
