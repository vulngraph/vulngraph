// Package memlimit derives the Go heap budget (GOMEMLIMIT) from the container's
// real memory limit minus the memory Go cannot see.
//
// GOMEMLIMIT governs the Go runtime ONLY. The Ladybug graph engine is a C++ library
// reached over cgo, so its buffer pool is invisible to the Go GC: the runtime will
// happily grow the heap to GOMEMLIMIT while Ladybug holds gigabytes alongside it, and
// the kernel kills the pod for the sum. GOMEMLIMIT lives in the deployment manifest
// and the Ladybug buffer size in the pod env, with no code aware of both, so raising
// either silently eats the other's headroom. Deriving the budget in the process
// that knows both numbers closes that gap and logs the arithmetic once at boot.
//
// The derivation only ever TIGHTENS: the effective limit is
// min(derived, GOMEMLIMIT), so an operator's explicit value is never exceeded.
//
// GOMEMLIMIT alone is not the whole answer, because it is a soft limit — the GC
// collects harder as the heap approaches it, trading CPU for memory rather than
// shrinking. Against a heap that is mostly reclaimable garbage rather than live
// data, GOGC is the lever that actually cuts steady-state RSS: at the default
// GOGC=100 the GC waits until the heap is ~2x live before collecting, so this
// package also lowers GOGC (see DefaultGCPercent) to collect sooner, trading a
// modest CPU increase for several GiB of headroom. GOGC handles the steady state;
// GOMEMLIMIT is the backstop for the tail.
package memlimit

import (
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// MiB is one mebibyte in bytes.
const MiB int64 = 1 << 20

// DefaultReserveMiB is what we hold back for memory that is neither Go heap nor
// the Ladybug buffer pool: uncounted thread stacks, the C++ allocator's overhead,
// mapped binary/file pages, and the slack a soft limit needs to be soft.
// Deliberately generous — over-reserving costs a slightly busier GC;
// under-reserving costs an OOM kill mid-sweep.
const DefaultReserveMiB int64 = 1024

// MinGoLimitMiB is the floor below which a derived budget is treated as nonsense
// rather than applied — a tiny limit would send the GC into a death spiral, which
// is harder to diagnose than the OOM it replaced.
const MinGoLimitMiB int64 = 512

// DefaultGCPercent paces the GC at 1.6x live heap instead of the runtime's default
// 2x, trading modest CPU for several GiB of RSS. Going much lower buys
// progressively less memory for steeply more CPU, since GC cost scales with
// 1/GOGC while the memory saved is bounded by the live set.
const DefaultGCPercent = 60

// Budget is the outcome of the derivation, suitable for logging as one line.
type Budget struct {
	CgroupLimit   int64  // bytes; 0 when unlimited or unreadable
	LadybugBuffer int64  // bytes reserved for the cgo buffer pool
	Reserve       int64  // bytes held back for non-heap RSS
	GoLimit       int64  // bytes; the value applied to debug.SetMemoryLimit
	Applied       bool   // false = left at the runtime/env default
	GCPercent     int    // value applied to debug.SetGCPercent; 0 = left alone
	Reason        string // why, in one phrase — always populated
}

func (b Budget) String() string {
	return fmt.Sprintf("cgroup=%dMiB ladybug_buffer=%dMiB reserve=%dMiB go_limit=%dMiB applied=%t gogc=%d (%s)",
		b.CgroupLimit/MiB, b.LadybugBuffer/MiB, b.Reserve/MiB, b.GoLimit/MiB, b.Applied, b.GCPercent, b.Reason)
}

// Derive computes the Go heap budget. Pure — no environment, no syscalls — so the
// arithmetic is exhaustively testable.
//
// The result is min(cgroup - ladybugBuffer - reserve, envLimit): whichever of the
// derived budget and the operator's explicit GOMEMLIMIT is tighter. It can only
// ever lower the runtime's ceiling, never raise it.
//
// cgroupLimit <= 0 means unknown or unlimited (dev machines, no container). Then
// there is nothing to derive from, so an explicit envLimit stands as-is and absent
// that nothing is applied — guessing a limit is worse than the runtime default.
func Derive(cgroupLimit, ladybugBuffer, reserve, envLimit int64) Budget {
	b := Budget{CgroupLimit: cgroupLimit, LadybugBuffer: ladybugBuffer, Reserve: reserve}

	if cgroupLimit <= 0 {
		b.GoLimit = envLimit
		b.Reason = "no cgroup memory limit visible; nothing to derive from"
		return b
	}

	derived := cgroupLimit - ladybugBuffer - reserve
	effective, source := derived, "derived from the cgroup limit minus the cgo buffer pool and reserve"
	if envLimit > 0 && envLimit < derived {
		effective, source = envLimit, fmt.Sprintf(
			"GOMEMLIMIT=%dMiB is tighter than the %dMiB derived budget; honouring the tighter value",
			envLimit/MiB, derived/MiB)
	}

	if effective < MinGoLimitMiB*MiB {
		b.GoLimit = effective
		b.Reason = fmt.Sprintf(
			"budget %dMiB is below the %dMiB floor (container %dMiB minus ladybug %dMiB minus reserve %dMiB) — not applied; raise the memory limit or lower LADYBUG_BUFFER_MB",
			effective/MiB, MinGoLimitMiB, cgroupLimit/MiB, ladybugBuffer/MiB, reserve/MiB)
		return b
	}

	b.GoLimit, b.Applied, b.Reason = effective, true, source
	return b
}

// Apply derives the budget from the live environment and installs it on the
// runtime. Returns the Budget so the caller can log exactly one line about it.
//
// getenv is injected for testability; pass os.Getenv.
func Apply(getenv func(string) string, ladybugBufferMB int) Budget {
	b := Derive(
		CgroupLimit(),
		int64(ladybugBufferMB)*MiB,
		reserveFromEnv(getenv),
		parseGoMemLimit(getenv("GOMEMLIMIT")),
	)
	if b.Applied {
		debug.SetMemoryLimit(b.GoLimit)
	}
	// GOGC is left entirely to the runtime when set in the environment: SetGCPercent
	// would override it, and an operator who tuned GOGC deliberately must win.
	if strings.TrimSpace(getenv("GOGC")) == "" {
		b.GCPercent = DefaultGCPercent
		debug.SetGCPercent(DefaultGCPercent)
	}
	return b
}

// reserveFromEnv allows the non-heap reserve to be tuned without a rebuild
// (MEM_RESERVE_MIB), because the right value depends on the pod's non-Go tenants.
func reserveFromEnv(getenv func(string) string) int64 {
	if n, err := strconv.ParseInt(strings.TrimSpace(getenv("MEM_RESERVE_MIB")), 10, 64); err == nil && n > 0 {
		return n * MiB
	}
	return DefaultReserveMiB * MiB
}

// cgroupPaths are read in order: cgroup v2 first, then v1.
var cgroupPaths = []string{
	"/sys/fs/cgroup/memory.max",                   // v2
	"/sys/fs/cgroup/memory/memory.limit_in_bytes", // v1
}

// CgroupLimit returns the container's memory limit in bytes, or 0 when there is
// none or it cannot be read (v2 writes the literal "max" when unlimited, and v1
// reports a sentinel near 2^63 that must not be mistaken for a real limit).
func CgroupLimit() int64 {
	for _, p := range cgroupPaths {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(raw))
		if s == "" || s == "max" {
			return 0
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		// v1 encodes "unlimited" as a huge number; anything past a petabyte is that.
		if n > 1<<50 {
			return 0
		}
		return n
	}
	return 0
}

// parseGoMemLimit reads the GOMEMLIMIT syntax the runtime itself accepts: a byte
// count with an optional B/KiB/MiB/GiB/TiB suffix. Returns 0 when unset or
// unparseable, so a malformed value falls through to derivation rather than
// silently disabling it.
func parseGoMemLimit(v string) int64 {
	s := strings.TrimSpace(v)
	if s == "" || s == "off" {
		return 0
	}
	mult := int64(1)
	for _, suf := range []struct {
		s string
		m int64
	}{
		{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1},
	} {
		if strings.HasSuffix(s, suf.s) {
			mult = suf.m
			s = strings.TrimSuffix(s, suf.s)
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n * mult
}
