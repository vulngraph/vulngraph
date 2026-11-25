package graphstore

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordedPhase struct {
	name    string
	seconds float64
}

type fakeSyncRecorder struct {
	paths  []string
	phases []recordedPhase
}

func (f *fakeSyncRecorder) ObserveLadybugSync(path string, _ float64) {
	f.paths = append(f.paths, path)
}

func (f *fakeSyncRecorder) ObserveLadybugPhase(phase string, seconds float64) {
	f.phases = append(f.phases, recordedPhase{phase, seconds})
}

// tickingClock advances a fixed step on every read, so a phase measured by it
// always has a known, nonzero duration however fast the test runs.
func tickingClock(start time.Time, step time.Duration) func() time.Time {
	now := start
	return func() time.Time {
		now = now.Add(step)
		return now
	}
}

func TestSyncPhasesRecordsEachPhaseOnceInOrder(t *testing.T) {
	rec := &fakeSyncRecorder{}
	p := newSyncPhases(rec, time.Now())

	p.mark(phaseLoad)
	p.mark(phaseCopy)
	p.mark(phaseBFS)

	names := make([]string, 0, len(rec.phases))
	for _, ph := range rec.phases {
		names = append(names, ph.name)
		assert.GreaterOrEqual(t, ph.seconds, 0.0, "a phase cannot take negative time")
	}
	require.Equal(t, []string{phaseLoad, phaseCopy, phaseBFS}, names,
		"every mark must reach the recorder, in the order it happened")
	require.Equal(t, []string{phaseLoad, phaseCopy, phaseBFS}, p.order)
}

// TestSyncPhasesAccumulateOnRepeatedMark pins the one behaviour that is easy to get
// backwards: a phase entered twice must ADD, not overwrite. Overwriting silently
// under-reports the phase, which is the same class of failure as having no phase
// timing at all — a number that looks measured and is wrong.
func TestSyncPhasesAccumulateOnRepeatedMark(t *testing.T) {
	rec := &fakeSyncRecorder{}
	start := time.Now()
	p := newSyncPhases(rec, start)
	p.clock = tickingClock(start, time.Millisecond)

	p.mark(phaseCopy)
	first := p.dur[phaseCopy]
	p.mark(phaseCopy)

	require.Equal(t, 2*first, p.dur[phaseCopy], "second visit to a phase must accumulate")
	require.Len(t, p.order, 1, "a repeated phase must not appear twice in the timeline")
	require.Len(t, rec.phases, 2, "each visit is its own observation on the metric")
}

func TestSyncPhasesTolerateNilRecorder(t *testing.T) {
	start := time.Now()
	p := newSyncPhases(nil, start)
	p.clock = tickingClock(start, time.Millisecond)
	p.mark(phaseLoad)
	require.Equal(t, time.Millisecond, p.total(), "phases must still be measured when metrics are unwired")
	var nilPhases *syncPhases
	nilPhases.mark(phaseLoad) // must not panic
	require.Zero(t, nilPhases.total())
}

// The unattributed remainder warns only when it is both more than a tenth of
// the rebuild and over a second, so scheduling jitter stays quiet and an
// unmeasured step does not.
func TestSyncPhasesWarnIfUnattributed(t *testing.T) {
	cases := []struct {
		name     string
		marked   time.Duration
		elapsed  time.Duration
		wantWarn bool
	}{
		{"fully attributed", 10 * time.Second, 10 * time.Second, false},
		{"small fraction of a long rebuild", 10 * time.Second, 11 * time.Second, false},
		{"large fraction but under a second", 100 * time.Millisecond, 900 * time.Millisecond, false},
		{"large fraction and over a second", 2 * time.Second, 10 * time.Second, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			p := newSyncPhases(nil, start)
			p.clock = tickingClock(start, tc.marked)
			p.mark(phaseLoad)

			var buf bytes.Buffer
			logger := zerolog.New(&buf)
			p.warnIfUnattributed(&logger, tc.elapsed)
			if tc.wantWarn {
				require.Contains(t, buf.String(), "a step is unmeasured")
			} else {
				require.Empty(t, buf.String())
			}
		})
	}
	var nilPhases *syncPhases
	nilPhases.warnIfUnattributed(nil, time.Hour) // must not panic
}

// TestEveryDeclaredPhaseIsMarked keeps the phase set and the rebuild path coupled.
//
// A declared phase that nothing marks is an invisible step: it reads as measured in
// the metric help text and contributes nothing, so the sum silently under-attributes
// the rebuild. That is exactly the failure the load-digest gate ran into one
// layer up — a signal that exists but cannot move.
//
// Source-level because there is no seam to run a full SyncFromSources against
// ClickHouse and Ladybug in a unit test, and the natural way to add a phase is to
// declare the constant and forget the call.
func TestEveryDeclaredPhaseIsMarked(t *testing.T) {
	body := serviceSource(t)

	for _, phase := range []string{
		phaseLoad, phaseFilter, phaseReach, phaseDigest,
		phaseCopy, phaseBFS, phaseSwap, phaseSnapshot,
	} {
		constName := phaseConstName(t, phase)
		assert.Contains(t, body, "phases.mark("+constName+")",
			"phase %q is declared in sync_phases.go but never marked in the rebuild path. "+
				"Either mark it where that work happens, or delete the constant — a declared "+
				"phase that nobody records makes the phase sum under-attribute the rebuild "+
				"while looking measured.", phase)
	}
}

// phaseConstName maps a phase's value back to the Go identifier, so the guard above
// asserts on the constant the code actually uses rather than a string literal.
func phaseConstName(t *testing.T, phase string) string {
	t.Helper()
	switch phase {
	case phaseLoad:
		return "phaseLoad"
	case phaseFilter:
		return "phaseFilter"
	case phaseReach:
		return "phaseReach"
	case phaseDigest:
		return "phaseDigest"
	case phaseCopy:
		return "phaseCopy"
	case phaseBFS:
		return "phaseBFS"
	case phaseSwap:
		return "phaseSwap"
	case phaseSnapshot:
		return "phaseSnapshot"
	}
	t.Fatalf("unknown phase %q — add it to phaseConstName so the guard covers it", phase)
	return ""
}

// TestReachOverlayIsDerivedInOnePlace keeps the exposure set and the hop map derived
// exactly once per sweep.
//
// One rebuild needs both in three places: the load digest's node walk, the loader's
// node walk, and the post-swap signal-cache prewarm. Each used to derive its own,
// which is three full passes over the whole edge slice and three copies of both maps on a
// memory-constrained worker.
//
// The time is the smaller half of the reason. node_rows.go documents at length that
// `exposed[id]` and `hops[id] == 0` are deliberately NOT the same predicate —
// internetHops seeds the `possible` tier at possibleSeedDepth and filters
// InternetNodeID, exposedSeedSet does neither — so N independent derivations is N
// chances for the pair to drift, and drift here moves must-fix classification.
//
// Source-level for the same reason as TestDigestLatchIsGatedOnScoresApplied: the
// drift is invisible (no error, just a differently-scored graph), and the natural way
// to add a fourth consumer is to call the two derivations again.
func TestReachOverlayIsDerivedInOnePlace(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	callers := map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rErr := os.ReadFile(filepath.Clean(name))
		require.NoError(t, rErr)
		for i, line := range strings.Split(string(src), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx] // ignore prose that names the functions
			}
			if strings.Contains(code, "func internetHops(") || strings.Contains(code, "func exposedSeedSet(") {
				continue // the definitions themselves
			}
			for _, fn := range []string{"internetHops(", "exposedSeedSet("} {
				if strings.Contains(code, fn) {
					callers[fn] = append(callers[fn], name+":"+strconv.Itoa(i+1))
				}
			}
		}
	}

	for _, fn := range []string{"internetHops(", "exposedSeedSet("} {
		assert.Len(t, callers[fn], 1,
			"%s must be called from exactly one place in production code (newReachOverlay), "+
				"found %v. Every extra call is another full pass over the edge slice AND another "+
				"independent derivation of a pair that must agree — pass the reachOverlay down "+
				"instead.", fn, callers[fn])
	}
}
