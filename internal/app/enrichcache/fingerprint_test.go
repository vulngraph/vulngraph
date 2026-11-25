package enrichcache

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

func base() FingerprintInput {
	return FingerprintInput{
		FindingID:  "f1",
		CheckID:    "c1",
		Type:       "exposure",
		Severity:   "high",
		ResourceID: "i-1",
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	require.Equal(t, Fingerprint(base()), Fingerprint(base()))
}

// TestReachBucketFor_TransitiveLabelDerivesFromMaxReachDepth couples the
// transitive-reach bucket's display text to graphschema.MaxReachDepth (declare
// once, derive everywhere) — a bare "1-3" literal here would silently go stale
// the moment MaxReachDepth changed, since nothing else would fail.
func TestReachBucketFor_TransitiveLabelDerivesFromMaxReachDepth(t *testing.T) {
	want := fmt.Sprintf("1-%d", graphschema.MaxReachDepth)
	require.Equal(t, want, ReachBucketFor(1, true))
	require.Equal(t, want, ReachBucketFor(graphschema.MaxReachDepth, true))
}

func TestReachBucketFor_UnknownNoneDirect(t *testing.T) {
	require.Equal(t, "", ReachBucketFor(2, false), "unknown must not churn the cache as a real bucket")
	require.Equal(t, "none", ReachBucketFor(-1, true))
	require.Equal(t, "direct", ReachBucketFor(0, true))
}

func TestFingerprint_InputChangesFlipHash(t *testing.T) {
	a := Fingerprint(base())
	cases := map[string]func(*FingerprintInput){
		"check":    func(i *FingerprintInput) { i.CheckID = "c2" },
		"type":     func(i *FingerprintInput) { i.Type = "misconfiguration" },
		"severity": func(i *FingerprintInput) { i.Severity = "critical" },
		"resource": func(i *FingerprintInput) { i.ResourceID = "i-2" },
		"kev":      func(i *FingerprintInput) { i.KnownExploited = true },
		"reach":    func(i *FingerprintInput) { i.ReachBucket = "1-3" },
	}
	for name, mut := range cases {
		in := base()
		mut(&in)
		require.NotEqualf(t, a, Fingerprint(in), "%s should change the fingerprint", name)
	}
}

// A read that failed carries the last measurement; with none, the field stays
// unmeasured rather than inventing one.
func TestCarryForward(t *testing.T) {
	prev := GraphContext{Exposed: "true", PrivescBucket: "2-3", ReachBucket: "direct"}
	in := base()
	got, stored := CarryForward(in, Measured{}, prev)
	require.True(t, got.IsExposed)
	require.Equal(t, "2-3", got.PrivescBucket)
	require.Equal(t, "direct", got.ReachBucket)
	require.Equal(t, prev, stored)

	measured := base()
	measured.PrivescBucket, measured.ReachBucket = "0", "none"
	got, stored = CarryForward(measured, Measured{Exposed: true, Privesc: true, Reach: true}, prev)
	require.False(t, got.IsExposed, "a measurement always wins over the carried value")
	require.Equal(t, GraphContext{Exposed: "false", PrivescBucket: "0", ReachBucket: "none"}, stored)

	got, stored = CarryForward(base(), Measured{}, GraphContext{})
	require.Equal(t, base(), got)
	require.Equal(t, GraphContext{}, stored, "nothing measured, nothing carried: stays unmeasured")
}
