package asset

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCapChangeValue covers the truncation contract: values at or under the cap are
// byte-identical, and oversized ones keep a readable prefix plus their true length and
// a digest.
func TestCapChangeValue(t *testing.T) {
	t.Run("under the cap is untouched", func(t *testing.T) {
		for _, n := range []int{0, 1, changeValueCap - 1, changeValueCap} {
			v := strings.Repeat("x", n)
			require.Equal(t, v, capChangeValue(v), "a %d-byte value must not be rewritten", n)
		}
	})

	t.Run("over the cap keeps a prefix plus length and digest", func(t *testing.T) {
		v := strings.Repeat("x", changeValueCap+1)
		got := capChangeValue(v)
		require.NotEqual(t, v, got)
		require.True(t, strings.HasPrefix(got, v[:changeValueCap]),
			"the prefix must stay readable for a responder scanning the timeline")
		require.Contains(t, got, "1025B", "the marker must carry the TRUE length, not the truncated one")
		require.Contains(t, got, "sha256:")
		require.Less(t, len(got), changeValueCap+64, "the marker must be small and bounded")
	})

	// The reason the digest exists. Without it, two different oversized values that
	// share a prefix would store identically, so old_value == new_value in the log and
	// a real change would read as "nothing happened".
	t.Run("different oversized values stay distinguishable", func(t *testing.T) {
		a := strings.Repeat("x", changeValueCap) + "AAA"
		b := strings.Repeat("x", changeValueCap) + "BBB"
		require.NotEqual(t, capChangeValue(a), capChangeValue(b))
	})

	// Same length, different content — the length alone cannot separate these, so this
	// pins that the digest (not just the length) is doing the work.
	t.Run("same length different content stay distinguishable", func(t *testing.T) {
		a := strings.Repeat("a", changeValueCap+10)
		b := strings.Repeat("b", changeValueCap+10)
		require.NotEqual(t, capChangeValue(a), capChangeValue(b))
	})
}

// TestDiffFields_DetectsChangesBeyondTheCap pins that capping does not cost detection:
// two values differing only past the 1 KiB boundary still produce a change, and the
// stored (capped) forms still show that something changed.
//
// Scope note, because it is easy to over-claim here: this does NOT prove that comparing
// before capping is required. It was written expecting that, and capping first still
// passes — the digest keeps capped values distinct. DiffFields compares uncapped anyway
// (see capChangeValue's comment), but that is a robustness preference, not something
// this test enforces.
func TestDiffFields_DetectsChangesBeyondTheCap(t *testing.T) {
	// Identical 1 KiB prefix, different tails — indistinguishable if capped too early.
	oldVal := strings.Repeat("p", changeValueCap) + "-OLD"
	newVal := strings.Repeat("p", changeValueCap) + "-NEW"

	old := Asset{ID: "i-1", Metadata: map[string]string{"permissions": oldVal}}
	next := Asset{ID: "i-1", Metadata: map[string]string{"permissions": newVal}}

	got := DiffFields(old, next)

	require.Len(t, got, 1, "a change beyond the cap boundary must still be detected")
	require.Equal(t, "meta:permissions", got[0].Field)
	require.LessOrEqual(t, len(got[0].OldValue), changeValueCap+64, "stored value must be capped")
	require.LessOrEqual(t, len(got[0].NewValue), changeValueCap+64, "stored value must be capped")
	require.NotEqual(t, got[0].OldValue, got[0].NewValue,
		"a capped row must still show that the value changed")
}

// A change entirely under the cap must round-trip byte-for-byte — the common case, and
// the one the timeline actually renders.
func TestDiffFields_SmallValuesRoundTrip(t *testing.T) {
	old := Asset{ID: "i-1", PublicIP: "1.2.3.4"}
	next := Asset{ID: "i-1", PublicIP: "5.6.7.8"}

	got := DiffFields(old, next)

	require.Len(t, got, 1)
	require.Equal(t, "public_ip", got[0].Field)
	require.Equal(t, "1.2.3.4", got[0].OldValue)
	require.Equal(t, "5.6.7.8", got[0].NewValue)
}
