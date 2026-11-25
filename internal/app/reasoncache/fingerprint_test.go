package reasoncache

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func base() FingerprintInput {
	return FingerprintInput{
		FindingID:     "f1",
		CheckID:       "c1",
		Type:          "exposure",
		ScoreBand:     "pipeline",
		BlastAssetIDs: []string{"b", "a", "c"},
		SeedID:        "i-1",
	}
}

func TestFingerprint_DeterministicAndOrderIndependent(t *testing.T) {
	a := Fingerprint(base())
	require.Equal(t, a, Fingerprint(base()), "deterministic")

	reordered := base()
	reordered.BlastAssetIDs = []string{"c", "a", "b"}
	require.Equal(t, a, Fingerprint(reordered), "asset-id set order must not matter")

	extraReordered := base()
	extraReordered.Extra = []string{"z", "a"}
	require.Equal(t, Fingerprint(func() FingerprintInput { i := base(); i.Extra = []string{"a", "z"}; return i }()),
		Fingerprint(extraReordered), "extra order must not matter")
}

func TestFingerprint_AnswerRelevantChangesFlipHash(t *testing.T) {
	a := Fingerprint(base())
	cases := map[string]func(*FingerprintInput){
		"band":      func(i *FingerprintInput) { i.ScoreBand = "high" },
		"kev":       func(i *FingerprintInput) { i.KnownExploited = true },
		"type":      func(i *FingerprintInput) { i.Type = "misconfiguration" },
		"check":     func(i *FingerprintInput) { i.CheckID = "c2" },
		"new-asset": func(i *FingerprintInput) { i.BlastAssetIDs = append(i.BlastAssetIDs, "d") },
		"exposure":  func(i *FingerprintInput) { i.Extra = []string{"internet_facing"} },
	}
	for name, mut := range cases {
		in := base()
		mut(&in)
		require.NotEqualf(t, a, Fingerprint(in), "%s should change the fingerprint", name)
	}
}

func TestFingerprint_TruncatedIsStableSentinel(t *testing.T) {
	t1 := base()
	t1.BlastTruncated = true
	t1.BlastAssetIDs = []string{"a", "b"}

	t2 := base()
	t2.BlastTruncated = true
	t2.BlastAssetIDs = []string{"x", "y", "z"} // different partial set, same seed

	require.Equal(t, Fingerprint(t1), Fingerprint(t2),
		"truncated walk hashes a stable seed sentinel, not the flapping partial set")
	require.NotEqual(t, Fingerprint(base()), Fingerprint(t1),
		"truncated differs from a complete walk")
}

// TestLogicVersionDrivesTheFingerprintPrefix pins the versioning mechanism
// itself: Fingerprint must hash LogicVersion in, not a bare literal, or bumping
// the constant would invalidate nothing.
func TestLogicVersionDrivesTheFingerprintPrefix(t *testing.T) {
	in := base()

	var b strings.Builder
	b.WriteString(LogicVersion)
	b.WriteByte('\n')
	writeLegacyBody(&b, in) // reimplements the non-version part, independently
	sum := sha256.Sum256([]byte(b.String()))

	require.NotEmpty(t, LogicVersion)
	require.Equal(t, hex.EncodeToString(sum[:]), Fingerprint(in),
		"Fingerprint must prefix its hashed material with LogicVersion")
}

// TestFingerprint_VersionBumpInvalidatesEveryKey is the hard requirement: a key
// computed under version N must not be served under version N+1. LogicVersion
// is a package constant, so this simulates the bump by recomputing the same
// hash construction Fingerprint uses with a different version string and
// confirming it diverges from the real Fingerprint(in) — i.e. had LogicVersion
// actually been bumped, every existing stored fingerprint would stop matching.
func TestFingerprint_VersionBumpInvalidatesEveryKey(t *testing.T) {
	in := base()
	underCurrent := Fingerprint(in)

	for _, bumped := range []string{"v5", "v6", "vNext"} {
		require.NotEqual(t, bumped, LogicVersion, "test bump must differ from the real constant")
		var b strings.Builder
		b.WriteString(bumped)
		b.WriteByte('\n')
		writeLegacyBody(&b, in)
		sum := sha256.Sum256([]byte(b.String()))
		underBumped := hex.EncodeToString(sum[:])

		require.NotEqual(t, underCurrent, underBumped,
			"a key computed under version %q must not be served under version %q", LogicVersion, bumped)
	}
}

// writeLegacyBody reimplements Fingerprint's post-version-prefix body,
// independently of the production code, so the two tests above are a real
// check that Fingerprint's version prefix does the invalidating — not a
// tautology that calls Fingerprint to test Fingerprint.
func writeLegacyBody(b *strings.Builder, in FingerprintInput) {
	b.WriteString(in.FindingID)
	b.WriteByte('\n')
	b.WriteString(in.CheckID)
	b.WriteByte('\n')
	b.WriteString(in.Type)
	b.WriteByte('\n')
	b.WriteString(in.ScoreBand)
	b.WriteByte('\n')
	if in.KnownExploited {
		b.WriteString("true\n")
	} else {
		b.WriteString("false\n")
	}
	if in.BlastTruncated {
		b.WriteString("blast:truncated:")
		b.WriteString(in.SeedID)
		b.WriteByte('\n')
	} else {
		ids := append([]string(nil), in.BlastAssetIDs...)
		sort.Strings(ids)
		for _, id := range ids {
			b.WriteString("a:")
			b.WriteString(id)
			b.WriteByte('\n')
		}
	}
	extra := append([]string(nil), in.Extra...)
	sort.Strings(extra)
	for _, e := range extra {
		b.WriteString("x:")
		b.WriteString(e)
		b.WriteByte('\n')
	}
}
