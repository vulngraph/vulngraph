package distro

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompareDpkg(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0", "1.0+deb12u1", -1},
		{"3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1},
		{"3.0.11-1~deb12u2", "3.0.11-1", -1},
		{"1:1.0", "2.0", 1},
		{"0:1.0", "1.0", 0},
		{"1.0-1", "1.0-1ubuntu1", -1},
		{"2.31-13+deb11u5", "2.31-13+deb11u11", -1},
		{"1.2a", "1.2", 1},
		{"1.2a", "1.2.1", -1}, // letters sort before other punctuation
		{"00012", "12", 0},
		{"99999999999999999999.1", "99999999999999999999.2", -1},
	} {
		require.Equal(t, tc.want, CompareDpkg(tc.a, tc.b), "%s vs %s", tc.a, tc.b)
		require.Equal(t, -tc.want, CompareDpkg(tc.b, tc.a), "%s vs %s (reversed)", tc.b, tc.a)
	}
}
