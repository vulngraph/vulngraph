package rpmver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVercmp is rpm's own rpmvercmp table (tests/rpmvercmp.at), so this port
// agrees with the tool that actually decides what gets installed.
func TestVercmp(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0}, {"1.0", "2.0", -1}, {"2.0", "1.0", 1},
		{"2.0.1", "2.0.1", 0}, {"2.0", "2.0.1", -1}, {"2.0.1", "2.0", 1},
		{"2.0.1a", "2.0.1a", 0}, {"2.0.1a", "2.0.1", 1}, {"2.0.1", "2.0.1a", -1},
		{"5.5p1", "5.5p1", 0}, {"5.5p1", "5.5p2", -1}, {"5.5p2", "5.5p1", 1},
		{"5.5p10", "5.5p10", 0}, {"5.5p1", "5.5p10", -1}, {"5.5p10", "5.5p1", 1},
		{"10xyz", "10.1xyz", -1}, {"10.1xyz", "10xyz", 1},
		{"xyz10", "xyz10", 0}, {"xyz10", "xyz10.1", -1}, {"xyz10.1", "xyz10", 1},
		{"xyz.4", "xyz.4", 0}, {"xyz.4", "8", -1}, {"8", "xyz.4", 1},
		{"xyz.4", "2", -1}, {"2", "xyz.4", 1},
		{"5.5p2", "5.6p1", -1}, {"5.6p1", "5.5p2", 1},
		{"5.6p1", "6.5p1", -1}, {"6.5p1", "5.6p1", 1},
		{"6.0.rc1", "6.0", 1}, {"6.0", "6.0.rc1", -1},
		{"10b2", "10a1", 1}, {"10a2", "10b2", -1},
		{"1.0aa", "1.0aa", 0}, {"1.0a", "1.0aa", -1}, {"1.0aa", "1.0a", 1},
		{"10.0001", "10.0001", 0}, {"10.0001", "10.1", 0}, {"10.1", "10.0001", 0},
		{"10.0001", "10.0039", -1}, {"10.0039", "10.0001", 1},
		{"4.999.9", "5.0", -1}, {"5.0", "4.999.9", 1},
		{"20101121", "20101121", 0}, {"20101121", "20101122", -1}, {"20101122", "20101121", 1},
		{"2_0", "2_0", 0}, {"2.0", "2_0", 0}, {"2_0", "2.0", 0},
		{"a", "a", 0}, {"a+", "a+", 0}, {"a+", "a_", 0}, {"a_", "a+", 0},
		{"+a", "+a", 0}, {"+a", "_a", 0}, {"_a", "+a", 0},
		{"+_", "+_", 0}, {"_+", "+_", 0}, {"_+", "_+", 0}, {"+", "_", 0}, {"_", "+", 0},
		{"1.0~rc1", "1.0~rc1", 0}, {"1.0~rc1", "1.0", -1}, {"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1}, {"1.0~rc2", "1.0~rc1", 1},
		{"1.0~rc1~git123", "1.0~rc1~git123", 0}, {"1.0~rc1~git123", "1.0~rc1", -1}, {"1.0~rc1", "1.0~rc1~git123", 1},
		{"1.0^", "1.0^", 0}, {"1.0^", "1.0", 1}, {"1.0", "1.0^", -1},
		{"1.0^git1", "1.0^git1", 0}, {"1.0^git1", "1.0", 1}, {"1.0", "1.0^git1", -1},
		{"1.0^git1", "1.0^git2", -1}, {"1.0^git2", "1.0^git1", 1},
		{"1.0^git1", "1.01", -1}, {"1.01", "1.0^git1", 1},
		{"1.0^20160101", "1.0^20160101", 0}, {"1.0^20160101", "1.0.1", -1}, {"1.0.1", "1.0^20160101", 1},
		{"1.0^20160101^git1", "1.0^20160101^git1", 0},
		{"1.0^20160102", "1.0^20160101^git1", 1}, {"1.0^20160101^git1", "1.0^20160102", -1},
		{"1.0~rc1^git1", "1.0~rc1^git1", 0}, {"1.0~rc1^git1", "1.0~rc1", 1}, {"1.0~rc1", "1.0~rc1^git1", -1},
		{"1.0^git1~pre", "1.0^git1~pre", 0}, {"1.0^git1", "1.0^git1~pre", 1}, {"1.0^git1~pre", "1.0^git1", -1},
		// Distro backport shapes the advisory feeds actually publish.
		{"1.0.2k", "1.0.2", 1},
		{"24.amzn2.0.4", "24.amzn2.0.12", -1},
		{"27.el9_4", "27.el9", 1},
		{"150500.5.3.1", "150500.5.1", 1},
		// Digit runs longer than any machine integer still compare by value.
		{"123456789012345678901234567890", "123456789012345678901234567889", 1},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, Vercmp(tt.a, tt.b), "rpmvercmp(%q, %q)", tt.a, tt.b)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		in   string
		want EVR
	}{
		{"1:3.0.7-27.el9", EVR{Epoch: "1", Version: "3.0.7", Release: "27.el9"}},
		{"3.0.7-27.el9", EVR{Version: "3.0.7", Release: "27.el9"}},
		{"0:1.0-1", EVR{Version: "1.0", Release: "1"}},
		{"007:1.0-1", EVR{Epoch: "7", Version: "1.0", Release: "1"}},
		{"1.0", EVR{Version: "1.0"}},
		// A non-numeric prefix is not an epoch.
		{"a:1.0-1", EVR{Version: "a:1.0", Release: "1"}},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, Parse(tt.in), tt.in)
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// Epoch dominates version and release.
		{"1:1.0-1", "2.0-1", 1},
		{"2.0-1", "1:1.0-1", -1},
		// Missing epoch is 0.
		{"0:1.0-1", "1.0-1", 0},
		{"1:3.0.7-24.el9", "1:3.0.7-27.el9", -1},
		{"1:3.0.7-27.el9", "1:3.0.7-27.el9", 0},
		{"1.0.2k-24.amzn2.0.4", "1.0.2k-24.amzn2.0.12", -1},
		// Version decides before release.
		{"1.10-1", "1.9-99", 1},
		// A release on only one side is not compared.
		{"1.0", "1.0-3", 0},
		{"10:1-1", "9:99-99", 1},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, Compare(tt.a, tt.b), "Compare(%q, %q)", tt.a, tt.b)
	}
}
