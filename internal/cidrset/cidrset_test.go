package cidrset

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCoversWorld(t *testing.T) {
	tests := []struct {
		cidrs []string
		want  bool
	}{
		{[]string{"0.0.0.0/0"}, true},
		{[]string{"::/0"}, true},
		{[]string{"0.0.0.0/1", "128.0.0.0/1"}, true},
		{[]string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1"}, true},
		{[]string{"0.0.0.0/1", "128.0.0.0/2"}, false},
		{[]string{"0.0.0.0/1", "8000::/1"}, false},
		{[]string{"10.0.0.0/8", "not-a-cidr"}, false},
		{[]string{" 0.0.0.0/1", "128.0.0.1/1"}, true},
		{nil, false},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, CoversWorld(tt.cidrs), "%v", tt.cidrs)
	}
}

func TestCover(t *testing.T) {
	target := netip.MustParsePrefix("10.0.1.0/24")
	tests := []struct {
		cidrs []string
		want  bool
	}{
		{[]string{"10.0.0.0/16"}, true},
		{[]string{"10.0.1.0/25", "10.0.1.128/25"}, true},
		{[]string{"10.0.1.0/25"}, false},
		{[]string{"10.0.2.0/24"}, false},
		{[]string{"::/0"}, false},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, Cover(Parse(tt.cidrs), target), "%v", tt.cidrs)
	}
}
