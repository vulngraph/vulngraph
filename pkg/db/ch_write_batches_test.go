package db

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteBatchesRespectRowsBytesAndOversizedProgress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sizes []int
		want  []int
	}{
		{"small", make([]int, 4501), []int{2000, 2000, 501}},
		{"wide", []int{CHWriteMaxBytes / 2, CHWriteMaxBytes / 2, 1}, []int{2, 1}},
		{"oversized", []int{CHWriteMaxBytes + 1, 1, CHWriteMaxBytes + 1}, []int{1, 1, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []int
			for start := 0; start < len(tc.sizes); {
				end := CHWriteBatchEnd(tc.sizes, start, func(n int) int { return n })
				require.Greater(t, end, start)
				got = append(got, end-start)
				start = end
			}
			require.Equal(t, tc.want, got)
		})
	}
	require.Greater(t, CHMapBytes(map[string]string{"wide": strings.Repeat("\x00", 1000)}), 6000)
}
