package guardmutation

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// shardEnv names the variable that splits the audit across CI jobs: "K/N" runs
// the K-th (zero-based) of N slices of the catalogue. Unset runs all of it.
const shardEnv = "GUARD_SHARD"

// parseShard reads a "K/N" value. The empty string is the whole catalogue.
func parseShard(v string) (k, n int, err error) {
	if v == "" {
		return 0, 1, nil
	}
	ks, ns, ok := strings.Cut(v, "/")
	if !ok {
		return 0, 0, fmt.Errorf("%s=%q: want K/N", shardEnv, v)
	}
	if k, err = strconv.Atoi(ks); err != nil {
		return 0, 0, fmt.Errorf("%s=%q: %w", shardEnv, v, err)
	}
	if n, err = strconv.Atoi(ns); err != nil {
		return 0, 0, fmt.Errorf("%s=%q: %w", shardEnv, v, err)
	}
	if n < 1 || k < 0 || k >= n {
		return 0, 0, fmt.Errorf("%s=%q: need 0 <= K < N", shardEnv, v)
	}
	return k, n, nil
}

// inShard reports whether the i-th mutation belongs to slice k of n. Interleaving
// (rather than cutting the catalogue into runs) spreads the slow guards, which
// cluster by package, across the slices.
func inShard(i, k, n int) bool { return i%n == k }

func TestParseShard(t *testing.T) {
	for _, tc := range []struct {
		in   string
		k, n int
		bad  bool
	}{
		{"", 0, 1, false},
		{"0/1", 0, 1, false},
		{"3/5", 3, 5, false},
		{"5/5", 0, 0, true},
		{"-1/5", 0, 0, true},
		{"1/0", 0, 0, true},
		{"x/5", 0, 0, true},
		{"3", 0, 0, true},
	} {
		k, n, err := parseShard(tc.in)
		if tc.bad {
			require.Errorf(t, err, "%q", tc.in)
			continue
		}
		require.NoErrorf(t, err, "%q", tc.in)
		require.Equal(t, tc.k, k, tc.in)
		require.Equal(t, tc.n, n, tc.in)
	}
}

// Every mutation runs in exactly one shard, so splitting the audit never drops
// a guard and never runs one twice.
func TestShardsPartitionTheCatalogue(t *testing.T) {
	for _, n := range []int{1, 2, 5, 7} {
		ran := make([]int, len(mutations))
		for k := range n {
			for i := range mutations {
				if inShard(i, k, n) {
					ran[i]++
				}
			}
		}
		for i, c := range ran {
			require.Equalf(t, 1, c, "mutation %d (%s) ran %d times across %d shards", i, mutations[i].Guard, c, n)
		}
	}
}
