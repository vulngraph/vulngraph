package benchmarks

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const snapshotTestDir = "testdata/sources"

// TestMatricesMatchUpstreamSnapshot is the completeness gate (ADR 092): each
// matrix's control-ID set must equal the list benchmark-watch recorded from
// its upstream, except for differences acknowledged with a reason. A control
// upstream adds and the matrix lacks would otherwise be coverage nobody is
// tracking, and a matrix row upstream dropped would be coverage claimed for a
// control that no longer exists.
//
// Only ID sets are compared, never statuses or check lists, so edits to
// existing rows never trip it. An acknowledgement that has since been
// reconciled FAILS: left in place it would silently re-mask the same
// difference if it came back, so the branch that adds the row also deletes
// the entry.
func TestMatricesMatchUpstreamSnapshot(t *testing.T) {
	bs, err := Load()
	require.NoError(t, err)
	snaps, err := ReadSnapshots(snapshotTestDir)
	require.NoError(t, err)
	acks, err := ReadAcknowledged(snapshotTestDir)
	require.NoError(t, err)

	for _, b := range bs {
		t.Run(b.ID, func(t *testing.T) {
			snap, ok := snaps[b.ID]
			require.True(t, ok, "no upstream snapshot for %s — run: go run ./cmd/benchmark-watch -update", b.ID)
			require.Equal(t, b.Version, snap.Pinned,
				"%s is pinned to %s but its snapshot was recorded for %s — run: go run ./cmd/benchmark-watch -update", b.ID, b.Version, snap.Pinned)
			ack := acks[b.ID]
			d := DiffIDs(b, snap.ControlIDs)
			var unexplained []string
			for _, id := range d.MissingFromMatrix {
				if _, ok := ack.MissingFromMatrix[id]; !ok {
					unexplained = append(unexplained, id+" (upstream, no matrix row)")
				}
			}
			for _, id := range d.NotInSource {
				if _, ok := ack.NotInSource[id]; !ok {
					unexplained = append(unexplained, id+" (matrix row, not upstream)")
				}
			}
			require.Empty(t, unexplained, "%s differs from %s: %s — add or drop the rows, or acknowledge them in %s/%s",
				b.ID, snap.Source, strings.Join(unexplained, ", "), snapshotTestDir, AcknowledgedFile)
			stale := append(reconciled(ack.MissingFromMatrix, d.MissingFromMatrix), reconciled(ack.NotInSource, d.NotInSource)...)
			require.Empty(t, stale, "%s: acknowledged differences no longer exist — remove them from %s/%s so they cannot re-mask drift",
				b.ID, snapshotTestDir, AcknowledgedFile)
		})
	}
}

// reconciled lists the acknowledged IDs that are no longer a difference.
func reconciled(acked map[string]string, still []string) []string {
	open := map[string]bool{}
	for _, id := range still {
		open[id] = true
	}
	var out []string
	for id := range acked {
		if !open[id] {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

func TestAcknowledgementsGiveReasons(t *testing.T) {
	acks, err := ReadAcknowledged(snapshotTestDir)
	require.NoError(t, err)
	bs, err := Load()
	require.NoError(t, err)
	known := map[string]bool{}
	for _, b := range bs {
		known[b.ID] = true
	}
	for bm, a := range acks {
		require.True(t, known[bm], "acknowledgement for unknown benchmark %q", bm)
		for _, m := range []map[string]string{a.MissingFromMatrix, a.NotInSource} {
			for id, why := range m {
				require.NotEmpty(t, strings.TrimSpace(why), "%s %s: acknowledgement without a reason", bm, id)
			}
		}
	}
}

func TestDiffIDs(t *testing.T) {
	b := Benchmark{Controls: []Control{{ID: "1.1"}, {ID: "1.2"}, {ID: "9.9"}}}
	d := DiffIDs(b, []string{"1.1", "1.2", "1.3"})
	require.Equal(t, []string{"1.3"}, d.MissingFromMatrix)
	require.Equal(t, []string{"9.9"}, d.NotInSource)
	require.Empty(t, DiffIDs(b, []string{"9.9", "1.2", "1.1"}).MissingFromMatrix, "order is irrelevant")
}
