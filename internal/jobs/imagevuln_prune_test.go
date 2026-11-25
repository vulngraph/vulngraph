package jobs

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// captureLog swaps the global zerolog writer for a buffer for the duration of
// fn, restoring it afterward — the established pattern for asserting on log
// output in this codebase (see internal/collect/aws/aws_test.go).
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	orig := zlog.Logger
	zlog.Logger = zerolog.New(zerolog.SyncWriter(&buf))
	t.Cleanup(func() { zlog.Logger = orig })
	fn()
	return buf.String()
}

// TestLogStalestDigest_NothingStaleLogsNothing is the common case: every
// tracked digest is within the coverage gauge's own tolerance
// (2*imageRescanAfter), so there is nothing worth a WARN line about.
func TestLogStalestDigest_NothingStaleLogsNothing(t *testing.T) {
	cursor := &fakeCursor{states: map[string]imageScanState{
		"sha256:a": {scannedAt: time.Now().Add(-time.Hour)},
	}}
	w := &ImageVulnWorker{cursor: cursor}

	out := captureLog(t, func() {
		w.logStalestDigest(context.Background(), imageAssets("sha256:a"))
	})
	require.Empty(t, out)
}

// TestLogStalestDigest_StillInInventoryWithFailures is the "keeps failing to
// rescan" case this diagnostic exists to distinguish from an orphan: the
// digest is stale, but liveImageDigests would call it live (recent LastSeen),
// so pruneOrphaned correctly leaves it alone — the coverage gauge alone
// cannot tell that apart from a digest nobody is even trying to scan.
func TestLogStalestDigest_StillInInventoryWithFailures(t *testing.T) {
	stale := time.Now().Add(-14 * 24 * time.Hour)
	cursor := &fakeCursor{states: map[string]imageScanState{
		"sha256:stuck": {
			scannedAt: stale, attemptedAt: time.Now().Add(-time.Hour),
			failures: 6, lastError: "pull access denied",
		},
		"sha256:fine": {scannedAt: time.Now().Add(-time.Hour)},
	}}
	w := &ImageVulnWorker{cursor: cursor}

	out := captureLog(t, func() {
		w.logStalestDigest(context.Background(), imageAssets("sha256:stuck", "sha256:fine"))
	})
	require.Contains(t, out, `"digest":"sha256:stuck"`)
	require.Contains(t, out, `"still_in_inventory":true`)
	require.Contains(t, out, `"failures":6`)
	require.Contains(t, out, `"last_error":"pull access denied"`,
		"the stored failure reason must be surfaced — it is already in the row, no DB query needed")
	require.NotContains(t, out, "sha256:fine",
		"only the worst offender is reported, not every tracked digest")
}

// TestLogStalestDigest_NotInInventoryMeansPruneBug: if the stalest digest is
// NOT in the live listing at all, pruneOrphaned should already have deleted
// its row — seeing it here at the same time means that guard has a bug, and
// this diagnostic must say so plainly rather than blend it with the
// keeps-failing case above.
func TestLogStalestDigest_NotInInventoryMeansPruneBug(t *testing.T) {
	stale := time.Now().Add(-14 * 24 * time.Hour)
	cursor := &fakeCursor{states: map[string]imageScanState{
		"sha256:orphaned": {scannedAt: stale},
	}}
	w := &ImageVulnWorker{cursor: cursor}

	out := captureLog(t, func() {
		w.logStalestDigest(context.Background(), nil) // orphaned: not in any current listing
	})
	require.Contains(t, out, `"digest":"sha256:orphaned"`)
	require.Contains(t, out, `"still_in_inventory":false`)
}

// A never-scanned digest (scannedAt zero) is graph_image_scan_never_scanned's
// own accepted floor, not this diagnostic's problem — it must never be
// reported as "the stalest digest" just because zero sorts oldest.
func TestLogStalestDigest_NeverScannedIsNotTheStalestDigest(t *testing.T) {
	cursor := &fakeCursor{states: map[string]imageScanState{
		"sha256:never-scanned": {attemptedAt: time.Now()}, // scannedAt zero
		"sha256:stale":         {scannedAt: time.Now().Add(-14 * 24 * time.Hour)},
	}}
	w := &ImageVulnWorker{cursor: cursor}

	out := captureLog(t, func() {
		w.logStalestDigest(context.Background(), imageAssets("sha256:stale"))
	})
	require.Contains(t, out, `"digest":"sha256:stale"`)
	require.NotContains(t, out, "never-scanned")
}

// A nil cursor (no Postgres wired) must degrade to a no-op, the same posture
// as pruneOrphaned/scanStates/recordAttempts.
func TestLogStalestDigest_NilCursorIsNoOp(t *testing.T) {
	w := &ImageVulnWorker{}
	out := captureLog(t, func() {
		require.NotPanics(t, func() {
			w.logStalestDigest(context.Background(), imageAssets("sha256:a"))
		})
	})
	require.Empty(t, out)
}
