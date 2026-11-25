// Sync outcome recording and connector fingerprint helpers: persisting
// RecordSync on a context detached from the job's own (possibly expired) ctx,
// the cleanNoOp backoff-streak gate, and the asset/checks fingerprint
// combine/split used by the sync short-circuit and the check-registry
// backfill. Kept out of sync.go to stay under the file-length ceiling.
package jobs

import (
	"context"
	"strings"
	"time"
)

// recordSyncTimeout bounds the failure-recording write with its own fresh
// deadline (context.WithoutCancel + this timeout), never the job's own ctx.
// RecordSync's whole job is to persist THAT a sync failed — the dominant
// failure mode is exactly a context-deadline error from Collect/Ingest/
// RecordObserved, and handing that same expired ctx to the write would make
// it fail too, silently, every time, leaving sync_error empty and
// last_synced_at frozen while the connector keeps failing invisibly.
const recordSyncTimeout = 5 * time.Second

// syncRecorder is the one method recordSync needs — narrowed rather than
// *connector.Service so a unit test can supply a trivial fake without
// implementing connector.Repo's full (unexported-return-type) interface.
type syncRecorder interface {
	RecordSync(ctx context.Context, id string, runErr error, at time.Time, cleanNoOp, partial bool) error
}

// recordSync persists a sync outcome on a context detached from the job's own
// (possibly already-expired) ctx — see recordSyncTimeout. cleanNoOp feeds the
// connector's backoff streak (connector.Connector.SyncStreak) — see
// cleanNoOp's own doc for what qualifies. partial feeds
// connector.Connector.PartialStreak, independent of cleanNoOp/runErr: a
// Partial sync still has runErr == nil, so without this the connector's only
// automated health signal (LastSuccessAt) never sees that a phase kept
// getting skipped.
func recordSync(ctx context.Context, connectors syncRecorder, id string, runErr error, cleanNoOp, partial bool) error {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordSyncTimeout)
	defer cancel()
	return connectors.RecordSync(writeCtx, id, runErr, time.Now(), cleanNoOp, partial)
}

// cleanNoOp reports whether a sync qualifies to advance the connector's
// backoff streak: the collection succeeded, matched the stored fingerprint
// (skipped == true, the sync short-circuit), and was neither Partial (some
// collector call failed/skipped this sweep — a fingerprint match from a
// half-collected sweep is not a trustworthy "nothing changed" signal) nor a
// pending check-registry backfill (skipped can only be true when
// needBackfill is false already, but this is stated explicitly rather than
// relied on implicitly, so a future change to that invariant fails a test
// here instead of silently over-extending the backoff).
func cleanNoOp(runErr error, skipped, partial, needBackfill bool) bool {
	return runErr == nil && skipped && !partial && !needBackfill
}

// checksFPSep separates the asset fingerprint from the check-registry
// fingerprint inside the stored connector sync_fingerprint. Storing the check
// identity per connector (not in worker memory) is what makes the new-check
// backfill fire exactly once per connector per check deployment.
const checksFPSep = "|checks:"

// clockDaySep separates the check-registry fingerprint from the UTC day the
// connector's time-dependent checks were last evaluated on every asset (see
// recheckTimeDependent). Per connector, for the same reason as checksFPSep.
const clockDaySep = "|day:"

// syncFingerprint is the stored sync_fingerprint, parsed.
type syncFingerprint struct {
	assetFP  string // asset content fingerprint: the short-circuit key
	checksFP string // check-registry fingerprint: a mismatch forces a backfill
	day      string // UTC day time-dependent checks last ran on every asset
}

// combineSyncFingerprint builds the stored fingerprint. An empty asset
// fingerprint stays empty — it means "never short-circuit", and must keep
// meaning that.
func combineSyncFingerprint(fp syncFingerprint) string {
	if fp.assetFP == "" {
		return ""
	}
	return fp.assetFP + checksFPSep + fp.checksFP + clockDaySep + fp.day
}

// splitSyncFingerprint parses a stored fingerprint. Fingerprints written
// before the checks suffix existed split with an empty checks part, which
// mismatches any live registry and forces exactly one backfill sweep per
// connector; ones written before the day suffix split with an empty day, which
// makes the time-dependent re-check due on the next sweep.
func splitSyncFingerprint(stored string) syncFingerprint {
	var fp syncFingerprint
	if i := strings.LastIndex(stored, clockDaySep); i >= 0 {
		stored, fp.day = stored[:i], stored[i+len(clockDaySep):]
	}
	if i := strings.LastIndex(stored, checksFPSep); i >= 0 {
		fp.assetFP, fp.checksFP = stored[:i], stored[i+len(checksFPSep):]
		return fp
	}
	fp.assetFP = stored
	return fp
}

// clockDay is the UTC calendar day of t, the granularity the time-dependent
// checks change at (an end-of-life date passes at a day boundary).
func clockDay(t time.Time) string { return t.UTC().Format(time.DateOnly) }
