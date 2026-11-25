package jobs

import (
	"context"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// imageAssetLivenessWindow bounds how stale a container_image asset's
// LastSeen may be and still count as "live" — see liveImageDigests. 72h
// mirrors EphemeralLivenessCond's buffer for the identical corpse-row
// problem: tiny next to the multi-day staleness the prune exists to catch.
const imageAssetLivenessWindow = 72 * time.Hour

// pruneOrphaned removes image_scan_state rows for digests no longer present
// in the current container_image inventory. GraphImageScanCoverageStale reads
// min(scanned_at) across the cursor table, and a digest that succeeds once
// and then drops out of inventory (retagged, or the asset decommissioned) is
// never touched again by selectTargets, so its scanned_at freezes forever and
// permanently depresses that metric regardless of the rest of the estate's
// coverage. OSV has the equivalent fix (DeleteOrphanedScannedPackages).
//
// Skipped, not just a no-op prune, when the listing looks truncated
// (len(images) == listImageLimit) or resolves to zero digests: either makes
// "live" untrustworthy, and this deletes rows, so a wrong snapshot must never
// be authoritative. Best-effort otherwise — a failed prune just leaves a
// stale row for one more cycle, same posture as recordAttempts.
func (w *ImageVulnWorker) pruneOrphaned(ctx context.Context, images []asset.Asset) {
	logger := log.FromContext(ctx)
	if w.cursor == nil {
		return
	}
	if len(images) >= listImageLimit {
		logger.Warn().Int("limit", listImageLimit).
			Msg("imagevuln: container_image listing looks truncated; skipping orphan prune this sweep")
		return
	}
	digests := liveImageDigests(images)
	if len(digests) == 0 {
		return
	}
	pruned, err := w.cursor.PruneOrphaned(ctx, digests, time.Now().Add(-imageRescanAfter))
	if err != nil {
		logger.Warn().Err(err).Msg("imagevuln: failed to prune orphaned image-scan cursor rows")
		return
	}
	if pruned > 0 {
		logger.Info().Int64("pruned", pruned).
			Msg("imagevuln: pruned orphaned image-scan cursor rows")
	}
}

// logStalestDigest surfaces graph_image_scan_oldest_scanned_timestamp_seconds'
// own worst offender, since the gauge itself cannot say WHY a digest is
// stuck: either it's an orphaned-inventory case pruneOrphaned should have
// caught (a bug if still_in_inventory is false), or it keeps failing to scan
// and re-entering backoff (a digest stuck in retry-and-fail looks identical
// to one that's stopped being attempted at all from the coverage gauge
// alone). Logs at WARN.
func (w *ImageVulnWorker) logStalestDigest(ctx context.Context, images []asset.Asset) {
	if w.cursor == nil {
		return
	}
	states, err := w.cursor.States(ctx)
	if err != nil || len(states) == 0 {
		return
	}
	live := make(map[string]bool, len(images))
	for _, img := range images {
		if d := img.Metadata["image_id"]; d != "" {
			live[d] = true
		}
	}
	var (
		worstDigest string
		worst       imageScanState
		found       bool
	)
	for digest, st := range states {
		if st.scannedAt.IsZero() {
			continue // never-scanned floor is graph_image_scan_never_scanned's own problem
		}
		if !found || st.scannedAt.Before(worst.scannedAt) {
			worstDigest, worst, found = digest, st, true
		}
	}
	if !found || time.Since(worst.scannedAt) < 2*imageRescanAfter {
		return // nothing meaningfully stale — the common case, log nothing
	}
	log.FromContext(ctx).Warn().
		Str("digest", worstDigest).
		Bool("still_in_inventory", live[worstDigest]).
		Int("failures", worst.failures).
		Str("last_error", worst.lastError).
		Dur("since_last_scan", time.Since(worst.scannedAt)).
		Dur("since_last_attempt", time.Since(worst.attemptedAt)).
		Msg("imagevuln: worst-covered digest is stale — still_in_inventory=false means an orphan " +
			"prune should have caught it (bug); true with failures>0 means it keeps failing to " +
			"rescan (see last_error); true with failures=0 and a recent attempt means it is not " +
			"yet being selected")
}

// liveImageDigests extracts every resolved digest from a container_image
// listing whose LastSeen is recent, deduplicated.
//
// The LastSeen filter matters because ListByType (backed by assetIDsByType)
// applies no liveness gate of its own, and asset rows are never deleted — so
// without this filter a decommissioned image's row is returned forever and
// its orphaned digest reads as still-tracked, defeating pruneOrphaned.
// Filtered on the asset's OWN LastSeen rather than widening the shared
// assetIDsByType/inventoryReadCond machinery (OSV's paging need there
// differs) to keep this local. Digest resolution mirrors selectTargets'.
func liveImageDigests(images []asset.Asset) []string {
	cutoff := time.Now().Add(-imageAssetLivenessWindow)
	seen := make(map[string]bool, len(images))
	out := make([]string, 0, len(images))
	for _, img := range images {
		if img.LastSeen.Before(cutoff) {
			continue
		}
		digest := img.Metadata["image_id"]
		if digest == "" || seen[digest] {
			continue
		}
		seen[digest] = true
		out = append(out, digest)
	}
	return out
}
