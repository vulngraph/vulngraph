package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// orphanSlack is how far before an intent's creation a snapshot may start and
// still be matched to it; clocks differ between this pod and the cloud.
const orphanSlack = 5 * time.Minute

// DiskScanSweepWorker deletes snapshots Vulngraph created and did not remove:
// the ones a crashed job left, found by their tag in the cloud whatever the
// database says, and the ones the registry lists past their delete-after time.
//
// It deletes only through the connector's own opt-in (engine.Authorize), and
// the snapshotter re-reads a snapshot's live tags before deleting it. A
// connector whose mode is no longer create_snapshots cannot be swept: its
// leftovers wait until the mode is set again.
type DiskScanSweepWorker struct {
	river.WorkerDefaults[DiskScanSweepArgs]
	svc    diskScanService
	clouds DiskScanClouds
	limits DiskScanLimits
	now    func() time.Time
}

func (w *DiskScanSweepWorker) Timeout(*river.Job[DiskScanSweepArgs]) time.Duration {
	return diskScanSweepTimeout
}

func (w *DiskScanSweepWorker) clock() time.Time {
	if w.now != nil {
		return w.now().UTC()
	}
	return time.Now().UTC()
}

// sweeper is one connector's snapshotter and the tagged snapshots it listed.
type sweeper struct {
	sn     engine.Snapshotter
	optIn  engine.OptIn
	tagged []engine.Snapshot
}

func (w *DiskScanSweepWorker) Work(ctx context.Context, _ *river.Job[DiskScanSweepArgs]) error {
	conns, err := w.svc.EnabledConnectors(ctx)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	var errs []error
	sweepers := map[string]*sweeper{}
	deleted := 0
	for _, c := range conns {
		if c.Mode != diskscan.DiskScanModeCreateSnapshots {
			continue
		}
		sw, err := w.sweeperFor(ctx, c.ConnectorID)
		if err != nil {
			errs = append(errs, fmt.Errorf("Work: %s: %w", c.ConnectorID, err))
			continue
		}
		sweepers[c.ConnectorID] = sw
		n, err := w.sweepTagged(ctx, sw)
		deleted += n
		if err != nil {
			errs = append(errs, fmt.Errorf("Work: %s: %w", c.ConnectorID, err))
		}
	}
	n, err := w.sweepOrphans(ctx, sweepers)
	deleted += n
	if err != nil {
		errs = append(errs, fmt.Errorf("Work: orphans: %w", err))
	}
	log.FromContext(ctx).Info().Int("deleted", deleted).Msg("disk scan sweep complete")
	return errors.Join(errs...)
}

// sweeperFor builds the connector's snapshotter and lists its tagged snapshots.
func (w *DiskScanSweepWorker) sweeperFor(ctx context.Context, connectorID string) (*sweeper, error) {
	grant, err := w.svc.Grant(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("sweeperFor: %w", err)
	}
	access, err := w.clouds.Resolve(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("sweeperFor: %w", err)
	}
	grant.DiskScanRole, grant.OtherRoles = access.Role, access.OtherRoles
	optIn, err := engine.Authorize(grant)
	if err != nil {
		return nil, fmt.Errorf("sweeperFor: %w", err)
	}
	sn, err := access.Cloud.Snapshotter(optIn)
	if err != nil {
		return nil, fmt.Errorf("sweeperFor: %w", err)
	}
	tagged, err := sn.ListTagged(ctx, optIn)
	if err != nil {
		return nil, fmt.Errorf("sweeperFor: list tagged: %w", err)
	}
	return &sweeper{sn: sn, optIn: optIn, tagged: tagged}, nil
}

// sweepTagged deletes the tagged snapshots older than the TTL.
func (w *DiskScanSweepWorker) sweepTagged(ctx context.Context, sw *sweeper) (int, error) {
	cutoff := w.clock().Add(-w.limits.SnapshotTTL)
	var errs []error
	n := 0
	for _, snap := range sw.tagged {
		if !snap.Ephemeral || snap.CreatedAt.IsZero() || !snap.CreatedAt.Before(cutoff) {
			continue
		}
		if err := sw.sn.DeleteTagged(ctx, sw.optIn, snap); err != nil {
			errs = append(errs, fmt.Errorf("sweepTagged: delete %s: %w", snap.ID, err))
			continue
		}
		n++
		if err := w.svc.MarkDeletedBySnapshot(ctx, snap.Provider, snap.ID); err != nil {
			errs = append(errs, fmt.Errorf("sweepTagged: mark %s: %w", snap.ID, err))
		}
	}
	return n, errors.Join(errs...)
}

// sweepOrphans acts on registry rows past their delete-after time. A row with a
// snapshot id deletes that snapshot. A row without one means a create may have
// happened and gone unrecorded: it is matched to a tagged snapshot of its
// volume, and closed only once the tag listing has shown nothing is left.
func (w *DiskScanSweepWorker) sweepOrphans(ctx context.Context, sweepers map[string]*sweeper) (int, error) {
	orphans, err := w.svc.ListOrphans(ctx)
	if err != nil {
		return 0, fmt.Errorf("sweepOrphans: %w", err)
	}
	var errs []error
	n := 0
	for _, in := range orphans {
		sw, ok := sweepers[in.ConnectorID]
		if !ok {
			log.FromContext(ctx).Warn().Str("connector_id", in.ConnectorID).Str("snapshot", in.SnapshotID).
				Msg("disk scan sweep: a snapshot is past its time but its connector cannot be swept (mode is not create_snapshots)")
			continue
		}
		snaps := []engine.Snapshot{{ID: in.SnapshotID, Provider: in.Provider, Region: in.Region, VolumeID: in.VolumeRef}}
		if in.SnapshotID == "" {
			snaps = matchTagged(sw.tagged, in)
		}
		failed := false
		for _, snap := range snaps {
			if err := sw.sn.DeleteTagged(ctx, sw.optIn, snap); err != nil {
				errs = append(errs, fmt.Errorf("sweepOrphans: delete %s: %w", snap.ID, err))
				failed = true
				continue
			}
			n++
		}
		if failed {
			continue
		}
		if err := w.svc.MarkDeleted(ctx, in.ID); err != nil {
			errs = append(errs, fmt.Errorf("sweepOrphans: mark %s: %w", in.ID, err))
		}
	}
	return n, errors.Join(errs...)
}

// matchTagged returns the tagged snapshots of the intent's volume created from
// the intent's start on.
func matchTagged(tagged []engine.Snapshot, in diskscan.SnapshotIntent) []engine.Snapshot {
	var out []engine.Snapshot
	for _, s := range tagged {
		if s.Ephemeral && s.VolumeID == in.VolumeRef && !s.CreatedAt.Before(in.CreatedAt.Add(-orphanSlack)) {
			out = append(out, s)
		}
	}
	return out
}
