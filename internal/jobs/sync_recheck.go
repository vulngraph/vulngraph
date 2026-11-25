// Package jobs — the daily re-evaluation of time-dependent checks.
//
// The sync worker re-checks only assets whose content changed, which is right
// for a predicate over collector output and wrong for one that compares a
// fixed date to today: a Debian 11 VM fleet that never changes would never get
// its end-of-life finding, because nothing about the assets moves on the day
// the date passes. So once per UTC day per connector, the checks that read the
// clock (checks.Check.TimeDependent) run over every applicable asset the sweep
// collected — no ClickHouse read, the sweep already holds the assets in memory.
package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
)

// recheckRecordBatch bounds one RecordObserved call of the re-check, so a large
// estate's end-of-life findings are written in pages rather than one insert.
const recheckRecordBatch = 1000

// findingRecorder is the slice of finding.Service the re-check writes through.
type findingRecorder interface {
	RecordObserved(ctx context.Context, findings []finding.Finding) error
}

// recheckTimeDependent evaluates the time-dependent checks in td over every
// asset they apply to, minus skip (assets this sweep already ran the full
// registry on), records what fires, and reconciles the rest. It returns how
// many findings it recorded. An error means the day's re-check did not
// complete and the caller must not mark it done, so the next sweep retries.
//
// The reconcile is scoped to td's check IDs: these assets did not run the rest
// of the registry this sweep, so an open finding from any other check on them
// says nothing and must not be closed as fixed.
func recheckTimeDependent(ctx context.Context, rec findingRecorder, life findingLifecycler, td *checks.Registry, assets []asset.Asset, skip map[string]bool, partial bool, now time.Time) (int, error) {
	if td.Len() == 0 {
		return 0, nil
	}
	tdChecks := td.All()
	var targets []asset.Asset
	for _, a := range assets {
		if skip[a.ID] {
			continue
		}
		for _, c := range tdChecks {
			if c.AppliesTo(a) {
				targets = append(targets, a)
				break
			}
		}
	}
	if len(targets) == 0 {
		return 0, nil
	}
	found := td.Run(targets, now)
	for start := 0; start < len(found); start += recheckRecordBatch {
		if err := rec.RecordObserved(ctx, found[start:min(start+recheckRecordBatch, len(found))]); err != nil {
			return 0, fmt.Errorf("recheckTimeDependent: record: %w", err)
		}
	}
	enqueueEnrichIfCapacity(ctx, found)
	ids := make(map[string]bool, len(tdChecks))
	for _, c := range tdChecks {
		ids[c.ID] = true
	}
	reconcileResolvedFindings(ctx, checkScopedLifecycler{findingLifecycler: life, checkIDs: ids}, td, targets, found, partial)
	return len(found), nil
}

// checkScopedLifecycler narrows the reconcile's stored-finding read to the
// checks that actually ran, so their silence is the only silence it reads.
type checkScopedLifecycler struct {
	findingLifecycler
	checkIDs map[string]bool
}

func (s checkScopedLifecycler) ByResourceIDs(ctx context.Context, ids []string) ([]finding.Finding, error) {
	stored, err := s.findingLifecycler.ByResourceIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("ByResourceIDs: %w", err)
	}
	out := stored[:0:0]
	for _, f := range stored {
		if s.checkIDs[f.CheckID] {
			out = append(out, f)
		}
	}
	return out, nil
}
