package jobs

import (
	"context"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
	"github.com/vulngraph/vulngraph/internal/checks"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// SuppressionCarrier copies a suppression from a superseded finding to the
// finding that replaced it. *suppress.Service implements it.
type SuppressionCarrier interface {
	CarryForward(ctx context.Context, toFindingID, fromFindingID string) (bool, error)
}

// suppressionCarrier keeps a nil *suppress.Service a nil interface, so the
// sync's nil check sees it instead of calling through a typed nil.
func suppressionCarrier(s *suppress.Service) SuppressionCarrier {
	if s == nil {
		return nil
	}
	return s
}

// carrySuppressions runs before the new findings reach enrichment: for every
// finding whose check superseded another on the same resource
// (checks.SupersededCheck), an unexpired suppression on the old finding is
// copied to the new one. Without it a check split resolves the suppressed
// finding and opens an unsuppressed one, so an accepted exception comes back
// at full severity. Best-effort: a failed carry is logged and retried next
// sweep (the new finding is re-emitted while it still violates).
func carrySuppressions(ctx context.Context, carrier SuppressionCarrier, found []finding.Finding) {
	if carrier == nil {
		return
	}
	for _, f := range found {
		old := checks.SupersededCheck(f.CheckID)
		if old == "" || f.ResourceID == "" {
			continue
		}
		if _, err := carrier.CarryForward(ctx, f.ID, dbutil.DeterministicID(old, f.ResourceID)); err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("finding_id", f.ID).Str("superseded_check", old).
				Msg("sync: carrying a suppression to its superseding finding failed (retried next sweep)")
		}
	}
}
