package asset

import (
	"context"
	"fmt"
	"time"
)

// VerifyDepartedAssets also recognizes authoritative cloud deletions after
// inventory retirement removed the asset row. Newer observations take precedence.
func (s *Service) VerifyDepartedAssets(ctx context.Context, ids []string) (map[string]bool, error) {
	out, err := s.repo.VerifyExpiredEphemeral(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("VerifyDepartedAssets: liveness: %w", err)
	}
	if out == nil {
		out = map[string]bool{}
	}
	return s.verifyDeletedAssets(ctx, ids, out)
}

// VerifyDeletedAssets distinguishes authoritative deletion from an uncollected
// identity. A successful observation at or after the proof permits reappearance.
// Read proofs in bounded batches; only proven IDs need observation hydration.
func (s *Service) VerifyDeletedAssets(ctx context.Context, ids []string) (map[string]bool, error) {
	return s.verifyDeletedAssets(ctx, ids, map[string]bool{})
}

func (s *Service) verifyDeletedAssets(ctx context.Context, ids []string, out map[string]bool) (map[string]bool, error) {
	if s.deletionProofs == nil {
		return out, nil
	}
	for start := 0; start < len(ids); start += 500 {
		chunk := ids[start:min(start+500, len(ids))]
		proofs, err := s.deletionProofs.AssetDeletions(ctx, chunk)
		if err != nil {
			return nil, fmt.Errorf("VerifyDeletedAssets: proofs: %w", err)
		}
		if len(proofs) == 0 {
			continue
		}
		candidates := make([]string, 0, len(proofs))
		for id := range proofs {
			candidates = append(candidates, id)
		}
		observed, err := s.repo.ByIDs(ctx, candidates)
		if err != nil {
			return nil, fmt.Errorf("VerifyDeletedAssets: observations: %w", err)
		}
		for _, a := range observed {
			if !observedBeforeDeletion(a.LastSeen, proofs[a.ID]) {
				delete(proofs, a.ID)
				delete(out, a.ID)
			}
		}
		for id := range proofs {
			out[id] = true
		}
	}
	return out, nil
}

// Whole seconds may have lost their fractional component before the precision
// migration. Match the conservative per-row predicate in the retirement repo.
func observedBeforeDeletion(observed, cutoff time.Time) bool {
	if observed.Nanosecond() == 0 {
		observed = observed.Add(time.Second - time.Nanosecond)
	}
	return observed.Before(cutoff)
}

func (s *Service) RetireAssets(ctx context.Context, deletions map[string]time.Time) ([]string, error) {
	ids, err := s.repo.RetireAssets(ctx, deletions)
	if err != nil {
		return nil, fmt.Errorf("RetireAssets: %w", err)
	}
	return ids, nil
}
