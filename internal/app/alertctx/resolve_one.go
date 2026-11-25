package alertctx

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// ResolveOne resolves an identifier to the one live asset it names, through
// the same exact predicates as Context. It is for callers that go on to treat
// the result as THE resource (MCP investigate_resource), so it never guesses:
//
//   - an exact asset-id match wins outright (ids are unique);
//   - otherwise exactly one match is required — two assets sharing a name or
//     IP is ErrAmbiguous, since a resource anyone can name could otherwise
//     stand in for the real one;
//   - a failed or cut-off lookup is ErrLookupFailed, because the candidate it
//     missed is the one that would have made the answer ambiguous.
func (s *Service) ResolveOne(ctx context.Context, identifier string) (asset.Asset, Match, error) {
	p := planFor(identifier)
	if len(p.lookups) == 0 {
		return asset.Asset{}, Match{}, ErrEmptyIdentfier
	}
	res, assets, capped := s.resolve(ctx, []plan{p})
	m, err := singleMatch(res[0], capped)
	if err != nil {
		return asset.Asset{}, Match{}, err
	}
	return assets[m.AssetID], m, nil
}

// singleMatch picks the one asset a resolution names, or says why it cannot.
func singleMatch(r Resolution, capped bool) (Match, error) {
	switch r.Status {
	case StatusLookupFailed:
		return Match{}, fmt.Errorf("%w: %s", ErrLookupFailed, r.Reason)
	case StatusUnresolved:
		if capped {
			return Match{}, fmt.Errorf("%w: the candidate scan was cut off", ErrLookupFailed)
		}
		return Match{}, ErrUnresolved
	}
	top := r.Matches[0] // sorted by confidence, highest first
	if top.Confidence == ConfExact {
		return top, nil
	}
	switch {
	case r.Reason != "":
		return Match{}, fmt.Errorf("%w: %s", ErrLookupFailed, r.Reason)
	case capped:
		return Match{}, fmt.Errorf("%w: the candidate scan was cut off", ErrLookupFailed)
	case len(r.Matches) > 1 || r.MoreMatches:
		return Match{}, fmt.Errorf("%w: %d or more live assets match", ErrAmbiguous, len(r.Matches))
	}
	return top, nil
}
