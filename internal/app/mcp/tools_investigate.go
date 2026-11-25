package mcp

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/vulngraph/vulngraph/internal/app/alertctx"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ResourceResolver resolves an identifier to the one live asset it names,
// with exact predicates and an explicit error when it is ambiguous or
// unresolvable. alertctx.Service implements it.
type ResourceResolver interface {
	ResolveOne(ctx context.Context, identifier string) (asset.Asset, alertctx.Match, error)
}

// WithResourceResolver registers investigate_resource. Resolution goes through
// alertctx's exact predicates and never a substring search: a LIMIT-1 ILIKE
// let any resource whose name CONTAINED the identifier stand in for the real
// one, and anyone who can name a resource chooses its name.
func (h *Handler) WithResourceResolver(r ResourceResolver, assets AssetReader, findings FindingLister) *Handler {
	h.register(tool{
		Name: "investigate_resource",
		Description: "Full investigation context for ONE resource. Accepts an asset ID, IP address, EC2 instance ID (i-xxx), " +
			"ARN, or hostname, resolved by exact match only: an identifier that matches several assets (or none) is an " +
			"error — use search_assets, then call again with the exact asset id. Returns: asset details, findings with " +
			"signal scores (KEV/EPSS/exploitable), blast radius, and an investigation summary. findings_known / " +
			"blast_radius_known false means NOT MEASURED, never 'none'. Use this first when you receive a GuardDuty " +
			"alert or any security alert.",
		InputSchema: objSchema(map[string]any{
			"identifier":       strProp("IP, instance ID, ARN, hostname, or internal asset ID"),
			"max_blast_radius": intProp("max blast radius nodes to return (default 20)"),
		}, "identifier"),
		// Resolution runs alertctx's unindexed attribute scan: same budget as
		// get_alert_context.
		limit: limitAlertContext,
		handler: func(ctx context.Context, args map[string]any) (any, error) {
			identifier, _ := args["identifier"].(string)
			if identifier == "" {
				return nil, fmt.Errorf("investigate_resource: %w: identifier is required", errInvalidParams)
			}
			a, m, err := r.ResolveOne(ctx, identifier)
			switch {
			case errors.Is(err, alertctx.ErrUnresolved), errors.Is(err, alertctx.ErrAmbiguous),
				errors.Is(err, alertctx.ErrEmptyIdentfier):
				return nil, fmt.Errorf("investigate_resource: %w: %w", errInvalidParams, err)
			case err != nil:
				return nil, fmt.Errorf("investigate_resource: %w", err)
			}
			return investigate(ctx, assets, findings, a, m, intArg(args, "max_blast_radius", 20)), nil
		},
	})
	return h
}

// investigate assembles the context for a resolved asset. A section whose
// read failed is reported known=false with no value: an empty finding list or
// a zero reach from a failed read would read as "nothing wrong here".
func investigate(ctx context.Context, assets AssetReader, findings FindingLister, a asset.Asset, m alertctx.Match, maxBR int) map[string]any {
	out := map[string]any{
		"asset":      a,
		"resolution": map[string]any{"match_type": m.MatchType, "confidence": m.Confidence},
	}

	assetFindings, findingsErr := assetFindings(ctx, findings, a)
	findingsPart := "findings unavailable"
	if findingsErr != nil {
		log.FromContext(ctx).Warn().Err(findingsErr).Str("asset_id", a.ID).Msg("mcp: investigate_resource findings unavailable")
		out["findings_known"], out["findings_reason"] = false, "the findings read failed"
	} else {
		var critCount, kevCount int
		for _, f := range assetFindings {
			if f.Severity == finding.SeverityCritical {
				critCount++
			}
			if f.KnownExploited {
				kevCount++
			}
		}
		out["findings"], out["findings_known"] = assetFindings, true
		findingsPart = fmt.Sprintf("%d findings (%d critical, %d KEV)", len(assetFindings), critCount, kevCount)
	}

	blastPart := "blast radius unavailable"
	br, err := assets.BlastRadius(ctx, a.ID, 3)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("asset_id", a.ID).Msg("mcp: investigate_resource blast radius unavailable")
		out["blast_radius_known"], out["blast_radius_reason"] = false, "the blast-radius walk failed"
	} else {
		reachable := reachableFrom(br, a.ID)
		brAssets := reachable
		if maxBR > 0 && len(brAssets) > maxBR {
			brAssets = brAssets[:maxBR]
		}
		out["blast_radius_known"] = true
		out["blast_radius_count"] = len(reachable)
		out["blast_radius_truncated"] = br.Truncated
		out["blast_radius_assets"] = brAssets
		out["blast_radius_edges"] = br.Edges
		atLeast := ""
		if br.Truncated {
			atLeast = "at least "
		}
		blastPart = fmt.Sprintf("blast radius reaches %s%d assets", atLeast, len(reachable))
	}

	out["investigation_summary"] = fmt.Sprintf("%s %s (risk score %d/100) — %s, %s",
		a.Type, a.Name, a.RiskScore, findingsPart, blastPart)
	return out
}

// assetFindings reads the asset's findings: keyed by asset ID, plus the
// verified name-keyed sources (nameKeyedSources) for IAM principals. Any read
// failing fails the whole list — a partial list would undercount.
func assetFindings(ctx context.Context, findings FindingLister, a asset.Asset) ([]finding.Finding, error) {
	byID, err := findings.List(ctx, finding.Filter{ResourceID: a.ID, SortByScore: true, Limit: 100})
	if err != nil {
		return nil, fmt.Errorf("by id: %w", err)
	}
	byName, err := nameKeyedFindings(ctx, findings, a, byID)
	if err != nil {
		return nil, fmt.Errorf("by name: %w", err)
	}
	all := append(byID, byName...)
	// The name-keyed rows are appended after the ID-keyed ones; a high-score
	// threat detection must not land behind lower-scoring findings.
	sort.SliceStable(all, func(i, j int) bool { return all[i].Score > all[j].Score })
	return all, nil
}

// reachableFrom is the blast radius without its seed: the walk returns the
// seed itself among its assets, and an asset is not part of its own blast
// radius.
func reachableFrom(br asset.BlastRadius, seedID string) []asset.Asset {
	out := make([]asset.Asset, 0, len(br.Assets))
	for _, a := range br.Assets {
		if a.ID != seedID {
			out = append(out, a)
		}
	}
	return out
}
