package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/app/driftanalysis"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/internal/jobs"
	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/internal/reason"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// driftAnalysisService builds the advisory drift analysis when
// DRIFT_ANALYSIS_ENABLED is on, else nil (no worker, no periodic, no rows). It
// spends LLM budget, so it is off by default; DRIFT_ANALYSIS_MODEL picks the
// model, empty meaning the provider's default.
func driftAnalysisService(ctx context.Context, getenv func(string) string, pool *pgxpool.Pool, client llm.Client,
	profiles driftProfiles, findings driftFindings, assets driftExposure) (*driftanalysis.Service, error) {
	on, err := jobs.SwitchFromEnv(getenv, jobs.DriftAnalysisEnabledEnv)
	if err != nil || !on {
		return nil, err
	}
	model := getenv("DRIFT_ANALYSIS_MODEL")
	svc := driftanalysis.New(
		driftanalysis.NewPGRepo(pool),
		reason.New(client, model),
		driftFacts{profiles: profiles, findings: findings, assets: assets},
		driftanalysis.WithModel(model),
	)
	log.FromContext(ctx).Info().Str("model", model).Msg("worker: drift analysis enabled (advisory; never starts a scan)")
	return svc, nil
}

type driftProfiles interface {
	ListProfiles(ctx context.Context) ([]scan.ScanProfile, error)
	ListDriftEnabledProfileIDs(ctx context.Context) ([]string, error)
}

type driftFindings interface {
	ByResourceIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
}

type driftExposure interface {
	IsExposedEdge(ctx context.Context, assetID string) (bool, error)
}

// driftFacts adapts the scan, finding and asset services to the facts the
// drift analyst is shown. Every method returns an error on any failed lookup,
// so the service marks the matching fact unknown instead of reading it as clean.
type driftFacts struct {
	profiles driftProfiles
	findings driftFindings
	assets   driftExposure
}

func (d driftFacts) Profiles(ctx context.Context) ([]driftanalysis.ProfileFact, []string, error) {
	all, err := d.profiles.ListProfiles(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("Profiles: %w", err)
	}
	auto, err := d.profiles.ListDriftEnabledProfileIDs(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("Profiles: %w", err)
	}
	var out []driftanalysis.ProfileFact
	for _, p := range all {
		if p.Enabled {
			out = append(out, driftanalysis.ProfileFact{ID: p.ID, Name: p.Name, TemplateTags: p.TemplateTags})
		}
	}
	return out, auto, nil
}

func (d driftFacts) Findings(ctx context.Context, assetIDs []string) (map[string]driftanalysis.AssetFact, error) {
	found, err := d.findings.ByResourceIDs(ctx, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("Findings: %w", err)
	}
	out := make(map[string]driftanalysis.AssetFact, len(assetIDs))
	for _, f := range found {
		if f.Resolved() {
			continue
		}
		a := out[f.ResourceID]
		a.AssetID = f.ResourceID
		a.OpenFindings++
		a.MaxScore = max(a.MaxScore, int(f.Score))
		out[f.ResourceID] = a
	}
	return out, nil
}

func (d driftFacts) Exposure(ctx context.Context, assetIDs []string) (map[string]bool, error) {
	out := make(map[string]bool, len(assetIDs))
	for _, id := range assetIDs {
		exposed, err := d.assets.IsExposedEdge(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("Exposure: %s: %w", id, err)
		}
		out[id] = exposed
	}
	return out, nil
}
