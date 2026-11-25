package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/app/driftanalysis"
	"github.com/vulngraph/vulngraph/internal/jobs"
)

// driftReader serves stored drift analyses from the serve pod. The analysis
// itself runs in the worker, so the serve pod has no model: the service is
// built read-only and Listing.Enabled is reported from the same switch the
// worker reads. A pod that cannot analyse still shows what was stored.
type driftReader struct {
	*driftanalysis.Service
	enabled bool
}

func (r driftReader) List(ctx context.Context, p driftanalysis.ListParams) (driftanalysis.Listing, error) {
	l, err := r.Service.List(ctx, p)
	if err != nil {
		return driftanalysis.Listing{}, fmt.Errorf("List: %w", err)
	}
	l.Enabled = r.enabled
	return l, nil
}

func newDriftReader(getenv func(string) string, pool *pgxpool.Pool) (driftReader, error) {
	on, err := jobs.SwitchFromEnv(getenv, jobs.DriftAnalysisEnabledEnv)
	if err != nil {
		return driftReader{}, fmt.Errorf("drift analysis: %w", err)
	}
	return driftReader{Service: driftanalysis.New(driftanalysis.NewPGRepo(pool), nil, nil), enabled: on}, nil
}
