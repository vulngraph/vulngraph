package scan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

const defaultListLimit = 50

type PGRepo struct {
	q *sqlcgen.Queries
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{q: sqlcgen.New(pool)} }

func (r *PGRepo) CreateRun(ctx context.Context, targetCount int) (Run, error) {
	row, err := r.q.CreateScanRun(ctx, int32(targetCount))
	if err != nil {
		return Run{}, fmt.Errorf("CreateRun: %w", err)
	}
	return toDomain(row), nil
}

// FailStaleRuns fails every run stuck in 'running' since before cutoff and
// returns the reaped ids — reconciling rows a dead worker never finished.
func (r *PGRepo) FailStaleRuns(ctx context.Context, cutoff time.Time) ([]string, error) {
	ids, err := r.q.FailStaleScanRuns(ctx, cutoff)
	if err != nil {
		return nil, fmt.Errorf("FailStaleRuns: %w", err)
	}
	return ids, nil
}

func (r *PGRepo) FinishRun(ctx context.Context, id string, status Status, findingCount int, scanErr string, tags []string, templateCount int, targetURLs []string, scannerName string) error {
	if tags == nil {
		tags = []string{}
	}
	if targetURLs == nil {
		targetURLs = []string{}
	}
	if scannerName == "" {
		scannerName = "nuclei"
	}
	err := r.q.FinishScanRun(ctx, sqlcgen.FinishScanRunParams{
		ID:            id,
		Status:        string(status),
		FindingCount:  int32(findingCount),
		Error:         scanErr,
		TemplateTags:  tags,
		TemplateCount: int32(templateCount),
		TargetUrls:    targetURLs,
		ScannerName:   scannerName,
	})
	if err != nil {
		return fmt.Errorf("FinishRun: %w", err)
	}
	return nil
}

func (r *PGRepo) GetRun(ctx context.Context, id string) (Run, error) {
	row, err := r.q.GetScanRun(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Run{}, ErrNotFound
		}
		return Run{}, fmt.Errorf("GetRun: %w", err)
	}
	return toDomain(row), nil
}

func (r *PGRepo) ListRuns(ctx context.Context, limit int) ([]Run, error) {
	if limit <= 0 || limit > defaultListLimit {
		limit = defaultListLimit
	}
	rows, err := r.q.ListScanRuns(ctx, int32(limit))
	if err != nil {
		return nil, fmt.Errorf("ListRuns: %w", err)
	}
	out := make([]Run, len(rows))
	for i, row := range rows {
		out[i] = toDomain(row)
	}
	return out, nil
}

func (r *PGRepo) CancelRun(ctx context.Context, id string) error {
	if err := r.q.CancelScanRun(ctx, id); err != nil {
		return fmt.Errorf("CancelRun: %w", err)
	}
	return nil
}

func toDomain(row sqlcgen.ScanRun) Run {
	run := Run{
		ID:            row.ID,
		Status:        Status(row.Status),
		TargetCount:   int(row.TargetCount),
		TargetURLs:    row.TargetUrls,
		FindingCount:  int(row.FindingCount),
		TemplateTags:  row.TemplateTags,
		TemplateCount: int(row.TemplateCount),
		ScannerName:   row.ScannerName,
		Error:         row.Error,
		StartedAt:     row.StartedAt,
	}
	if row.FinishedAt.Valid {
		t := row.FinishedAt.Time
		run.FinishedAt = &t
	}
	return run
}
