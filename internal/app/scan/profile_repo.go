package scan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// invalidTextRepresentation is Postgres's error for a non-UUID id: such an id
// cannot match a row.
const invalidTextRepresentation = "22P02"

// PGProfileRepo persists scan profiles and their per-asset scan findings using
// direct pgx/v5 pool calls (no sqlc — profile tables are managed outside the
// main sqlcgen query set).
type PGProfileRepo struct {
	pool *pgxpool.Pool
}

// NewPGProfileRepo constructs a PGProfileRepo backed by pool.
func NewPGProfileRepo(pool *pgxpool.Pool) *PGProfileRepo {
	return &PGProfileRepo{pool: pool}
}

// ─── ScanProfile ─────────────────────────────────────────────────────────────

// createProfileQ generates the id as a real uuid, not gen_random_uuid()::text:
// scan_profiles.id is a uuid column, and Postgres has no implicit assignment
// cast from text to uuid — casting the generated value to text (to match a
// COALESCE sibling elsewhere) makes every CreateProfile call fail with "column
// is of type uuid but expression is of type text". upsertScanFindingQ below
// carries the same constraint.
const createProfileQ = `
INSERT INTO scan_profiles (
    id, name, description, template_tags, template_strategy,
    target_query, scanner_type, schedule, enabled, drift_enabled, created_at, updated_at
) VALUES (
    gen_random_uuid(), $1, $2, $3, $4,
    $5, $6, $7, $8, $9, now(), now()
)
RETURNING id, name, description, template_tags, template_strategy,
          target_query, scanner_type, schedule, enabled, drift_enabled, created_at, updated_at`

func (r *PGProfileRepo) CreateProfile(
	ctx context.Context,
	name, description string,
	tags []string,
	enabled bool,
	targetQuery string,
	driftEnabled bool,
	schedule string,
	scannerType string,
	templateStrategy string,
) (ScanProfile, error) {
	if tags == nil {
		tags = []string{}
	}
	if scannerType == "" {
		scannerType = "nuclei"
	}
	if templateStrategy == "" {
		templateStrategy = string(StrategyAll)
	}
	row := r.pool.QueryRow(ctx, createProfileQ,
		name, description, tags, templateStrategy,
		targetQuery, scannerType, schedule, enabled, driftEnabled,
	)
	out, err := scanProfileRow(row)
	if err != nil {
		return ScanProfile{}, fmt.Errorf("CreateProfile: %w", err)
	}
	return out, nil
}

const getProfileQ = `
SELECT id, name, description, template_tags, template_strategy,
       target_query, scanner_type, schedule, enabled, drift_enabled, created_at, updated_at
FROM scan_profiles WHERE id = $1`

func (r *PGProfileRepo) GetProfile(ctx context.Context, id string) (ScanProfile, error) {
	row := r.pool.QueryRow(ctx, getProfileQ, id)
	out, err := scanProfileRow(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation) {
			return ScanProfile{}, ErrProfileNotFound
		}
		return ScanProfile{}, fmt.Errorf("GetProfile: %w", err)
	}
	return out, nil
}

const listProfilesQ = `
SELECT id, name, description, template_tags, template_strategy,
       target_query, scanner_type, schedule, enabled, drift_enabled, created_at, updated_at
FROM scan_profiles ORDER BY created_at DESC`

func (r *PGProfileRepo) ListProfiles(ctx context.Context) ([]ScanProfile, error) {
	rows, err := r.pool.Query(ctx, listProfilesQ)
	if err != nil {
		return nil, fmt.Errorf("ListProfiles: %w", err)
	}
	defer rows.Close()

	var out []ScanProfile
	for rows.Next() {
		p, err := scanProfileRow(rows)
		if err != nil {
			return nil, fmt.Errorf("ListProfiles: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListProfiles: %w", err)
	}
	return out, nil
}

const updateProfileQ = `
UPDATE scan_profiles
SET name = $2, description = $3, template_tags = $4, template_strategy = $5,
    enabled = $6, target_query = $7, drift_enabled = $8, schedule = $9,
    scanner_type = $10, updated_at = now()
WHERE id = $1
RETURNING id, name, description, template_tags, template_strategy,
          target_query, scanner_type, schedule, enabled, drift_enabled, created_at, updated_at`

func (r *PGProfileRepo) UpdateProfile(
	ctx context.Context,
	id, name, description string,
	tags []string,
	enabled bool,
	targetQuery string,
	driftEnabled bool,
	schedule string,
	scannerType string,
	templateStrategy string,
) (ScanProfile, error) {
	if tags == nil {
		tags = []string{}
	}
	if scannerType == "" {
		scannerType = "nuclei"
	}
	if templateStrategy == "" {
		templateStrategy = string(StrategyAll)
	}
	row := r.pool.QueryRow(ctx, updateProfileQ,
		id, name, description, tags, templateStrategy,
		enabled, targetQuery, driftEnabled, schedule, scannerType,
	)
	out, err := scanProfileRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ScanProfile{}, ErrProfileNotFound
		}
		return ScanProfile{}, fmt.Errorf("UpdateProfile: %w", err)
	}
	return out, nil
}

const deleteProfileQ = `DELETE FROM scan_profiles WHERE id = $1`

func (r *PGProfileRepo) DeleteProfile(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, deleteProfileQ, id)
	if err != nil {
		return fmt.Errorf("DeleteProfile: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrProfileNotFound
	}
	return nil
}

const createRunForProfileQ = `
INSERT INTO scan_runs (id, status, target_count, finding_count, template_tags,
                       template_count, target_urls, scanner_name, error, profile_id,
                       started_at)
VALUES (gen_random_uuid(), 'running', $1, 0, '{}', 0, '{}', 'nuclei', '', $2, now())
RETURNING id, status, target_count, finding_count, template_tags,
          template_count, target_urls, scanner_name, error, started_at, finished_at`

func (r *PGProfileRepo) CreateRunForProfile(ctx context.Context, profileID string, targetCount int) (Run, error) {
	run, err := scanRunForProfileRow(r.pool.QueryRow(ctx, createRunForProfileQ, targetCount, profileID))
	if err != nil {
		return Run{}, fmt.Errorf("CreateRunForProfile: %w", err)
	}
	return run, nil
}

// CreateRunForProfileAndEnqueue inserts the run row and calls enqueue with the
// still-open transaction, committing only if enqueue succeeds: the
// row and its follow-up job land together, or neither does, so a crash or a
// failed enqueue between the two cannot strand a run in `running`
// forever.
func (r *PGProfileRepo) CreateRunForProfileAndEnqueue(ctx context.Context, profileID string, targetCount int, enqueue func(ctx context.Context, tx pgx.Tx, runID string) error) (Run, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Run{}, fmt.Errorf("CreateRunForProfileAndEnqueue: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	run, err := scanRunForProfileRow(tx.QueryRow(ctx, createRunForProfileQ, targetCount, profileID))
	if err != nil {
		return Run{}, fmt.Errorf("CreateRunForProfileAndEnqueue: %w", err)
	}

	if err := enqueue(ctx, tx, run.ID); err != nil {
		return Run{}, fmt.Errorf("CreateRunForProfileAndEnqueue: enqueue: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Run{}, fmt.Errorf("CreateRunForProfileAndEnqueue: commit: %w", err)
	}
	return run, nil
}

func scanRunForProfileRow(row pgx.Row) (Run, error) {
	var run Run
	var finishedAt *time.Time
	err := row.Scan(
		&run.ID, &run.Status, &run.TargetCount, &run.FindingCount,
		&run.TemplateTags, &run.TemplateCount, &run.TargetURLs,
		&run.ScannerName, &run.Error, &run.StartedAt, &finishedAt,
	)
	if err != nil {
		return Run{}, err
	}
	run.FinishedAt = finishedAt
	return run, nil
}

// ─── ScanFinding ─────────────────────────────────────────────────────────────

const getScanFindingByAssetCheckQ = `
SELECT id, scan_run_id, finding_id, asset_id, check_id, title, severity,
       status, first_seen_at, last_seen_at, resolved_at
FROM scan_findings
WHERE asset_id = $1 AND check_id = $2
ORDER BY last_seen_at DESC LIMIT 1`

func (r *PGProfileRepo) GetScanFindingByAssetCheck(ctx context.Context, assetID, checkID string) (ScanFinding, error) {
	row := r.pool.QueryRow(ctx, getScanFindingByAssetCheckQ, assetID, checkID)
	out, err := scanFindingRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ScanFinding{}, ErrProfileNotFound
		}
		return ScanFinding{}, fmt.Errorf("GetScanFindingByAssetCheck: %w", err)
	}
	return out, nil
}

// upsertScanFindingQ: scan_findings.id is also uuid, not text — a caller-supplied
// ID (an existing finding being re-upserted, always a real uuid string read back
// from this same column) is cast explicitly so COALESCE's two branches agree in
// type; the auto-generated branch is a bare gen_random_uuid(), not ::text — see
// createProfileQ's comment above for why that cast is wrong.
const upsertScanFindingQ = `
INSERT INTO scan_findings (
    id, scan_run_id, finding_id, asset_id, check_id, title, severity,
    status, first_seen_at, last_seen_at, resolved_at
) VALUES (
    COALESCE(NULLIF($1, '')::uuid, gen_random_uuid()),
    $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)
ON CONFLICT (id) DO UPDATE
    SET scan_run_id  = EXCLUDED.scan_run_id,
        title        = EXCLUDED.title,
        severity     = EXCLUDED.severity,
        status       = EXCLUDED.status,
        last_seen_at = EXCLUDED.last_seen_at,
        resolved_at  = EXCLUDED.resolved_at`

func (r *PGProfileRepo) UpsertScanFinding(ctx context.Context, f ScanFinding) error {
	_, err := r.pool.Exec(ctx, upsertScanFindingQ,
		f.ID, f.ScanRunID, f.FindingID, f.AssetID, f.CheckID, f.Title, f.Severity,
		string(f.Status), f.FirstSeenAt, f.LastSeenAt, f.ResolvedAt,
	)
	if err != nil {
		return fmt.Errorf("UpsertScanFinding: %w", err)
	}
	return nil
}

// listOpenScanFindingsByRunQ returns confirmed findings that belong to the SAME
// profile as currentRunID but were recorded by an earlier run of it — the
// candidates for auto-resolution after a clean re-scan. Scoping to the current
// run's own profile (derived here, not passed by the caller) is essential:
// without it, a run of profile A auto-resolves profile B's confirmed findings,
// because B's (asset,check) pairs are never in A's "seen" set. A run with no
// profile (ad-hoc) has cur.profile_id IS NULL, so this returns nothing and
// resolves nothing across runs.
const listOpenScanFindingsByRunQ = `
SELECT sf.id, sf.scan_run_id, sf.finding_id, sf.asset_id, sf.check_id, sf.title,
       sf.severity, sf.status, sf.first_seen_at, sf.last_seen_at, sf.resolved_at
FROM scan_findings sf
JOIN scan_runs r   ON r.id = sf.scan_run_id
JOIN scan_runs cur ON cur.id = $1
WHERE sf.scan_run_id != $1
  AND sf.status = 'confirmed'
  AND cur.profile_id IS NOT NULL
  AND r.profile_id = cur.profile_id
ORDER BY sf.last_seen_at DESC`

func (r *PGProfileRepo) ListOpenScanFindingsByRun(ctx context.Context, currentRunID string) ([]ScanFinding, error) {
	rows, err := r.pool.Query(ctx, listOpenScanFindingsByRunQ, currentRunID)
	if err != nil {
		return nil, fmt.Errorf("ListOpenScanFindingsByRun: %w", err)
	}
	defer rows.Close()

	var out []ScanFinding
	for rows.Next() {
		f, err := scanFindingRow(rows)
		if err != nil {
			return nil, fmt.Errorf("ListOpenScanFindingsByRun: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListOpenScanFindingsByRun: %w", err)
	}
	return out, nil
}

const batchGetScanFindingsByAssetIDsQ = `
SELECT DISTINCT ON (asset_id, check_id)
    id, scan_run_id, finding_id, asset_id, check_id, title, severity,
    status, first_seen_at, last_seen_at, resolved_at
FROM scan_findings
WHERE asset_id = ANY($1)
ORDER BY asset_id, check_id, last_seen_at DESC`

func (r *PGProfileRepo) BatchGetScanFindingsByAssetIDs(ctx context.Context, assetIDs []string) ([]ScanFinding, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx, batchGetScanFindingsByAssetIDsQ, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("BatchGetScanFindingsByAssetIDs: %w", err)
	}
	defer rows.Close()

	var out []ScanFinding
	for rows.Next() {
		f, err := scanFindingRow(rows)
		if err != nil {
			return nil, fmt.Errorf("BatchGetScanFindingsByAssetIDs: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("BatchGetScanFindingsByAssetIDs: %w", err)
	}
	return out, nil
}

// ─── row scanners ────────────────────────────────────────────────────────────

// profileRowScanner is satisfied by both pgx.Row and pgx.Rows.
type profileRowScanner interface {
	Scan(dest ...any) error
}

func scanProfileRow(row profileRowScanner) (ScanProfile, error) {
	var p ScanProfile
	var strategy, targetQuery, scannerType string
	err := row.Scan(
		&p.ID, &p.Name, &p.Description, &p.TemplateTags, &strategy,
		&targetQuery, &scannerType, &p.Schedule, &p.Enabled, &p.DriftEnabled,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return ScanProfile{}, err
	}
	p.TemplateStrategy = TemplateStrategy(strategy)
	p.TargetQuery = targetQuery
	p.ScannerType = scannerType
	return p, nil
}

// ListDriftEnabledProfiles returns all enabled profiles that have drift scanning
// turned on — used by the sync worker to enqueue drift scans on asset changes.
// listDriftProfilesQ excludes any profile with a non-empty TargetQuery.
// ScanAssetWorker (the consumer of the jobs this drives) builds its scan
// target directly from the drift-changed asset it's handed — it has no
// Cypher resolver wired to check that asset against the profile's own scope,
// so a scoped profile firing here would run nuclei on every drift-changed
// external asset in the whole estate regardless of what the profile was
// actually scoped to (found immediately
// after this drift-trigger path went from dead to live). Excluding scoped
// profiles is the safe direction: this path was dead before, so no observed
// behavior regresses, and it removes the scope-violation risk entirely rather
// than firing broadly. An unscoped profile (empty TargetQuery) already means
// "all internet-exposed assets" (ResolveTargets' own doc), which one drift-
// changed external asset is always a member of.
const listDriftProfilesQ = `
SELECT id, name, description, template_tags, template_strategy,
       target_query, scanner_type, schedule, enabled, drift_enabled, created_at, updated_at
FROM scan_profiles
WHERE enabled = true AND drift_enabled = true AND target_query = ''`

func (r *PGProfileRepo) ListDriftEnabledProfiles(ctx context.Context) ([]ScanProfile, error) {
	rows, err := r.pool.Query(ctx, listDriftProfilesQ)
	if err != nil {
		return nil, fmt.Errorf("ListDriftEnabledProfiles: %w", err)
	}
	defer rows.Close()
	var out []ScanProfile
	for rows.Next() {
		p, err := scanProfileRow(rows)
		if err != nil {
			return nil, fmt.Errorf("ListDriftEnabledProfiles: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func scanFindingRow(row profileRowScanner) (ScanFinding, error) {
	var f ScanFinding
	var status string
	err := row.Scan(
		&f.ID, &f.ScanRunID, &f.FindingID, &f.AssetID, &f.CheckID,
		&f.Title, &f.Severity, &status,
		&f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt,
	)
	if err != nil {
		return ScanFinding{}, err
	}
	f.Status = ScanFindingStatus(status)
	return f, nil
}
