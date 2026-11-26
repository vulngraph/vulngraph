-- +goose Up
-- Preserve history, but make old active-scan schedules and unfinished work inert.
UPDATE scan_profiles SET enabled = false, schedule = '', drift_enabled = false;
UPDATE scan_runs SET status = 'cancelled', finished_at = now(),
    error = 'Active external scanning has been removed'
WHERE status = 'running';
-- River may not exist yet on a fresh install: its migrations run separately.
-- +goose StatementBegin
DO $$
BEGIN
    IF to_regclass('river_job') IS NOT NULL THEN
        UPDATE river_job SET state = 'cancelled', finalized_at = now()
        WHERE kind IN ('scan', 'scan_profile', 'scan_asset', 'run_scheduled_profiles')
          -- Our migrations run before River upgrades its enum. Compare text
          -- so an older enum without 'pending' does not abort the upgrade.
          AND state::text IN ('available', 'scheduled', 'retryable', 'running', 'pending');
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Intentionally do not reactivate old scanning or replay cancelled jobs.
SELECT 1;
