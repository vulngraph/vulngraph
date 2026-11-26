-- +goose Up
ALTER TABLE asset_deletions ADD COLUMN retired_at timestamptz;
CREATE INDEX asset_deletions_pending_retirement_idx
    ON asset_deletions (deleted_at, asset_id) WHERE retired_at IS NULL;

-- +goose Down
DROP INDEX asset_deletions_pending_retirement_idx;
ALTER TABLE asset_deletions DROP COLUMN retired_at;
