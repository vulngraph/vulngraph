-- +goose Up
ALTER TABLE connectors ADD COLUMN deletion_observed_at timestamptz;
CREATE TABLE connector_deletion_candidates (
    connector_id uuid NOT NULL,
    asset_id text NOT NULL,
    first_missing_at timestamptz NOT NULL,
    last_missing_at timestamptz NOT NULL,
    PRIMARY KEY (connector_id, asset_id),
    FOREIGN KEY (connector_id, asset_id)
        REFERENCES connector_asset_hashes (connector_id, asset_id) ON DELETE CASCADE,
    CHECK (last_missing_at >= first_missing_at)
);
CREATE INDEX connector_deletion_candidates_age_idx
    ON connector_deletion_candidates (connector_id, first_missing_at, asset_id);

-- +goose Down
DROP TABLE connector_deletion_candidates;
ALTER TABLE connectors DROP COLUMN deletion_observed_at;
