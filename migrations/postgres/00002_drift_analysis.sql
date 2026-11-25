-- +goose Up
-- One row per batch of inventory changes on one connector, analysed by the
-- drift-analysis agent. The verdict is advisory: nothing here starts a scan.
-- A connector's first batch is a 'baseline' (its watermark only, never sent to
-- the model); the next batch starts at the latest window_end.
CREATE TABLE IF NOT EXISTS drift_batches (
    id             text        PRIMARY KEY,
    connector_id   uuid        NOT NULL REFERENCES connectors (id) ON DELETE CASCADE,
    window_start   timestamptz NOT NULL,
    window_end     timestamptz NOT NULL,
    asset_ids      text[]      NOT NULL DEFAULT '{}',
    truncated      boolean     NOT NULL DEFAULT false,
    status         text        NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'analysed', 'unknown', 'baseline')),
    attempts       integer     NOT NULL DEFAULT 0,
    verdict        jsonb,
    unknown_reason text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    analysed_at    timestamptz
);

CREATE INDEX IF NOT EXISTS drift_batches_status_created_idx ON drift_batches (status, created_at);
CREATE INDEX IF NOT EXISTS drift_batches_created_idx ON drift_batches (created_at DESC);
CREATE INDEX IF NOT EXISTS drift_batches_connector_window_idx ON drift_batches (connector_id, window_end DESC);

-- +goose Down
DROP TABLE IF EXISTS drift_batches;
