-- +goose Up
CREATE TABLE IF NOT EXISTS enrichment_sweep_progress (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    cursor_value text NOT NULL DEFAULT '',
    pass_before timestamptz,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    CHECK (cursor_value = '' OR pass_before IS NOT NULL)
);
INSERT INTO enrichment_sweep_progress (id) VALUES (true) ON CONFLICT (id) DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS enrichment_sweep_progress;
