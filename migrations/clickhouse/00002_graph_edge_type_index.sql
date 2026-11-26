-- +goose Up
-- The primary key starts with src_id. A refresh filtering only by edge_type
-- otherwise reads package membership parts even for an empty bulk tier.
-- A bounded set per granule skips unrelated types without duplicating topology.
ALTER TABLE graph_edges ADD INDEX IF NOT EXISTS idx_edge_type edge_type TYPE set(128) GRANULARITY 1;
ALTER TABLE graph_edges MATERIALIZE INDEX idx_edge_type SETTINGS mutations_sync = 1;

-- +goose Down
ALTER TABLE graph_edges DROP INDEX IF EXISTS idx_edge_type;
