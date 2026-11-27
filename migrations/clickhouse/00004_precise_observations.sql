-- +goose Up
-- last_seen is not a ReplacingMergeTree version column, so it can be converted
-- in place. Keep the TTL at second precision and wait for all existing parts.
ALTER TABLE assets MODIFY TTL toDateTime(last_seen) + INTERVAL 180 DAY SETTINGS materialize_ttl_after_modify = 0;
ALTER TABLE assets MODIFY COLUMN last_seen DateTime64(9) SETTINGS mutations_sync = 2;

-- +goose Down
-- Downgrading loses fractional observations; retirement treats whole seconds
-- conservatively even after a subsequent upgrade.
ALTER TABLE assets MODIFY COLUMN last_seen DateTime SETTINGS mutations_sync = 2;
ALTER TABLE assets MODIFY TTL last_seen + INTERVAL 180 DAY SETTINGS materialize_ttl_after_modify = 0;
