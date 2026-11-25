-- +goose Up
-- One package-inventory claim per (source, asset), submitted by a customer's own
-- scanning agent through an inventory-scoped API key (bring-your-own-agent).
-- source is byoa:<api_key_id>:<scanner name>, so one key cannot replace another
-- key's claim. The packages themselves are not stored here: they enter the graph
-- as runs_package edges. This row is the provenance and the server's verdict on
-- how far the claim may be believed (inventory_known / cve_matchable_known are
-- decided by the server, never by the agent).
-- Deleting the key deletes its claims: a revoked agent's inventory reads as
-- unknown, never as clean.
CREATE TABLE IF NOT EXISTS package_inventories (
    source              text        NOT NULL,
    asset_id            text        NOT NULL,
    api_key_id          uuid        NOT NULL REFERENCES api_keys (id) ON DELETE CASCADE,
    scanner_name        text        NOT NULL,
    scanner_version     text        NOT NULL,
    os_id               text        NOT NULL DEFAULT '',
    os_version_id       text        NOT NULL DEFAULT '',
    os_name             text        NOT NULL DEFAULT '',
    ecosystem           text        NOT NULL DEFAULT '',
    observed_at         timestamptz NOT NULL,
    received_at         timestamptz NOT NULL DEFAULT now(),
    complete            boolean     NOT NULL DEFAULT false,
    package_count       integer     NOT NULL DEFAULT 0,
    covered             jsonb       NOT NULL DEFAULT '[]',
    inventory_known     boolean     NOT NULL DEFAULT false,
    cve_matchable_known boolean     NOT NULL DEFAULT false,
    gap                 text        NOT NULL DEFAULT '',
    PRIMARY KEY (source, asset_id)
);

CREATE INDEX IF NOT EXISTS package_inventories_asset_idx ON package_inventories (asset_id);
CREATE INDEX IF NOT EXISTS package_inventories_key_idx ON package_inventories (api_key_id);

-- +goose Down
DROP TABLE IF EXISTS package_inventories;
