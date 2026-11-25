-- +goose Up
-- admin_since is when the user's role last became admin. The executor's
-- two-person account-age floor counts from the later of created_at and
-- admin_since, so an old account promoted today cannot approve today.
-- NULL means unknown: every non-admin, and every admin that existed before
-- this migration (their promotion time was never recorded). For an admin the
-- floor then falls back to created_at, so an upgrade locks no one out.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS admin_since timestamptz;

-- +goose Down
ALTER TABLE users
    DROP COLUMN IF EXISTS admin_since;
