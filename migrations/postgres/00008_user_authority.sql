-- +goose Up
ALTER TABLE users ADD COLUMN authority_version bigint NOT NULL DEFAULT 1 CHECK (authority_version > 0);
-- Historical role tenure is unknown. Existing active admins start the cooling
-- period at migration time, rather than inheriting their account creation date.
UPDATE users SET admin_since = CASE WHEN role = 'admin' AND disabled_at IS NULL THEN now() ELSE NULL END;

-- +goose StatementBegin
CREATE FUNCTION track_user_authority() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.authority_version := 1;
        NEW.admin_since := CASE WHEN NEW.role = 'admin' AND NEW.disabled_at IS NULL THEN clock_timestamp() ELSE NULL END;
        RETURN NEW;
    END IF;
    IF NEW.role IS DISTINCT FROM OLD.role OR NEW.disabled_at IS DISTINCT FROM OLD.disabled_at
       OR NEW.password_hash IS DISTINCT FROM OLD.password_hash OR NEW.totp_secret IS DISTINCT FROM OLD.totp_secret
       OR NEW.oidc_issuer IS DISTINCT FROM OLD.oidc_issuer OR NEW.oidc_subject IS DISTINCT FROM OLD.oidc_subject THEN
        NEW.authority_version := OLD.authority_version + 1;
    END IF;
    IF NEW.role = 'admin' AND NEW.disabled_at IS NULL THEN
        IF OLD.role <> 'admin' OR OLD.disabled_at IS NOT NULL THEN
            NEW.admin_since := clock_timestamp();
        ELSE
            NEW.admin_since := OLD.admin_since;
        END IF;
    ELSE
        NEW.admin_since := NULL;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER users_authority BEFORE INSERT OR UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION track_user_authority();

-- +goose Down
DROP TRIGGER users_authority ON users;
DROP FUNCTION track_user_authority();
ALTER TABLE users DROP COLUMN authority_version;
