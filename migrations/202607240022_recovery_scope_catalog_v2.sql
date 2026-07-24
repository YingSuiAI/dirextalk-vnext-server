-- V44: retain the complete signed Catalog V2 authority coordinates.
-- This is a fresh-only epoch, so the additive columns are still required to
-- make the durable projection bind authority device, key-id, and key.
ALTER TABLE identity.recovery_scope_catalogs
    ADD COLUMN authority_key_id uuid
        NOT NULL
        CHECK (messaging.is_uuid_v7(authority_key_id));

ALTER TABLE identity.recovery_scope_catalog_preparations
    ADD COLUMN authority_key_id uuid
        NOT NULL
        CHECK (messaging.is_uuid_v7(authority_key_id));

CREATE FUNCTION identity.enforce_recovery_scope_catalog_authority_key_id_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.authority_key_id IS DISTINCT FROM NEW.authority_key_id THEN
        RAISE EXCEPTION 'recovery catalog authority key-id is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_recovery_scope_catalog_authority_key_id_immutable
BEFORE UPDATE ON identity.recovery_scope_catalogs
FOR EACH ROW EXECUTE FUNCTION identity.enforce_recovery_scope_catalog_authority_key_id_immutable();

CREATE TRIGGER identity_recovery_scope_catalog_preparation_authority_key_id_immutable
BEFORE UPDATE ON identity.recovery_scope_catalog_preparations
FOR EACH ROW EXECUTE FUNCTION identity.enforce_recovery_scope_catalog_authority_key_id_immutable();

REVOKE ALL ON FUNCTION identity.enforce_recovery_scope_catalog_authority_key_id_immutable()
    FROM PUBLIC;
