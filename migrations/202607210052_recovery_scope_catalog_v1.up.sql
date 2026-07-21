-- V41: encrypted recovery-scope catalog and pre-enrollment provider handoff.
-- The identity service stores only signed metadata and opaque ciphertext.  It
-- never receives the catalog plaintext, membership receipts, or scope leaves.

-- Catalog preparations retain their linked enrollment challenge so terminal
-- catalog status remains queryable.  Exclude those rows before the bounded
-- selection: a referenced oldest challenge must not block eligible retention.
CREATE OR REPLACE FUNCTION identity.prune_expired_device_enrollment_challenges(
    target_cutoff_ms bigint,
    maximum_rows integer DEFAULT 256
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
AS $$
DECLARE
    removed bigint := 0;
BEGIN
    IF target_cutoff_ms NOT BETWEEN -62135596800000 AND 253402301699999 THEN
        RAISE EXCEPTION 'device enrollment retention cutoff is invalid'
            USING ERRCODE = '22003';
    END IF;
    IF maximum_rows NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'device enrollment retention batch is invalid'
            USING ERRCODE = '22023';
    END IF;

    PERFORM set_config('identity.device_enrollment_retention_prune', 'on', true);
    WITH expired_challenges AS MATERIALIZED (
        SELECT challenge_id
          FROM identity.device_enrollment_challenges
         WHERE retention_until_ms <= target_cutoff_ms
           AND NOT EXISTS (
               SELECT 1
                 FROM identity.recovery_scope_catalog_preparations
                WHERE request_id = identity.device_enrollment_challenges.challenge_id
           )
         ORDER BY retention_until_ms, challenge_id
         LIMIT maximum_rows
         FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM identity.device_enrollment_challenges AS challenge
         USING expired_challenges AS expired
         WHERE challenge.challenge_id = expired.challenge_id
         RETURNING 1
    )
    SELECT count(*) INTO removed FROM deleted;
    RETURN removed;
END
$$;

CREATE TABLE identity.recovery_scope_catalogs (
    identity_id text NOT NULL,
    generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    previous_head_digest bytea CHECK (previous_head_digest IS NULL OR octet_length(previous_head_digest)=32),
    leaf_count bigint NOT NULL CHECK (leaf_count BETWEEN 1 AND 65535),
    merkle_root bytea NOT NULL CHECK (octet_length(merkle_root)=32),
    ciphertext_digest bytea NOT NULL CHECK (octet_length(ciphertext_digest)=32),
    observed_head_sequence bigint NOT NULL CHECK (observed_head_sequence BETWEEN 0 AND 9007199254740991),
    observed_head_hash bytea NOT NULL CHECK (octet_length(observed_head_hash)=32),
    authority_device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(authority_device_id)),
    authority_signing_key bytea NOT NULL CHECK (octet_length(authority_signing_key)=32),
    issued_at_ms bigint NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9007199254740991),
    expires_at_ms bigint NOT NULL CHECK (expires_at_ms>issued_at_ms AND expires_at_ms<=9007199254740991),
    signature bytea NOT NULL CHECK (octet_length(signature)=64),
    head_bytes bytea NOT NULL CHECK (octet_length(head_bytes) BETWEEN 1 AND 16384),
    head_digest bytea NOT NULL CHECK (octet_length(head_digest)=32),
    encrypted_catalog bytea NOT NULL CHECK (octet_length(encrypted_catalog) BETWEEN 1 AND 1048576),
    upload_digest bytea NOT NULL CHECK (octet_length(upload_digest)=32),
    idempotency_key_hash bytea NOT NULL CHECK (octet_length(idempotency_key_hash)=32),
    created_at_ms bigint NOT NULL,
    PRIMARY KEY(identity_id,generation),
    UNIQUE(identity_id,head_digest),
    UNIQUE(identity_id,idempotency_key_hash),
    FOREIGN KEY(identity_id) REFERENCES identity.log_heads(identity_id)
);

CREATE TABLE identity.recovery_scope_catalog_preparations (
    request_id uuid PRIMARY KEY CHECK (messaging.is_uuid_v7(request_id)),
    identity_id text NOT NULL,
    candidate_device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(candidate_device_id)),
    candidate_signing_key bytea NOT NULL CHECK (octet_length(candidate_signing_key)=32),
    candidate_recipient_key bytea NOT NULL CHECK (octet_length(candidate_recipient_key)=32),
    observed_head_sequence bigint NOT NULL CHECK (observed_head_sequence BETWEEN 0 AND 9007199254740991),
    observed_head_hash bytea NOT NULL CHECK (octet_length(observed_head_hash)=32),
    candidate_nonce bytea NOT NULL CHECK (octet_length(candidate_nonce)=32),
    issued_at_ms bigint NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9007199254740991),
    expires_at_ms bigint NOT NULL CHECK (expires_at_ms>issued_at_ms AND expires_at_ms<=9007199254740991),
    response_capability_hash bytea NOT NULL CHECK (octet_length(response_capability_hash)=32),
    enrollment_capability_hash bytea NOT NULL CHECK (octet_length(enrollment_capability_hash)=32),
    candidate_signature bytea NOT NULL CHECK (octet_length(candidate_signature)=64),
    preparation_bytes bytea NOT NULL CHECK (octet_length(preparation_bytes) BETWEEN 1 AND 16384),
    preparation_digest bytea NOT NULL CHECK (octet_length(preparation_digest)=32),
    catalog_generation bigint NOT NULL CHECK (catalog_generation BETWEEN 1 AND 9007199254740991),
    catalog_head_digest bytea NOT NULL CHECK (octet_length(catalog_head_digest)=32),
    authority_device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(authority_device_id)),
    authority_signing_key bytea NOT NULL CHECK (octet_length(authority_signing_key)=32),
    idempotency_key_hash bytea NOT NULL CHECK (octet_length(idempotency_key_hash)=32),
    created_at_ms bigint NOT NULL,
    provider_response_bytes bytea CHECK (provider_response_bytes IS NULL OR octet_length(provider_response_bytes) BETWEEN 1 AND 1065984),
    provider_response_digest bytea CHECK (provider_response_digest IS NULL OR octet_length(provider_response_digest)=32),
    provider_device_id uuid CHECK (provider_device_id IS NULL OR messaging.is_uuid_v7(provider_device_id)),
    provider_signing_key bytea CHECK (provider_signing_key IS NULL OR octet_length(provider_signing_key)=32),
    provider_ciphertext_digest bytea CHECK (provider_ciphertext_digest IS NULL OR octet_length(provider_ciphertext_digest)=32),
    provider_expires_at_ms bigint,
    provider_idempotency_key_hash bytea CHECK (provider_idempotency_key_hash IS NULL OR octet_length(provider_idempotency_key_hash)=32),
    provider_recorded_at_ms bigint,
    CONSTRAINT recovery_scope_catalog_preparation_provider_shape CHECK (
        (provider_response_bytes IS NULL AND provider_response_digest IS NULL
         AND provider_device_id IS NULL AND provider_signing_key IS NULL
         AND provider_ciphertext_digest IS NULL AND provider_expires_at_ms IS NULL
         AND provider_idempotency_key_hash IS NULL AND provider_recorded_at_ms IS NULL)
        OR
        (provider_response_bytes IS NOT NULL AND provider_response_digest IS NOT NULL
         AND provider_device_id IS NOT NULL AND provider_signing_key IS NOT NULL
         AND provider_ciphertext_digest IS NOT NULL AND provider_expires_at_ms IS NOT NULL
         AND provider_idempotency_key_hash IS NOT NULL AND provider_recorded_at_ms IS NOT NULL
         AND provider_expires_at_ms>provider_recorded_at_ms
         AND provider_expires_at_ms<=expires_at_ms)
    ),
    UNIQUE(identity_id,idempotency_key_hash),
    FOREIGN KEY(identity_id,catalog_generation)
        REFERENCES identity.recovery_scope_catalogs(identity_id,generation),
    FOREIGN KEY(request_id) REFERENCES identity.device_enrollment_challenges(challenge_id)
);

CREATE FUNCTION identity.enforce_recovery_scope_catalog_preparation_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.request_id IS DISTINCT FROM NEW.request_id
       OR OLD.identity_id IS DISTINCT FROM NEW.identity_id
       OR OLD.candidate_device_id IS DISTINCT FROM NEW.candidate_device_id
       OR OLD.candidate_signing_key IS DISTINCT FROM NEW.candidate_signing_key
       OR OLD.candidate_recipient_key IS DISTINCT FROM NEW.candidate_recipient_key
       OR OLD.observed_head_sequence IS DISTINCT FROM NEW.observed_head_sequence
       OR OLD.observed_head_hash IS DISTINCT FROM NEW.observed_head_hash
       OR OLD.candidate_nonce IS DISTINCT FROM NEW.candidate_nonce
       OR OLD.issued_at_ms IS DISTINCT FROM NEW.issued_at_ms
       OR OLD.expires_at_ms IS DISTINCT FROM NEW.expires_at_ms
       OR OLD.response_capability_hash IS DISTINCT FROM NEW.response_capability_hash
       OR OLD.enrollment_capability_hash IS DISTINCT FROM NEW.enrollment_capability_hash
       OR OLD.candidate_signature IS DISTINCT FROM NEW.candidate_signature
       OR OLD.preparation_bytes IS DISTINCT FROM NEW.preparation_bytes
       OR OLD.preparation_digest IS DISTINCT FROM NEW.preparation_digest
       OR OLD.catalog_generation IS DISTINCT FROM NEW.catalog_generation
       OR OLD.catalog_head_digest IS DISTINCT FROM NEW.catalog_head_digest
       OR OLD.authority_device_id IS DISTINCT FROM NEW.authority_device_id
       OR OLD.authority_signing_key IS DISTINCT FROM NEW.authority_signing_key
       OR OLD.idempotency_key_hash IS DISTINCT FROM NEW.idempotency_key_hash
       OR OLD.created_at_ms IS DISTINCT FROM NEW.created_at_ms THEN
        RAISE EXCEPTION 'recovery scope catalog preparation binding is immutable'
            USING ERRCODE='23514';
    END IF;
    IF OLD.provider_response_bytes IS NOT NULL
       AND (OLD.provider_response_bytes IS DISTINCT FROM NEW.provider_response_bytes
         OR OLD.provider_response_digest IS DISTINCT FROM NEW.provider_response_digest
         OR OLD.provider_device_id IS DISTINCT FROM NEW.provider_device_id
         OR OLD.provider_signing_key IS DISTINCT FROM NEW.provider_signing_key
         OR OLD.provider_ciphertext_digest IS DISTINCT FROM NEW.provider_ciphertext_digest
         OR OLD.provider_expires_at_ms IS DISTINCT FROM NEW.provider_expires_at_ms
         OR OLD.provider_idempotency_key_hash IS DISTINCT FROM NEW.provider_idempotency_key_hash
         OR OLD.provider_recorded_at_ms IS DISTINCT FROM NEW.provider_recorded_at_ms) THEN
        RAISE EXCEPTION 'recovery scope catalog provider response is immutable'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER identity_recovery_scope_catalog_preparation_transition
BEFORE UPDATE ON identity.recovery_scope_catalog_preparations
FOR EACH ROW EXECUTE FUNCTION identity.enforce_recovery_scope_catalog_preparation_transition();
REVOKE ALL ON FUNCTION identity.enforce_recovery_scope_catalog_preparation_transition()
    FROM PUBLIC;

ALTER TABLE identity.recovery_scope_catalogs ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.recovery_scope_catalogs FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.recovery_scope_catalogs
    USING (identity.identity_runtime_authorized())
    WITH CHECK (identity.identity_runtime_authorized());

ALTER TABLE identity.recovery_scope_catalog_preparations ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.recovery_scope_catalog_preparations FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.recovery_scope_catalog_preparations
    USING (identity.identity_runtime_authorized())
    WITH CHECK (identity.identity_runtime_authorized());

DO $grants$ BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA messaging TO dtx_identity_runtime;
        GRANT EXECUTE ON FUNCTION messaging.is_uuid_v7(uuid) TO dtx_identity_runtime;
        GRANT SELECT,INSERT ON identity.recovery_scope_catalogs TO dtx_identity_runtime;
        GRANT SELECT,INSERT ON identity.recovery_scope_catalog_preparations TO dtx_identity_runtime;
        GRANT UPDATE(
            provider_response_bytes,provider_response_digest,provider_device_id,
            provider_signing_key,provider_ciphertext_digest,provider_expires_at_ms,
            provider_idempotency_key_hash,provider_recorded_at_ms
        ) ON identity.recovery_scope_catalog_preparations TO dtx_identity_runtime;
    END IF;
END $grants$;
