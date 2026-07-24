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
-- V42 immutable candidate Request V4 admission. Raw capabilities and
-- idempotency keys are represented only by domain-separated digests.
CREATE TABLE identity.history_recovery_requests (
    request_id uuid PRIMARY KEY CHECK (messaging.is_uuid_v7(request_id)),
    identity_id text NOT NULL REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
    candidate_device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(candidate_device_id)),
    candidate_signing_key bytea NOT NULL CHECK (octet_length(candidate_signing_key)=32),
    candidate_recipient_key bytea NOT NULL CHECK (octet_length(candidate_recipient_key)=32),
    pre_head_sequence bigint NOT NULL CHECK (pre_head_sequence BETWEEN 0 AND 9007199254740990),
    pre_head_hash bytea NOT NULL CHECK (octet_length(pre_head_hash)=32),
    post_head_sequence bigint NOT NULL CHECK (post_head_sequence=pre_head_sequence+1),
    post_head_hash bytea NOT NULL CHECK (octet_length(post_head_hash)=32),
    device_add_bytes bytea NOT NULL CHECK (octet_length(device_add_bytes) BETWEEN 1 AND 533),
    device_add_digest bytea NOT NULL CHECK (octet_length(device_add_digest)=32),
    preparation_bytes bytea NOT NULL CHECK (octet_length(preparation_bytes) BETWEEN 1 AND 532),
    preparation_digest bytea NOT NULL CHECK (octet_length(preparation_digest)=32),
    manifest_bytes bytea NOT NULL CHECK (octet_length(manifest_bytes) BETWEEN 1 AND 35477),
    manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest)=32),
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL CHECK (expires_at_ms>issued_at_ms),
    response_capability_digest bytea NOT NULL CHECK (octet_length(response_capability_digest)=32),
    idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest)=32),
    candidate_signature bytea NOT NULL CHECK (octet_length(candidate_signature)=64),
    request_bytes bytea NOT NULL CHECK (octet_length(request_bytes) BETWEEN 1 AND 37114),
    request_digest bytea NOT NULL UNIQUE CHECK (octet_length(request_digest)=32),
    receipt_bytes bytea NOT NULL CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 256),
    accepted_at_ms bigint NOT NULL,
    UNIQUE(identity_id,idempotency_digest)
);
ALTER TABLE identity.history_recovery_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.history_recovery_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.history_recovery_requests
    USING (identity.identity_runtime_authorized())
    WITH CHECK (identity.identity_runtime_authorized());
DO $grants$ BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        GRANT SELECT,INSERT ON identity.history_recovery_requests TO dtx_identity_runtime;
    END IF;
END $grants$;
CREATE FUNCTION identity.enforce_history_recovery_request_v4_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'history recovery request is immutable' USING ERRCODE='23514';
END
$$;
CREATE TRIGGER identity_history_recovery_request_v4_immutable
BEFORE UPDATE OR DELETE ON identity.history_recovery_requests
FOR EACH ROW EXECUTE FUNCTION identity.enforce_history_recovery_request_v4_immutable();

-- V43 opaque push is a wake hint only.  Mailbox Pull/ACK and account read
-- cursors remain authoritative; this relation never contains a provider body.
CREATE TABLE messaging.opaque_push_registrations (
    registration_id uuid PRIMARY KEY CHECK (messaging.is_uuid_v7(registration_id)),
    identity_id text NOT NULL REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
    device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(device_id)),
    provider text NOT NULL CHECK (provider='fcm'),
    state text NOT NULL CHECK (state IN ('active','suspended','revoked')),
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    -- Bound ciphertext framing only; repository code enforces plaintext FCM token 1..4096.
    token_ciphertext bytea NOT NULL CHECK (octet_length(token_ciphertext) BETWEEN 1 AND 16384),
    token_nonce bytea NOT NULL CHECK (octet_length(token_nonce) BETWEEN 12 AND 64),
    encrypted_dek bytea NOT NULL CHECK (octet_length(encrypted_dek) BETWEEN 1 AND 16384),
    kms_key_version text NOT NULL CHECK (octet_length(kms_key_version) BETWEEN 1 AND 256),
    encryption_context bytea NOT NULL CHECK (octet_length(encryption_context) BETWEEN 1 AND 4096),
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    revoked_at_ms bigint,
    UNIQUE(device_id,provider),
    CHECK (updated_at_ms>=created_at_ms),
    CHECK ((state='revoked') = (revoked_at_ms IS NOT NULL))
);

CREATE TABLE messaging.opaque_push_idempotency_claims (
    device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(device_id)),
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 16),
    path text NOT NULL CHECK (octet_length(path) BETWEEN 1 AND 256),
    idempotency_key bytea NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
    if_match_revision bigint NOT NULL CHECK (if_match_revision BETWEEN 0 AND 9007199254740991),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    receipt_bytes bytea NOT NULL CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    created_at_ms bigint NOT NULL,
    PRIMARY KEY(device_id,idempotency_key)
);

CREATE TABLE messaging.opaque_push_deliveries (
    delivery_id uuid PRIMARY KEY CHECK (messaging.is_uuid_v7(delivery_id)),
    registration_id uuid NOT NULL REFERENCES messaging.opaque_push_registrations(registration_id) ON DELETE RESTRICT,
    registration_revision bigint NOT NULL CHECK (registration_revision BETWEEN 1 AND 9007199254740991),
    mailbox_id uuid NOT NULL,
    envelope_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','claimed','delivered','permanent_failure','expired','revoked')),
    claim_token uuid CHECK (claim_token IS NULL OR messaging.is_uuid_v7(claim_token)),
    claim_expires_at_ms bigint,
    retry_at_ms bigint,
    retry_count integer NOT NULL DEFAULT 0 CHECK (retry_count BETWEEN 0 AND 100),
    error_class text CHECK (error_class IS NULL OR error_class IN ('transient','invalid_token','provider_rejected')),
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    terminal_at_ms bigint,
    UNIQUE(registration_id,registration_revision,mailbox_id,envelope_id),
    FOREIGN KEY(mailbox_id,envelope_id) REFERENCES messaging.mailbox_envelopes(mailbox_id,envelope_id) ON DELETE RESTRICT,
    CHECK (expires_at_ms=created_at_ms+60000),
    CHECK ((state='claimed') = (claim_token IS NOT NULL AND claim_expires_at_ms IS NOT NULL)),
    CHECK ((state IN ('delivered','permanent_failure','expired','revoked')) = (terminal_at_ms IS NOT NULL))
);
CREATE INDEX opaque_push_deliveries_claim_idx ON messaging.opaque_push_deliveries(state,retry_at_ms,expires_at_ms,created_at_ms);
CREATE INDEX opaque_push_deliveries_terminal_idx ON messaging.opaque_push_deliveries(terminal_at_ms) WHERE terminal_at_ms IS NOT NULL;

ALTER TABLE messaging.opaque_push_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.opaque_push_registrations FORCE ROW LEVEL SECURITY;
ALTER TABLE messaging.opaque_push_idempotency_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.opaque_push_idempotency_claims FORCE ROW LEVEL SECURITY;
ALTER TABLE messaging.opaque_push_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.opaque_push_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY opaque_push_registration_owner_only ON messaging.opaque_push_registrations USING (messaging.mailbox_owner_authorized()) WITH CHECK (messaging.mailbox_owner_authorized());
CREATE POLICY opaque_push_claim_owner_only ON messaging.opaque_push_idempotency_claims USING (messaging.mailbox_owner_authorized()) WITH CHECK (messaging.mailbox_owner_authorized());
CREATE POLICY opaque_push_delivery_owner_only ON messaging.opaque_push_deliveries USING (messaging.mailbox_owner_authorized()) WITH CHECK (messaging.mailbox_owner_authorized());

-- These are deliberately read-only and named separately from the identity
-- domain policies: FORCE RLS makes the narrow auth-reader grant effective.
CREATE POLICY opaque_push_identity_auth_session_select ON identity.device_sessions
    FOR SELECT USING (COALESCE(pg_has_role(session_user,to_regrole('dtx_push_identity_auth_runtime'),'MEMBER'),false));
CREATE POLICY opaque_push_identity_auth_head_select ON identity.log_heads
    FOR SELECT USING (COALESCE(pg_has_role(session_user,to_regrole('dtx_push_identity_auth_runtime'),'MEMBER'),false));
CREATE POLICY opaque_push_identity_auth_entry_select ON identity.log_entries
    FOR SELECT USING (COALESCE(pg_has_role(session_user,to_regrole('dtx_push_identity_auth_runtime'),'MEMBER'),false));

-- The receipt is a protocol value, not caller supplied data.  Keep this
-- helper private so every stored replay byte sequence is canonical.
CREATE FUNCTION messaging.opaque_push_cbor_uint(value bigint) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
BEGIN
    IF value < 0 THEN RAISE EXCEPTION 'negative CBOR unsigned integer' USING ERRCODE='22023'; END IF;
    IF value < 24 THEN RETURN set_byte(decode('00','hex'),0,value::integer); END IF;
    IF value <= 255 THEN RETURN decode('18','hex') || set_byte(decode('00','hex'),0,value::integer); END IF;
    IF value <= 65535 THEN RETURN decode('19','hex') || decode(lpad(to_hex(value),4,'0'),'hex'); END IF;
    IF value <= 4294967295 THEN RETURN decode('1a','hex') || decode(lpad(to_hex(value),8,'0'),'hex'); END IF;
    RETURN decode('1b','hex') || decode(lpad(to_hex(value),16,'0'),'hex');
END $$;

CREATE FUNCTION messaging.opaque_push_canonical_receipt(revision bigint, receipt_state text) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE state_bytes bytea;
BEGIN
    IF revision < 1 OR receipt_state NOT IN ('active','revoked') THEN RAISE EXCEPTION 'opaque push receipt rejected' USING ERRCODE='22023'; END IF;
    state_bytes := convert_to(receipt_state,'UTF8');
    RETURN decode('a40101026366636d03','hex') || messaging.opaque_push_cbor_uint(revision)
        || decode('04','hex') || set_byte(decode('60','hex'),0,96 + octet_length(state_bytes)) || state_bytes;
END $$;

CREATE FUNCTION messaging.opaque_push_prepare_mutation(
    authenticated_session_id uuid, presented_secret_hash bytea, request_method text,
    request_path text, request_key bytea, expected_revision bigint, request_digest bytea,
    candidate_registration_id uuid
) RETURNS TABLE(outcome text, identity_id text, device_id uuid, registration_id uuid, next_revision bigint, receipt_bytes bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging,identity AS $$
DECLARE session_row identity.device_sessions%ROWTYPE; prior messaging.opaque_push_idempotency_claims%ROWTYPE; registration messaging.opaque_push_registrations%ROWTYPE;
BEGIN
    IF NOT COALESCE(pg_has_role(session_user,to_regrole('dtx_push_registration_runtime'),'MEMBER'),false)
       OR octet_length(presented_secret_hash) <> 32 OR octet_length(request_digest) <> 32
       OR octet_length(request_key) NOT BETWEEN 1 AND 128 OR request_method NOT IN ('PUT','DELETE')
       OR expected_revision NOT BETWEEN 0 AND 9007199254740991
       OR (request_method='PUT' AND (candidate_registration_id IS NULL OR NOT messaging.is_uuid_v7(candidate_registration_id))) THEN
        RAISE EXCEPTION 'opaque push prepare rejected' USING ERRCODE='42501';
    END IF;
    -- Authentication intentionally precedes the claim lookup: an unknown or
    -- wrong credential cannot be used to probe replay state.
    SELECT * INTO session_row FROM identity.device_sessions
      WHERE session_id=authenticated_session_id AND session_secret_hash=presented_secret_hash;
    IF NOT FOUND THEN RAISE EXCEPTION 'opaque push session rejected' USING ERRCODE='42501'; END IF;
    SELECT c.* INTO prior FROM messaging.opaque_push_idempotency_claims AS c
      WHERE c.device_id=session_row.device_id AND c.idempotency_key=request_key;
    IF FOUND THEN
        IF prior.method IS DISTINCT FROM request_method OR prior.path IS DISTINCT FROM request_path
           OR prior.if_match_revision IS DISTINCT FROM expected_revision OR prior.request_digest IS DISTINCT FROM request_digest THEN
            RAISE EXCEPTION 'opaque push idempotency binding conflict' USING ERRCODE='23505';
        END IF;
        RETURN QUERY SELECT 'replay', session_row.identity_id, session_row.device_id, NULL::uuid, NULL::bigint, prior.receipt_bytes;
        RETURN;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('opaque_push:provider:'||session_row.device_id::text||':fcm',0));
    SELECT r.* INTO registration FROM messaging.opaque_push_registrations AS r
      WHERE r.device_id=session_row.device_id AND r.provider='fcm' AND r.state IN ('active','suspended') FOR UPDATE;
    RETURN QUERY SELECT 'execute', session_row.identity_id, session_row.device_id,
        COALESCE(registration.registration_id,candidate_registration_id),
        COALESCE(registration.revision + 1, 1), NULL::bytea;
END $$;

CREATE FUNCTION messaging.opaque_push_commit_put(
    authenticated_session_id uuid, presented_secret_hash bytea, requested_registration_id uuid,
    request_method text, request_path text, request_key bytea, expected_revision bigint, request_digest bytea,
    expected_protocol_major smallint, expected_protocol_minor smallint,
    expected_minimum_reader_major smallint, expected_minimum_reader_minor smallint,
    expected_identity_state text, expected_head_sequence bigint, expected_head_hash bytea,
    requested_token_ciphertext bytea, requested_token_nonce bytea, requested_encrypted_dek bytea,
    requested_kms_key_version text, requested_context bytea
) RETURNS bytea LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging,identity AS $$
DECLARE session_row identity.device_sessions%ROWTYPE; head identity.log_heads%ROWTYPE; prior messaging.opaque_push_idempotency_claims%ROWTYPE; authoritative_registration_id uuid; next_revision bigint; now_ms bigint; result bytea;
BEGIN
    SELECT * INTO session_row FROM identity.device_sessions WHERE session_id=authenticated_session_id AND session_secret_hash=presented_secret_hash;
    IF NOT FOUND OR octet_length(presented_secret_hash)<>32 THEN RAISE EXCEPTION 'opaque push session rejected' USING ERRCODE='42501'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('opaque_push:idempotency:'||session_row.device_id::text||':'||encode(request_key,'hex'),0));
    SELECT * INTO prior FROM messaging.opaque_push_idempotency_claims WHERE device_id=session_row.device_id AND idempotency_key=request_key;
    IF FOUND THEN
      IF prior.method IS DISTINCT FROM request_method OR prior.path IS DISTINCT FROM request_path OR prior.if_match_revision IS DISTINCT FROM expected_revision OR prior.request_digest IS DISTINCT FROM request_digest THEN RAISE EXCEPTION 'opaque push idempotency binding conflict' USING ERRCODE='23505'; END IF;
      RETURN prior.receipt_bytes;
    END IF;
    IF request_method<>'PUT' OR NOT messaging.is_uuid_v7(requested_registration_id)
       OR octet_length(request_digest)<>32 OR octet_length(requested_token_nonce)<>24
       OR octet_length(requested_token_ciphertext) NOT BETWEEN 17 AND 4112 OR octet_length(requested_encrypted_dek) NOT BETWEEN 1 AND 4096
       OR octet_length(requested_kms_key_version) NOT BETWEEN 1 AND 256 OR octet_length(requested_context) NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION 'opaque push commit rejected' USING ERRCODE='22023'; END IF;
    SELECT * INTO session_row FROM identity.device_sessions WHERE session_id=authenticated_session_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'opaque push session rejected' USING ERRCODE='42501'; END IF;
    SELECT * INTO head FROM identity.log_heads WHERE identity_id=session_row.identity_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'opaque push identity fence lost' USING ERRCODE='40001'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('opaque_push:provider:'||session_row.device_id::text||':fcm',0));
    SELECT r.registration_id,r.revision+1 INTO authoritative_registration_id,next_revision FROM messaging.opaque_push_registrations AS r WHERE r.device_id=session_row.device_id AND r.provider='fcm' AND r.state IN ('active','suspended') FOR UPDATE;
    now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
    IF session_row.session_secret_hash IS DISTINCT FROM presented_secret_hash OR session_row.expires_at_ms<=now_ms THEN RAISE EXCEPTION 'opaque push session rejected' USING ERRCODE='42501'; END IF;
    IF head.protocol_major IS DISTINCT FROM expected_protocol_major OR head.protocol_minor IS DISTINCT FROM expected_protocol_minor OR head.minimum_reader_major IS DISTINCT FROM expected_minimum_reader_major OR head.minimum_reader_minor IS DISTINCT FROM expected_minimum_reader_minor OR head.state IS DISTINCT FROM expected_identity_state OR head.state<>'active' OR head.head_sequence IS DISTINCT FROM expected_head_sequence OR head.head_hash IS DISTINCT FROM expected_head_hash THEN RAISE EXCEPTION 'opaque push identity fence lost' USING ERRCODE='40001'; END IF;
    IF NOT FOUND THEN
        IF EXISTS(SELECT 1 FROM messaging.opaque_push_registrations WHERE device_id=session_row.device_id AND provider='fcm' AND state='revoked') OR expected_revision<>0 THEN RAISE EXCEPTION 'opaque push revision conflict' USING ERRCODE='40001'; END IF;
        next_revision:=1;
    ELSIF requested_registration_id IS DISTINCT FROM authoritative_registration_id OR expected_revision IS DISTINCT FROM next_revision-1 THEN
        RAISE EXCEPTION 'opaque push registration context conflict' USING ERRCODE='40001';
    END IF;
    result:=messaging.opaque_push_canonical_receipt(next_revision,'active');
    INSERT INTO messaging.opaque_push_registrations(registration_id,identity_id,device_id,provider,state,revision,token_ciphertext,token_nonce,encrypted_dek,kms_key_version,encryption_context,created_at_ms,updated_at_ms) VALUES(requested_registration_id,session_row.identity_id,session_row.device_id,'fcm','active',next_revision,requested_token_ciphertext,requested_token_nonce,requested_encrypted_dek,requested_kms_key_version,requested_context,now_ms,now_ms) ON CONFLICT(device_id,provider) DO UPDATE SET state='active',revision=EXCLUDED.revision,token_ciphertext=EXCLUDED.token_ciphertext,token_nonce=EXCLUDED.token_nonce,encrypted_dek=EXCLUDED.encrypted_dek,kms_key_version=EXCLUDED.kms_key_version,encryption_context=EXCLUDED.encryption_context,updated_at_ms=EXCLUDED.updated_at_ms,revoked_at_ms=NULL;
    INSERT INTO messaging.opaque_push_idempotency_claims VALUES(session_row.device_id,request_method,request_path,request_key,expected_revision,request_digest,result,now_ms);
    RETURN result;
END $$;

CREATE FUNCTION messaging.opaque_push_commit_delete(
    authenticated_session_id uuid, presented_secret_hash bytea, request_method text, request_path text,
    request_key bytea, expected_revision bigint, request_digest bytea,
    expected_protocol_major smallint, expected_protocol_minor smallint,
    expected_minimum_reader_major smallint, expected_minimum_reader_minor smallint,
    expected_identity_state text, expected_head_sequence bigint, expected_head_hash bytea
) RETURNS bytea LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging,identity AS $$
DECLARE session_row identity.device_sessions%ROWTYPE; head identity.log_heads%ROWTYPE; prior messaging.opaque_push_idempotency_claims%ROWTYPE; registration messaging.opaque_push_registrations%ROWTYPE; now_ms bigint; result bytea;
BEGIN
    SELECT * INTO session_row FROM identity.device_sessions WHERE session_id=authenticated_session_id AND session_secret_hash=presented_secret_hash;
    IF NOT FOUND OR octet_length(presented_secret_hash)<>32 THEN RAISE EXCEPTION 'opaque push session rejected' USING ERRCODE='42501'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('opaque_push:idempotency:'||session_row.device_id::text||':'||encode(request_key,'hex'),0));
    SELECT * INTO prior FROM messaging.opaque_push_idempotency_claims WHERE device_id=session_row.device_id AND idempotency_key=request_key;
    IF FOUND THEN IF prior.method IS DISTINCT FROM request_method OR prior.path IS DISTINCT FROM request_path OR prior.if_match_revision IS DISTINCT FROM expected_revision OR prior.request_digest IS DISTINCT FROM request_digest THEN RAISE EXCEPTION 'opaque push idempotency binding conflict' USING ERRCODE='23505'; END IF; RETURN prior.receipt_bytes; END IF;
    IF request_method<>'DELETE' OR octet_length(request_digest)<>32 THEN RAISE EXCEPTION 'opaque push commit rejected' USING ERRCODE='22023'; END IF;
    SELECT * INTO session_row FROM identity.device_sessions WHERE session_id=authenticated_session_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'opaque push session rejected' USING ERRCODE='42501'; END IF;
    SELECT * INTO head FROM identity.log_heads WHERE identity_id=session_row.identity_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'opaque push identity fence lost' USING ERRCODE='40001'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('opaque_push:provider:'||session_row.device_id::text||':fcm',0));
    SELECT * INTO registration FROM messaging.opaque_push_registrations WHERE device_id=session_row.device_id AND provider='fcm' AND state IN ('active','suspended') FOR UPDATE;
    now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
    IF session_row.session_secret_hash IS DISTINCT FROM presented_secret_hash OR session_row.expires_at_ms<=now_ms THEN RAISE EXCEPTION 'opaque push session rejected' USING ERRCODE='42501'; END IF;
    IF head.protocol_major IS DISTINCT FROM expected_protocol_major OR head.protocol_minor IS DISTINCT FROM expected_protocol_minor OR head.minimum_reader_major IS DISTINCT FROM expected_minimum_reader_major OR head.minimum_reader_minor IS DISTINCT FROM expected_minimum_reader_minor OR head.state IS DISTINCT FROM expected_identity_state OR head.state<>'active' OR head.head_sequence IS DISTINCT FROM expected_head_sequence OR head.head_hash IS DISTINCT FROM expected_head_hash THEN RAISE EXCEPTION 'opaque push identity fence lost' USING ERRCODE='40001'; END IF;
    IF NOT FOUND OR registration.revision<>expected_revision THEN RAISE EXCEPTION 'opaque push revision conflict' USING ERRCODE='40001'; END IF;
    result:=messaging.opaque_push_canonical_receipt(registration.revision+1,'revoked');
    UPDATE messaging.opaque_push_registrations SET state='revoked',revision=revision+1,updated_at_ms=now_ms,revoked_at_ms=now_ms WHERE registration_id=registration.registration_id;
    UPDATE messaging.opaque_push_deliveries SET state='revoked',claim_token=NULL,claim_expires_at_ms=NULL,terminal_at_ms=now_ms WHERE registration_id=registration.registration_id AND registration_revision=registration.revision AND state IN ('pending','claimed');
    INSERT INTO messaging.opaque_push_idempotency_claims VALUES(session_row.device_id,request_method,request_path,request_key,expected_revision,request_digest,result,now_ms);
    RETURN result;
END $$;

CREATE FUNCTION messaging.enqueue_opaque_push_intent(requested_delivery_id uuid, requested_mailbox_id uuid, requested_envelope_id uuid)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging AS $$
DECLARE inserted bigint; selected_device uuid; now_ms bigint;
BEGIN
 IF NOT COALESCE(pg_has_role(session_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),false) OR NOT messaging.is_uuid_v7(requested_delivery_id) THEN RAISE EXCEPTION 'opaque push intent rejected' USING ERRCODE='42501'; END IF;
 SELECT owner_device_id INTO selected_device FROM messaging.mailboxes WHERE mailbox_id=requested_mailbox_id;
 IF selected_device IS NULL THEN RETURN 0; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('opaque_push:provider:'||selected_device::text||':fcm',0));
 now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
 INSERT INTO messaging.opaque_push_deliveries(delivery_id,registration_id,registration_revision,mailbox_id,envelope_id,created_at_ms,expires_at_ms)
 SELECT requested_delivery_id,r.registration_id,r.revision,requested_mailbox_id,requested_envelope_id,now_ms,now_ms+60000 FROM messaging.opaque_push_registrations r JOIN messaging.mailboxes m ON m.owner_device_id=r.device_id WHERE m.mailbox_id=requested_mailbox_id AND m.owner_device_id=selected_device AND r.provider='fcm' AND r.state='active'
 ON CONFLICT(registration_id,registration_revision,mailbox_id,envelope_id) DO NOTHING;
 GET DIAGNOSTICS inserted=ROW_COUNT; RETURN inserted;
END $$;

CREATE FUNCTION messaging.claim_opaque_push_deliveries(requested_claim uuid, maximum_rows integer)
RETURNS TABLE(claim_token uuid,delivery_id uuid,registration_id uuid,identity_id text,device_id uuid,provider text,pinned_revision bigint,mailbox_id uuid,envelope_id uuid,token_ciphertext bytea,token_nonce bytea,encrypted_dek bytea,kms_key_version text,encryption_context bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging AS $$
DECLARE now_ms bigint;
BEGIN
 now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
 IF NOT COALESCE(pg_has_role(session_user,to_regrole('dtx_push_broker_runtime'),'MEMBER'),false) OR NOT messaging.is_uuid_v7(requested_claim) OR maximum_rows NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'opaque push claim rejected' USING ERRCODE='42501'; END IF;
 UPDATE messaging.opaque_push_deliveries SET state='expired',claim_token=NULL,claim_expires_at_ms=NULL,terminal_at_ms=now_ms WHERE state IN ('pending','claimed') AND expires_at_ms<=now_ms;
 RETURN QUERY WITH candidates AS (SELECT d.delivery_id FROM messaging.opaque_push_deliveries d WHERE (d.state='pending' AND COALESCE(d.retry_at_ms,d.created_at_ms)<=now_ms OR d.state='claimed' AND d.claim_expires_at_ms<=now_ms) AND d.expires_at_ms>now_ms ORDER BY d.created_at_ms LIMIT maximum_rows FOR UPDATE SKIP LOCKED), claimed AS (UPDATE messaging.opaque_push_deliveries d SET state='claimed',claim_token=requested_claim,claim_expires_at_ms=now_ms+30000,retry_count=d.retry_count+1 FROM candidates c WHERE d.delivery_id=c.delivery_id RETURNING d.*) SELECT c.claim_token,c.delivery_id,r.registration_id,r.identity_id,r.device_id,r.provider,c.registration_revision,c.mailbox_id,c.envelope_id,r.token_ciphertext,r.token_nonce,r.encrypted_dek,r.kms_key_version,r.encryption_context FROM claimed c JOIN messaging.opaque_push_registrations r ON r.registration_id=c.registration_id AND r.revision=c.registration_revision AND r.state='active';
END $$;

/* generic finish removed: callers use dedicated fenced outcome functions below */
/* CREATE FUNCTION messaging.finish_opaque_push_delivery(requested_delivery uuid, requested_claim uuid, outcome text, now_ms bigint)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging AS $$
DECLARE changed boolean;
BEGIN
 now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
 IF NOT COALESCE(pg_has_role(session_user,to_regrole('dtx_push_broker_runtime'),'MEMBER'),false) OR outcome NOT IN ('accepted','transient','permanent_invalid','expired') THEN RAISE EXCEPTION 'opaque push finish rejected' USING ERRCODE='42501'; END IF;
 UPDATE messaging.opaque_push_deliveries d SET state=CASE outcome WHEN 'accepted' THEN 'delivered' WHEN 'transient' THEN 'pending' WHEN 'permanent_invalid' THEN 'permanent_failure' ELSE 'expired' END,claim_token=NULL,claim_expires_at_ms=NULL,retry_at_ms=CASE WHEN outcome='transient' THEN now_ms+1000 END,error_class=CASE WHEN outcome='permanent_invalid' THEN 'invalid_token' WHEN outcome='transient' THEN 'transient' END,terminal_at_ms=CASE WHEN outcome IN ('accepted','permanent_invalid','expired') THEN now_ms END FROM messaging.opaque_push_registrations r WHERE d.delivery_id=requested_delivery AND d.state='claimed' AND d.claim_token=requested_claim AND r.registration_id=d.registration_id AND r.revision=d.registration_revision AND r.state='active' RETURNING true INTO changed;
 IF outcome='permanent_invalid' AND changed THEN UPDATE messaging.opaque_push_registrations r SET state='suspended',updated_at_ms=now_ms FROM messaging.opaque_push_deliveries d WHERE d.delivery_id=requested_delivery AND r.registration_id=d.registration_id AND r.revision=d.registration_revision; END IF;
 RETURN COALESCE(changed,false);
END $$; */

CREATE FUNCTION messaging.prune_opaque_push_terminal(maximum_rows integer DEFAULT 256) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging AS $$
DECLARE removed bigint; now_ms bigint; BEGIN now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint; IF NOT COALESCE(pg_has_role(session_user,to_regrole('dtx_push_broker_runtime'),'MEMBER'),false) OR maximum_rows NOT BETWEEN 1 AND 1024 THEN RAISE EXCEPTION 'opaque push prune rejected' USING ERRCODE='42501'; END IF; WITH selected AS (SELECT delivery_id FROM messaging.opaque_push_deliveries WHERE terminal_at_ms<=now_ms-86400000 ORDER BY terminal_at_ms LIMIT maximum_rows FOR UPDATE SKIP LOCKED), gone AS (DELETE FROM messaging.opaque_push_deliveries d USING selected s WHERE d.delivery_id=s.delivery_id RETURNING 1) SELECT count(*) INTO removed FROM gone; RETURN removed; END $$;

CREATE FUNCTION messaging.authorize_opaque_push_send(requested_delivery uuid, requested_claim uuid)
RETURNS TABLE(registration_revision bigint, expires_at_ms bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging AS $$
DECLARE d messaging.opaque_push_deliveries%ROWTYPE; r messaging.opaque_push_registrations%ROWTYPE; now_ms bigint; candidate_registration uuid; candidate_device uuid; candidate_provider text;
BEGIN
 IF NOT COALESCE(pg_has_role(session_user,to_regrole('dtx_push_broker_runtime'),'MEMBER'),false) THEN RAISE EXCEPTION 'opaque push authorize rejected' USING ERRCODE='42501'; END IF;
 SELECT del.registration_id,reg.device_id,reg.provider INTO candidate_registration,candidate_device,candidate_provider FROM messaging.opaque_push_deliveries del JOIN messaging.opaque_push_registrations reg ON reg.registration_id=del.registration_id WHERE del.delivery_id=requested_delivery;
 IF NOT FOUND THEN RETURN; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('opaque_push:provider:'||candidate_device::text||':'||candidate_provider,0));
 SELECT * INTO r FROM messaging.opaque_push_registrations WHERE registration_id=candidate_registration FOR UPDATE;
 IF NOT FOUND OR r.device_id<>candidate_device OR r.provider<>candidate_provider THEN RETURN; END IF;
 SELECT * INTO d FROM messaging.opaque_push_deliveries WHERE delivery_id=requested_delivery FOR UPDATE;
 IF NOT FOUND OR d.registration_id<>r.registration_id OR d.state<>'claimed' OR d.claim_token IS DISTINCT FROM requested_claim OR d.registration_revision<>r.revision THEN RETURN; END IF;
 now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
 IF d.expires_at_ms<=now_ms THEN UPDATE messaging.opaque_push_deliveries SET state='expired',claim_token=NULL,claim_expires_at_ms=NULL,terminal_at_ms=now_ms WHERE delivery_id=d.delivery_id; RETURN; END IF;
 IF r.state<>'active' OR r.revision<>d.registration_revision THEN UPDATE messaging.opaque_push_deliveries SET state='revoked',claim_token=NULL,claim_expires_at_ms=NULL,terminal_at_ms=now_ms,error_class='provider_rejected' WHERE delivery_id=d.delivery_id; RETURN; END IF;
 IF d.claim_expires_at_ms<=now_ms THEN UPDATE messaging.opaque_push_deliveries SET state='pending',claim_token=NULL,claim_expires_at_ms=NULL WHERE delivery_id=d.delivery_id; RETURN; END IF;
 registration_revision:=d.registration_revision; expires_at_ms:=d.expires_at_ms; RETURN NEXT;
END $$;

CREATE FUNCTION messaging.finish_opaque_push_accepted(requested_delivery uuid, requested_claim uuid) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging AS $$
DECLARE permit record; now_ms bigint; changed boolean;
BEGIN IF NOT COALESCE(pg_has_role(session_user,to_regrole('dtx_push_broker_runtime'),'MEMBER'),false) THEN RAISE EXCEPTION 'opaque push accepted rejected' USING ERRCODE='42501'; END IF; SELECT * INTO permit FROM messaging.authorize_opaque_push_send(requested_delivery,requested_claim); IF permit IS NULL THEN RETURN false; END IF; now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint; UPDATE messaging.opaque_push_deliveries SET state='delivered',claim_token=NULL,claim_expires_at_ms=NULL,terminal_at_ms=now_ms WHERE delivery_id=requested_delivery AND state='claimed' AND claim_token=requested_claim; GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed; END $$;

CREATE FUNCTION messaging.finish_opaque_push_permanent_failure(requested_delivery uuid, requested_claim uuid, requested_error_class text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging AS $$
DECLARE permit record; now_ms bigint; changed boolean;
BEGIN IF NOT COALESCE(pg_has_role(session_user,to_regrole('dtx_push_broker_runtime'),'MEMBER'),false) THEN RAISE EXCEPTION 'opaque push permanent rejected' USING ERRCODE='42501'; END IF; IF requested_error_class IS DISTINCT FROM 'provider_rejected' THEN RAISE EXCEPTION 'opaque push permanent class rejected' USING ERRCODE='22023'; END IF; SELECT * INTO permit FROM messaging.authorize_opaque_push_send(requested_delivery,requested_claim); IF permit IS NULL THEN RETURN false; END IF; now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint; UPDATE messaging.opaque_push_deliveries SET state='permanent_failure',error_class=requested_error_class,claim_token=NULL,claim_expires_at_ms=NULL,terminal_at_ms=now_ms WHERE delivery_id=requested_delivery AND state='claimed' AND claim_token=requested_claim; GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed; END $$;

CREATE FUNCTION messaging.finish_opaque_push_transient(requested_delivery uuid, requested_claim uuid, retry_after_seconds integer, requested_error_class text)
RETURNS TABLE(outcome text, db_now bigint, next_attempt bigint, expires bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging AS $$
DECLARE d messaging.opaque_push_deliveries%ROWTYPE; permit record;
BEGIN
 IF NOT COALESCE(pg_has_role(session_user,to_regrole('dtx_push_broker_runtime'),'MEMBER'),false) THEN RAISE EXCEPTION 'opaque push transient rejected' USING ERRCODE='42501'; END IF;
 IF retry_after_seconds NOT BETWEEN 1 AND 60 OR requested_error_class IS DISTINCT FROM 'transient' THEN RAISE EXCEPTION 'opaque push transient rejected' USING ERRCODE='22023'; END IF;
 SELECT * INTO permit FROM messaging.authorize_opaque_push_send(requested_delivery,requested_claim);
 IF permit IS NULL THEN db_now:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint; RETURN QUERY SELECT 'fence_lost',db_now,NULL::bigint,NULL::bigint; RETURN; END IF;
 SELECT * INTO d FROM messaging.opaque_push_deliveries WHERE delivery_id=requested_delivery FOR UPDATE;
 db_now:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 expires:=d.expires_at_ms;
 next_attempt:=LEAST(db_now+retry_after_seconds*1000,d.expires_at_ms-1);
 IF next_attempt<=db_now THEN UPDATE messaging.opaque_push_deliveries SET state='expired',claim_token=NULL,claim_expires_at_ms=NULL,terminal_at_ms=db_now WHERE delivery_id=requested_delivery; RETURN QUERY SELECT 'expired',db_now,NULL::bigint,expires; RETURN; END IF;
 UPDATE messaging.opaque_push_deliveries SET state='pending',retry_at_ms=next_attempt,error_class='transient',claim_token=NULL,claim_expires_at_ms=NULL WHERE delivery_id=requested_delivery AND state='claimed' AND claim_token=requested_claim;
 RETURN QUERY SELECT 'scheduled',db_now,next_attempt,expires;
END $$;

CREATE FUNCTION messaging.finish_opaque_push_invalid_token(requested_delivery uuid, requested_claim uuid, pinned_revision bigint) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,messaging AS $$
DECLARE d messaging.opaque_push_deliveries%ROWTYPE; r messaging.opaque_push_registrations%ROWTYPE; now_ms bigint; changed integer; selected_device uuid;
BEGIN
 IF NOT COALESCE(pg_has_role(session_user,to_regrole('dtx_push_broker_runtime'),'MEMBER'),false) THEN RAISE EXCEPTION 'opaque push invalid token rejected' USING ERRCODE='42501'; END IF;
 SELECT reg.device_id INTO selected_device FROM messaging.opaque_push_deliveries del JOIN messaging.opaque_push_registrations reg ON reg.registration_id=del.registration_id WHERE del.delivery_id=requested_delivery;
 IF selected_device IS NULL THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('opaque_push:provider:'||selected_device::text||':fcm',0));
 SELECT * INTO r FROM messaging.opaque_push_registrations WHERE device_id=selected_device AND provider='fcm' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO d FROM messaging.opaque_push_deliveries WHERE delivery_id=requested_delivery FOR UPDATE;
 IF NOT FOUND OR d.registration_id<>r.registration_id THEN RETURN false; END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF d.state<>'claimed' OR d.claim_token IS DISTINCT FROM requested_claim OR d.claim_expires_at_ms<=now_ms OR d.expires_at_ms<=now_ms OR d.registration_revision<>pinned_revision OR r.device_id<>selected_device OR r.provider<>'fcm' OR r.state<>'active' OR r.revision<>pinned_revision THEN RETURN false; END IF;
 UPDATE messaging.opaque_push_registrations SET state='suspended',updated_at_ms=now_ms WHERE registration_id=r.registration_id AND state='active' AND revision=pinned_revision;
 UPDATE messaging.opaque_push_deliveries SET state='permanent_failure',error_class='invalid_token',claim_token=NULL,claim_expires_at_ms=NULL,terminal_at_ms=now_ms WHERE registration_id=r.registration_id AND registration_revision=pinned_revision AND state IN ('pending','claimed');
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed > 0;
END $$;

REVOKE ALL ON SCHEMA messaging FROM PUBLIC;
REVOKE ALL ON messaging.opaque_push_registrations,messaging.opaque_push_idempotency_claims,messaging.opaque_push_deliveries FROM PUBLIC;
REVOKE ALL ON FUNCTION messaging.opaque_push_cbor_uint(bigint), messaging.opaque_push_canonical_receipt(bigint,text), messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid), messaging.opaque_push_commit_put(uuid,bytea,uuid,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea,bytea,bytea,bytea,text,bytea), messaging.opaque_push_commit_delete(uuid,bytea,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION messaging.enqueue_opaque_push_intent(uuid,uuid,uuid), messaging.claim_opaque_push_deliveries(uuid,integer), messaging.prune_opaque_push_terminal(integer), messaging.authorize_opaque_push_send(uuid,uuid), messaging.finish_opaque_push_accepted(uuid,uuid), messaging.finish_opaque_push_permanent_failure(uuid,uuid,text), messaging.finish_opaque_push_transient(uuid,uuid,integer,text), messaging.finish_opaque_push_invalid_token(uuid,uuid,bigint) FROM PUBLIC;
DO $grants$ BEGIN
 IF to_regrole('dtx_push_registration_runtime') IS NOT NULL THEN GRANT USAGE ON SCHEMA messaging TO dtx_push_registration_runtime; GRANT EXECUTE ON FUNCTION messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid), messaging.opaque_push_commit_put(uuid,bytea,uuid,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea,bytea,bytea,bytea,text,bytea), messaging.opaque_push_commit_delete(uuid,bytea,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea) TO dtx_push_registration_runtime; END IF;
 IF to_regrole('dtx_push_identity_auth_runtime') IS NOT NULL THEN GRANT USAGE ON SCHEMA identity TO dtx_push_identity_auth_runtime; GRANT SELECT ON identity.device_sessions,identity.log_heads,identity.log_entries TO dtx_push_identity_auth_runtime; END IF;
 IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION messaging.enqueue_opaque_push_intent(uuid,uuid,uuid) TO dtx_mailbox_runtime; END IF;
 IF to_regrole('dtx_push_broker_runtime') IS NOT NULL THEN GRANT USAGE ON SCHEMA messaging TO dtx_push_broker_runtime; GRANT EXECUTE ON FUNCTION messaging.claim_opaque_push_deliveries(uuid,integer),messaging.prune_opaque_push_terminal(integer),messaging.authorize_opaque_push_send(uuid,uuid),messaging.finish_opaque_push_accepted(uuid,uuid),messaging.finish_opaque_push_permanent_failure(uuid,uuid,text),messaging.finish_opaque_push_transient(uuid,uuid,integer,text),messaging.finish_opaque_push_invalid_token(uuid,uuid,bigint) TO dtx_push_broker_runtime; END IF;
END $grants$;
