-- V45: catalog-exhaustive History Recovery Grant V4.  The grant and its
-- delivery fact are immutable append-only receipts.  Raw capabilities,
-- prompts, decrypted history, MLS private state, and provider bodies are not
-- stored here; the only opaque payload is the recipient ciphertext offer.
CREATE TABLE messaging.history_recovery_grants_v4 (
    identity_id text NOT NULL,
    request_id uuid NOT NULL CHECK (messaging.is_uuid_v7(request_id)),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest)=32),
    catalog_id uuid NOT NULL CHECK (messaging.is_uuid_v7(catalog_id)),
    generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    catalog_head_bytes bytea NOT NULL CHECK (octet_length(catalog_head_bytes) BETWEEN 1 AND 466),
    catalog_head_digest bytea NOT NULL CHECK (octet_length(catalog_head_digest)=32),
    catalog_merkle_root bytea NOT NULL CHECK (octet_length(catalog_merkle_root)=32),
    catalog_leaf_count bigint NOT NULL CHECK (catalog_leaf_count BETWEEN 1 AND 1023),
    catalog_leaf_set_digest bytea NOT NULL CHECK (octet_length(catalog_leaf_set_digest)=32),
    candidate_device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(candidate_device_id)),
    candidate_signing_key bytea NOT NULL CHECK (octet_length(candidate_signing_key)=32),
    candidate_recipient_key bytea NOT NULL CHECK (octet_length(candidate_recipient_key)=32),
    pre_head_sequence bigint NOT NULL CHECK (pre_head_sequence BETWEEN 0 AND 9007199254740990),
    pre_head_hash bytea NOT NULL CHECK (octet_length(pre_head_hash)=32),
    post_head_sequence bigint NOT NULL CHECK (post_head_sequence=pre_head_sequence+1),
    post_head_hash bytea NOT NULL CHECK (octet_length(post_head_hash)=32),
    device_add_digest bytea NOT NULL CHECK (octet_length(device_add_digest)=32),
    preparation_digest bytea NOT NULL CHECK (octet_length(preparation_digest)=32),
    provider_device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(provider_device_id)),
    provider_descriptor bytea NOT NULL CHECK (octet_length(provider_descriptor) BETWEEN 1 AND 77),
    authority_descriptor bytea NOT NULL CHECK (octet_length(authority_descriptor) BETWEEN 1 AND 77),
    recipient_key_digest bytea NOT NULL CHECK (octet_length(recipient_key_digest)=32),
    offer_digest bytea NOT NULL CHECK (octet_length(offer_digest)=32),
    mailbox_id uuid NOT NULL CHECK (messaging.is_uuid_v7(mailbox_id)),
    envelope_id uuid NOT NULL CHECK (messaging.is_uuid_v7(envelope_id)),
    mailbox_highwater bigint NOT NULL CHECK (mailbox_highwater BETWEEN 0 AND 9007199254740990),
    earliest_sequence bigint NOT NULL CHECK (earliest_sequence=mailbox_highwater+1),
    delivery_fact_id uuid NOT NULL CHECK (messaging.is_uuid_v7(delivery_fact_id)),
    issued_at_ms bigint NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9007199254740991),
    expires_at_ms bigint NOT NULL CHECK (expires_at_ms>issued_at_ms),
    idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest)=32),
    provider_signature bytea NOT NULL CHECK (octet_length(provider_signature)=64),
    authority_signature bytea NOT NULL CHECK (octet_length(authority_signature)=64),
    exact_offer bytea NOT NULL CHECK (octet_length(exact_offer) BETWEEN 1 AND 1049093),
    exact_grant bytea NOT NULL CHECK (octet_length(exact_grant) BETWEEN 1 AND 1050733),
    grant_digest bytea NOT NULL CHECK (octet_length(grant_digest)=32),
    delivery_fact_bytes bytea NOT NULL CHECK (octet_length(delivery_fact_bytes) BETWEEN 1 AND 366),
    delivery_fact_digest bytea NOT NULL CHECK (octet_length(delivery_fact_digest)=32),
    receipt_bytes bytea NOT NULL CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    receipt_hash bytea NOT NULL CHECK (octet_length(receipt_hash)=32),
    accepted_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, request_id),
    UNIQUE (identity_id, provider_device_id, idempotency_digest),
    UNIQUE (mailbox_id, envelope_id),
    UNIQUE (delivery_fact_id),
    FOREIGN KEY (request_id)
        REFERENCES identity.history_recovery_requests(request_id)
        ON DELETE RESTRICT
);

CREATE FUNCTION messaging.reject_history_recovery_grant_v4_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'history recovery grant is immutable' USING ERRCODE='23514';
END
$$;
CREATE TRIGGER history_recovery_grant_v4_append_only
BEFORE UPDATE OR DELETE ON messaging.history_recovery_grants_v4
FOR EACH ROW EXECUTE FUNCTION messaging.reject_history_recovery_grant_v4_mutation();

ALTER TABLE messaging.history_recovery_grants_v4 ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.history_recovery_grants_v4 FORCE ROW LEVEL SECURITY;
CREATE POLICY history_recovery_grant_v4_runtime_only
    ON messaging.history_recovery_grants_v4
    USING (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized())
    WITH CHECK (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized());

-- The mailbox role receives only the immutable projection needed to fence a
-- grant.  Existing identity rows remain read-only and are exposed through
-- the same narrow mailbox reader policy used for session authentication.
ALTER POLICY identity_runtime_only ON identity.device_enrollment_challenges
    USING (identity.identity_runtime_authorized() OR identity.identity_mailbox_reader_authorized() OR identity.identity_owner_authorized());
ALTER POLICY identity_runtime_only ON identity.history_recovery_requests
    USING (identity.identity_runtime_authorized() OR identity.identity_mailbox_reader_authorized() OR identity.identity_owner_authorized());
ALTER POLICY identity_runtime_only ON identity.recovery_scope_catalogs
    USING (identity.identity_runtime_authorized() OR identity.identity_mailbox_reader_authorized() OR identity.identity_owner_authorized());
ALTER POLICY identity_runtime_only ON identity.recovery_scope_catalog_preparations
    USING (identity.identity_runtime_authorized() OR identity.identity_mailbox_reader_authorized() OR identity.identity_owner_authorized());

DO $grants$
BEGIN
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON messaging.history_recovery_grants_v4 TO dtx_mailbox_runtime;
        GRANT SELECT ON identity.device_enrollment_challenges,
            identity.history_recovery_requests,
            identity.recovery_scope_catalogs,
            identity.recovery_scope_catalog_preparations TO dtx_mailbox_runtime;
    END IF;
END
$grants$;
REVOKE ALL ON FUNCTION messaging.reject_history_recovery_grant_v4_mutation() FROM PUBLIC;
