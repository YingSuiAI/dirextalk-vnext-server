CREATE SCHEMA realtime;

CREATE FUNCTION realtime.runtime_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT pg_has_role(session_user, 'dtx_realtime_sync_runtime', 'MEMBER')
       AND NOT pg_has_role(session_user, 'dtx_mailbox_runtime', 'MEMBER')
       AND NOT pg_has_role(session_user, 'dtx_identity_runtime', 'MEMBER')
$$;

REVOKE ALL ON FUNCTION realtime.runtime_authorized() FROM PUBLIC;

CREATE FUNCTION identity.identity_realtime_reader_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT COALESCE(
        pg_has_role(current_user, to_regrole('dtx_realtime_sync_runtime'), 'MEMBER'),
        false
    )
$$;

REVOKE ALL ON FUNCTION identity.identity_realtime_reader_authorized() FROM PUBLIC;

ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_realtime_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_realtime_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_realtime_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

CREATE TABLE messaging.identity_delivery_heads (
    identity_id text PRIMARY KEY REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
    next_sequence bigint NOT NULL DEFAULT 0 CHECK (next_sequence BETWEEN 0 AND 9007199254740991)
);

CREATE TABLE messaging.identity_delivery_journal (
    identity_id text NOT NULL,
    delivery_sequence bigint NOT NULL CHECK (delivery_sequence BETWEEN 1 AND 9007199254740991),
    mailbox_id uuid NOT NULL,
    envelope_id uuid NOT NULL,
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, delivery_sequence),
    UNIQUE (mailbox_id, envelope_id),
    FOREIGN KEY (identity_id) REFERENCES messaging.identity_delivery_heads(identity_id) ON DELETE RESTRICT,
    FOREIGN KEY (mailbox_id, envelope_id) REFERENCES messaging.mailbox_envelopes(mailbox_id, envelope_id) ON DELETE RESTRICT,
    CHECK (expires_at_ms > created_at_ms)
);

CREATE TABLE messaging.device_delivery_state (
    identity_id text NOT NULL,
    device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(device_id)),
    contiguous_ack_sequence bigint NOT NULL DEFAULT 0 CHECK (contiguous_ack_sequence BETWEEN 0 AND 9007199254740991),
    earliest_authorized_sequence bigint NOT NULL CHECK (earliest_authorized_sequence BETWEEN 1 AND 9007199254740991),
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, device_id),
    FOREIGN KEY (identity_id) REFERENCES messaging.identity_delivery_heads(identity_id) ON DELETE RESTRICT
);

CREATE TABLE messaging.device_delivery_ack_claims (
    identity_id text NOT NULL,
    device_id uuid NOT NULL,
    idempotency_key_hash bytea NOT NULL CHECK (octet_length(idempotency_key_hash)=32),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    ack_sequence bigint NOT NULL CHECK (ack_sequence BETWEEN 0 AND 9007199254740991),
    receipt_bytes bytea NOT NULL CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    receipt_hash bytea NOT NULL CHECK (octet_length(receipt_hash)=32),
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, device_id, idempotency_key_hash),
    FOREIGN KEY (identity_id, device_id) REFERENCES messaging.device_delivery_state(identity_id, device_id) ON DELETE RESTRICT
);

CREATE TABLE messaging.device_history_grants (
    identity_id text NOT NULL,
    new_device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(new_device_id)),
    identity_head bytea NOT NULL CHECK (octet_length(identity_head)=32),
    earliest_sequence bigint NOT NULL CHECK (earliest_sequence BETWEEN 1 AND 9007199254740991),
    encrypted_history_digest bytea NOT NULL CHECK (octet_length(encrypted_history_digest)=32),
    authorization_kind text NOT NULL CHECK (authorization_kind IN ('grantor_device','recovery','root')),
    authorizer_id text NOT NULL CHECK (octet_length(authorizer_id) BETWEEN 8 AND 128),
    new_device_pop_digest bytea NOT NULL CHECK (octet_length(new_device_pop_digest)=32),
    canonical_grant bytea NOT NULL CHECK (octet_length(canonical_grant) BETWEEN 1 AND 16384),
    grant_digest bytea NOT NULL CHECK (octet_length(grant_digest)=32),
    signature bytea NOT NULL CHECK (octet_length(signature)=64),
    new_device_pop_signature bytea NOT NULL CHECK (octet_length(new_device_pop_signature)=64),
    granted_at_ms bigint NOT NULL,
    revoked_at_ms bigint,
    PRIMARY KEY (identity_id, new_device_id),
    FOREIGN KEY (identity_id) REFERENCES messaging.identity_delivery_heads(identity_id) ON DELETE RESTRICT,
    CHECK (revoked_at_ms IS NULL OR revoked_at_ms >= granted_at_ms)
);

CREATE TABLE realtime.identity_heads (
    identity_id text PRIMARY KEY REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
    next_cursor bigint NOT NULL DEFAULT 0 CHECK (next_cursor BETWEEN 0 AND 9007199254740991),
    journal_floor bigint NOT NULL DEFAULT 1 CHECK (journal_floor BETWEEN 1 AND 9007199254740991)
);

CREATE TABLE realtime.journal (
    identity_id text NOT NULL,
    cursor bigint NOT NULL CHECK (cursor BETWEEN 1 AND 9007199254740991),
    event_kind text NOT NULL CHECK (event_kind IN ('mailbox_delivery','conversation_read','durable_invalidation')),
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest)=32),
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, cursor),
    FOREIGN KEY (identity_id) REFERENCES realtime.identity_heads(identity_id) ON DELETE RESTRICT,
    CHECK (expires_at_ms > created_at_ms)
);

CREATE TABLE realtime.outbox (
    identity_id text NOT NULL,
    cursor bigint NOT NULL,
    published_at_ms bigint,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1000),
    PRIMARY KEY (identity_id, cursor),
    FOREIGN KEY (identity_id, cursor) REFERENCES realtime.journal(identity_id, cursor) ON DELETE RESTRICT
);

CREATE TABLE realtime.device_sync_acks (
    identity_id text NOT NULL,
    device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(device_id)),
    ack_cursor bigint NOT NULL DEFAULT 0 CHECK (ack_cursor BETWEEN 0 AND 9007199254740991),
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, device_id),
    FOREIGN KEY (identity_id) REFERENCES realtime.identity_heads(identity_id) ON DELETE RESTRICT
);

CREATE TABLE realtime.device_leases (
    identity_id text NOT NULL,
    device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(device_id)),
    lease_id uuid NOT NULL CHECK (messaging.is_uuid_v7(lease_id)),
    fence bigint NOT NULL CHECK (fence BETWEEN 1 AND 9007199254740991),
    heartbeat_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, device_id),
    UNIQUE (lease_id),
    FOREIGN KEY (identity_id) REFERENCES realtime.identity_heads(identity_id) ON DELETE RESTRICT,
    CHECK (expires_at_ms = heartbeat_at_ms + 45000)
);

CREATE TABLE realtime.encrypted_account_read_cursors (
    identity_id text NOT NULL,
    conversation_digest bytea NOT NULL CHECK (octet_length(conversation_digest)=32),
    encrypted_cursor bytea NOT NULL CHECK (octet_length(encrypted_cursor) BETWEEN 1 AND 4096),
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    updated_by_device uuid NOT NULL CHECK (messaging.is_uuid_v7(updated_by_device)),
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, conversation_digest),
    FOREIGN KEY (identity_id) REFERENCES realtime.identity_heads(identity_id) ON DELETE RESTRICT
);

REVOKE ALL ON SCHEMA realtime FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA realtime FROM PUBLIC;
REVOKE ALL ON messaging.identity_delivery_heads, messaging.identity_delivery_journal,
    messaging.device_delivery_state, messaging.device_delivery_ack_claims,
    messaging.device_history_grants FROM PUBLIC;

DO $grants$
BEGIN
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION identity.identity_realtime_reader_authorized() TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT, UPDATE ON messaging.identity_delivery_heads TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON messaging.identity_delivery_journal TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT, UPDATE ON messaging.device_delivery_state TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON messaging.device_delivery_ack_claims TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT, UPDATE ON messaging.device_history_grants TO dtx_mailbox_runtime;
        GRANT USAGE ON SCHEMA realtime TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT, UPDATE ON realtime.identity_heads TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON realtime.journal, realtime.outbox TO dtx_mailbox_runtime;
    END IF;
    IF to_regrole('dtx_realtime_sync_runtime') IS NOT NULL THEN
        -- `messaging` schema visibility is required only so startup can prove
        -- that the gateway has no mailbox payload table privilege.
        GRANT USAGE ON SCHEMA realtime, identity, messaging TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION realtime.runtime_authorized() TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION messaging.is_uuid_v7(uuid) TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_runtime_authorized() TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_owner_authorized() TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_realtime_reader_authorized() TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_mailbox_reader_authorized() TO dtx_realtime_sync_runtime;
        GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries TO dtx_realtime_sync_runtime;
        GRANT SELECT ON realtime.identity_heads, realtime.journal TO dtx_realtime_sync_runtime;
        GRANT SELECT, INSERT, UPDATE ON realtime.device_sync_acks, realtime.device_leases TO dtx_realtime_sync_runtime;
    END IF;
END
$grants$;
