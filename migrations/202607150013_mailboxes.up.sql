-- The opaque mailbox relay deliberately owns only delivery metadata and
-- ciphertext bytes.  It can validate an already-issued device session via a
-- read-only identity projection grant, but cannot append or rewrite identity
-- facts.  Raw write capabilities never enter these relations.
CREATE SCHEMA messaging;

CREATE FUNCTION messaging.mailbox_runtime_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT COALESCE(
        pg_has_role(current_user, to_regrole('dtx_mailbox_runtime'), 'MEMBER'),
        false
    )
$$;

CREATE FUNCTION messaging.mailbox_owner_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT current_user = pg_get_userbyid(nspowner)
      FROM pg_namespace
     WHERE nspname = 'messaging'
$$;

CREATE FUNCTION messaging.is_uuid_v7(candidate uuid)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT (get_byte(uuid_send(candidate), 6) >> 4) = 7
       AND (get_byte(uuid_send(candidate), 8) >> 6) = 2
$$;

-- Keep the mailbox role narrowly read-capable across identity state.  This is
-- used only by `DeviceSessionRepository::authenticate_in_transaction`; no
-- mailbox policy grants identity writes or access to opaque KeyPackages.
CREATE FUNCTION identity.identity_mailbox_reader_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT COALESCE(
        pg_has_role(current_user, to_regrole('dtx_mailbox_runtime'), 'MEMBER'),
        false
    )
$$;

ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (
        identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_owner_authorized()
    )
    WITH CHECK (
        identity.identity_runtime_authorized()
        OR identity.identity_owner_authorized()
    );

ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (
        identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_owner_authorized()
    )
    WITH CHECK (
        identity.identity_runtime_authorized()
        OR identity.identity_owner_authorized()
    );

ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (
        identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_owner_authorized()
    )
    WITH CHECK (
        identity.identity_runtime_authorized()
        OR identity.identity_owner_authorized()
    );

CREATE TABLE messaging.mailboxes (
    mailbox_id uuid PRIMARY KEY,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    write_capability_hash bytea NOT NULL,
    expires_at_ms bigint NOT NULL,
    next_delivery_sequence bigint NOT NULL DEFAULT 0,
    active_envelope_count integer NOT NULL DEFAULT 0,
    active_envelope_bytes bigint NOT NULL DEFAULT 0,
    created_at_ms bigint NOT NULL,
    CONSTRAINT messaging_mailboxes_id_v7
        CHECK (messaging.is_uuid_v7(mailbox_id)),
    CONSTRAINT messaging_mailboxes_owner_device_v7
        CHECK (messaging.is_uuid_v7(owner_device_id)),
    CONSTRAINT messaging_mailboxes_owner_identity_bounded
        CHECK (octet_length(owner_identity_id) BETWEEN 8 AND 128),
    CONSTRAINT messaging_mailboxes_capability_hash_size
        CHECK (octet_length(write_capability_hash) = 32),
    CONSTRAINT messaging_mailboxes_expiry_valid
        CHECK (expires_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT messaging_mailboxes_created_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT messaging_mailboxes_expiry_after_creation
        CHECK (expires_at_ms > created_at_ms),
    CONSTRAINT messaging_mailboxes_next_sequence_safe
        CHECK (next_delivery_sequence BETWEEN 0 AND 9007199254740991),
    CONSTRAINT messaging_mailboxes_active_count_bounded
        CHECK (active_envelope_count BETWEEN 0 AND 1000),
    CONSTRAINT messaging_mailboxes_active_bytes_bounded
        CHECK (active_envelope_bytes BETWEEN 0 AND 67108864),
    CONSTRAINT messaging_mailboxes_owner_identity_fk
        FOREIGN KEY (owner_identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE messaging.mailbox_registration_claims (
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    mailbox_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_hash bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (owner_identity_id, owner_device_id, idempotency_key_hash),
    CONSTRAINT messaging_registration_claims_owner_identity_fk
        FOREIGN KEY (owner_identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT messaging_registration_claims_mailbox_fk
        FOREIGN KEY (mailbox_id)
        REFERENCES messaging.mailboxes (mailbox_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT messaging_registration_claims_device_v7
        CHECK (messaging.is_uuid_v7(owner_device_id)),
    CONSTRAINT messaging_registration_claims_idempotency_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT messaging_registration_claims_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT messaging_registration_claims_receipt_hash_size
        CHECK (octet_length(receipt_hash) = 32),
    CONSTRAINT messaging_registration_claims_receipt_bounded
        CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    CONSTRAINT messaging_registration_claims_created_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE UNIQUE INDEX messaging_registration_claims_mailbox_unique
    ON messaging.mailbox_registration_claims (mailbox_id);

CREATE TABLE messaging.mailbox_envelopes (
    mailbox_id uuid NOT NULL,
    envelope_id uuid NOT NULL,
    delivery_sequence bigint NOT NULL,
    opaque_ciphertext bytea NOT NULL,
    request_digest bytea NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_hash bytea NOT NULL,
    expires_at_ms bigint NOT NULL,
    state text NOT NULL DEFAULT 'available',
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (mailbox_id, envelope_id),
    CONSTRAINT messaging_envelopes_mailbox_fk
        FOREIGN KEY (mailbox_id)
        REFERENCES messaging.mailboxes (mailbox_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT messaging_envelopes_id_v7
        CHECK (messaging.is_uuid_v7(envelope_id)),
    CONSTRAINT messaging_envelopes_sequence_safe
        CHECK (delivery_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT messaging_envelopes_delivery_unique
        UNIQUE (mailbox_id, delivery_sequence),
    CONSTRAINT messaging_envelopes_ciphertext_bounded
        CHECK (octet_length(opaque_ciphertext) BETWEEN 1 AND 262144),
    CONSTRAINT messaging_envelopes_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT messaging_envelopes_receipt_hash_size
        CHECK (octet_length(receipt_hash) = 32),
    CONSTRAINT messaging_envelopes_receipt_bounded
        CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    CONSTRAINT messaging_envelopes_expiry_valid
        CHECK (expires_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT messaging_envelopes_created_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT messaging_envelopes_expiry_after_creation
        CHECK (expires_at_ms > created_at_ms),
    CONSTRAINT messaging_envelopes_state_valid
        CHECK (state IN ('available', 'acked', 'expired'))
);

CREATE INDEX messaging_envelopes_pull_idx
    ON messaging.mailbox_envelopes (mailbox_id, delivery_sequence);

CREATE TABLE messaging.mailbox_enqueue_claims (
    mailbox_id uuid NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    envelope_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_hash bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (mailbox_id, idempotency_key_hash),
    CONSTRAINT messaging_enqueue_claims_mailbox_fk
        FOREIGN KEY (mailbox_id)
        REFERENCES messaging.mailboxes (mailbox_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT messaging_enqueue_claims_envelope_fk
        FOREIGN KEY (mailbox_id, envelope_id)
        REFERENCES messaging.mailbox_envelopes (mailbox_id, envelope_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT messaging_enqueue_claims_idempotency_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT messaging_enqueue_claims_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT messaging_enqueue_claims_receipt_hash_size
        CHECK (octet_length(receipt_hash) = 32),
    CONSTRAINT messaging_enqueue_claims_receipt_bounded
        CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    CONSTRAINT messaging_enqueue_claims_created_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TABLE messaging.mailbox_ack_claims (
    mailbox_id uuid NOT NULL,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    request_digest bytea NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_hash bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (
        mailbox_id,
        owner_identity_id,
        owner_device_id,
        idempotency_key_hash
    ),
    CONSTRAINT messaging_ack_claims_mailbox_fk
        FOREIGN KEY (mailbox_id)
        REFERENCES messaging.mailboxes (mailbox_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT messaging_ack_claims_owner_identity_fk
        FOREIGN KEY (owner_identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT messaging_ack_claims_device_v7
        CHECK (messaging.is_uuid_v7(owner_device_id)),
    CONSTRAINT messaging_ack_claims_idempotency_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT messaging_ack_claims_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT messaging_ack_claims_receipt_hash_size
        CHECK (octet_length(receipt_hash) = 32),
    CONSTRAINT messaging_ack_claims_receipt_bounded
        CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    CONSTRAINT messaging_ack_claims_created_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE FUNCTION messaging.enforce_mailbox_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.mailbox_id IS DISTINCT FROM NEW.mailbox_id
       OR OLD.owner_identity_id IS DISTINCT FROM NEW.owner_identity_id
       OR OLD.owner_device_id IS DISTINCT FROM NEW.owner_device_id
       OR OLD.write_capability_hash IS DISTINCT FROM NEW.write_capability_hash
       OR OLD.expires_at_ms IS DISTINCT FROM NEW.expires_at_ms
       OR OLD.created_at_ms IS DISTINCT FROM NEW.created_at_ms THEN
        RAISE EXCEPTION 'mailbox registration is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION messaging.enforce_envelope_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.mailbox_id IS DISTINCT FROM NEW.mailbox_id
       OR OLD.envelope_id IS DISTINCT FROM NEW.envelope_id
       OR OLD.delivery_sequence IS DISTINCT FROM NEW.delivery_sequence
       OR OLD.opaque_ciphertext IS DISTINCT FROM NEW.opaque_ciphertext
       OR OLD.request_digest IS DISTINCT FROM NEW.request_digest
       OR OLD.receipt_bytes IS DISTINCT FROM NEW.receipt_bytes
       OR OLD.receipt_hash IS DISTINCT FROM NEW.receipt_hash
       OR OLD.expires_at_ms IS DISTINCT FROM NEW.expires_at_ms
       OR OLD.created_at_ms IS DISTINCT FROM NEW.created_at_ms
       OR OLD.state <> 'available'
       OR NEW.state NOT IN ('acked', 'expired') THEN
        RAISE EXCEPTION 'mailbox envelope transition is not authorized'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION messaging.reject_immutable_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'mailbox immutable relation cannot be rewritten'
        USING ERRCODE = '23514';
END
$$;

CREATE TRIGGER messaging_mailboxes_transition
BEFORE UPDATE OR DELETE ON messaging.mailboxes
FOR EACH ROW
EXECUTE FUNCTION messaging.enforce_mailbox_transition();

CREATE TRIGGER messaging_envelopes_transition
BEFORE UPDATE OR DELETE ON messaging.mailbox_envelopes
FOR EACH ROW
EXECUTE FUNCTION messaging.enforce_envelope_transition();

CREATE TRIGGER messaging_registration_claims_append_only
BEFORE UPDATE OR DELETE ON messaging.mailbox_registration_claims
FOR EACH ROW
EXECUTE FUNCTION messaging.reject_immutable_mutation();

CREATE TRIGGER messaging_enqueue_claims_append_only
BEFORE UPDATE OR DELETE ON messaging.mailbox_enqueue_claims
FOR EACH ROW
EXECUTE FUNCTION messaging.reject_immutable_mutation();

CREATE TRIGGER messaging_ack_claims_append_only
BEFORE UPDATE OR DELETE ON messaging.mailbox_ack_claims
FOR EACH ROW
EXECUTE FUNCTION messaging.reject_immutable_mutation();

ALTER TABLE messaging.mailboxes ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.mailboxes FORCE ROW LEVEL SECURITY;
CREATE POLICY messaging_runtime_only ON messaging.mailboxes
    USING (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized())
    WITH CHECK (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized());

ALTER TABLE messaging.mailbox_registration_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.mailbox_registration_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY messaging_runtime_only ON messaging.mailbox_registration_claims
    USING (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized())
    WITH CHECK (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized());

ALTER TABLE messaging.mailbox_envelopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.mailbox_envelopes FORCE ROW LEVEL SECURITY;
CREATE POLICY messaging_runtime_only ON messaging.mailbox_envelopes
    USING (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized())
    WITH CHECK (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized());

ALTER TABLE messaging.mailbox_enqueue_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.mailbox_enqueue_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY messaging_runtime_only ON messaging.mailbox_enqueue_claims
    USING (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized())
    WITH CHECK (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized());

ALTER TABLE messaging.mailbox_ack_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.mailbox_ack_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY messaging_runtime_only ON messaging.mailbox_ack_claims
    USING (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized())
    WITH CHECK (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized());

DO $grant$
BEGIN
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA messaging, identity TO dtx_mailbox_runtime;
        GRANT EXECUTE ON FUNCTION messaging.mailbox_runtime_authorized() TO dtx_mailbox_runtime;
        GRANT EXECUTE ON FUNCTION messaging.mailbox_owner_authorized() TO dtx_mailbox_runtime;
        GRANT EXECUTE ON FUNCTION messaging.is_uuid_v7(uuid) TO dtx_mailbox_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_runtime_authorized()
            TO dtx_mailbox_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_owner_authorized()
            TO dtx_mailbox_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_mailbox_reader_authorized()
            TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT, UPDATE ON messaging.mailboxes TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON messaging.mailbox_registration_claims TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT, UPDATE ON messaging.mailbox_envelopes TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON messaging.mailbox_enqueue_claims TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON messaging.mailbox_ack_claims TO dtx_mailbox_runtime;
        GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
            TO dtx_mailbox_runtime;
    END IF;
END
$grant$;

REVOKE ALL ON SCHEMA messaging FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA messaging FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA messaging FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.identity_mailbox_reader_authorized() FROM PUBLIC;
