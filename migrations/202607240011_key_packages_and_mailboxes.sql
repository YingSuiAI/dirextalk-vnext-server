-- An MLS KeyPackage is opaque application data.  The identity service stores
-- only the exact signed envelope, its fixed-domain digest, the publishing
-- device binding, and the one-time claim result.  It must never parse MLS
-- bytes or persist an MLS private key.
CREATE TABLE identity.key_packages (
    package_id uuid PRIMARY KEY,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    published_head_sequence bigint NOT NULL,
    published_head_hash bytea NOT NULL,
    package_digest bytea NOT NULL UNIQUE,
    exact_publish_bytes bytea NOT NULL,
    published_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    state text NOT NULL DEFAULT 'available',
    claimed_at_ms bigint,
    retention_until_ms bigint NOT NULL,
    CONSTRAINT identity_key_packages_owner_fk
        FOREIGN KEY (owner_identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_key_packages_head_sequence_safe
        CHECK (published_head_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT identity_key_packages_head_hash_size
        CHECK (octet_length(published_head_hash) = 32),
    CONSTRAINT identity_key_packages_digest_size
        CHECK (octet_length(package_digest) = 32),
    CONSTRAINT identity_key_packages_publish_bytes_bounded
        CHECK (octet_length(exact_publish_bytes) BETWEEN 1 AND 131072),
    CONSTRAINT identity_key_packages_state_valid
        CHECK (state IN ('available', 'claimed')),
    CONSTRAINT identity_key_packages_time_valid
        CHECK (
            published_at_ms BETWEEN -62135596800000 AND 253402300799999
            AND expires_at_ms BETWEEN published_at_ms AND 253402300799999
            AND retention_until_ms BETWEEN expires_at_ms AND 253402301699999
        ),
    CONSTRAINT identity_key_packages_state_consistent
        CHECK (
            (state = 'available' AND claimed_at_ms IS NULL AND retention_until_ms = expires_at_ms)
            OR (
                state = 'claimed'
                AND claimed_at_ms BETWEEN published_at_ms AND expires_at_ms
                AND retention_until_ms >= claimed_at_ms
            )
        )
);

-- A publish key is intentionally scoped to the authenticated identity/device.
-- The exact immutable receipt survives a lost success response without making
-- a device session itself a durable source of identity authority.
CREATE TABLE identity.key_package_publish_claims (
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    request_digest bytea NOT NULL,
    package_id uuid NOT NULL UNIQUE,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (owner_identity_id, owner_device_id, idempotency_key_hash),
    CONSTRAINT identity_key_package_publish_claims_owner_fk
        FOREIGN KEY (owner_identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_key_package_publish_claims_package_fk
        FOREIGN KEY (package_id)
        REFERENCES identity.key_packages (package_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_key_package_publish_claims_key_hash_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT identity_key_package_publish_claims_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT identity_key_package_publish_claims_receipt_bytes_bounded
        CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    CONSTRAINT identity_key_package_publish_claims_receipt_digest_size
        CHECK (octet_length(receipt_digest) = 32),
    CONSTRAINT identity_key_package_publish_claims_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

-- Exactly one row can reference a package, making a claim an atomic,
-- durable one-time consumption even when two HTTP requests race.  The exact
-- original publish envelope is retained as the claim receipt for retry.
CREATE TABLE identity.key_package_claims (
    claimant_identity_id text NOT NULL,
    claimant_device_id uuid NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    target_identity_id text NOT NULL,
    target_device_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (claimant_identity_id, claimant_device_id, idempotency_key_hash),
    CONSTRAINT identity_key_package_claims_claimant_fk
        FOREIGN KEY (claimant_identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_key_package_claims_target_fk
        FOREIGN KEY (target_identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_key_package_claims_key_hash_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT identity_key_package_claims_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT identity_key_package_claims_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TABLE identity.key_package_claim_receipts (
    claimant_identity_id text NOT NULL,
    claimant_device_id uuid NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    package_id uuid NOT NULL UNIQUE,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    claimed_at_ms bigint NOT NULL,
    PRIMARY KEY (claimant_identity_id, claimant_device_id, idempotency_key_hash),
    CONSTRAINT identity_key_package_claim_receipts_claim_fk
        FOREIGN KEY (claimant_identity_id, claimant_device_id, idempotency_key_hash)
        REFERENCES identity.key_package_claims (
            claimant_identity_id, claimant_device_id, idempotency_key_hash
        )
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_key_package_claim_receipts_package_fk
        FOREIGN KEY (package_id)
        REFERENCES identity.key_packages (package_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_key_package_claim_receipts_bytes_bounded
        CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 131072),
    CONSTRAINT identity_key_package_claim_receipts_digest_size
        CHECK (octet_length(receipt_digest) = 32),
    CONSTRAINT identity_key_package_claim_receipts_claimed_at_valid
        CHECK (claimed_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE INDEX identity_key_packages_available_by_target_idx
    ON identity.key_packages (
        owner_identity_id,
        owner_device_id,
        expires_at_ms,
        package_id
    ) WHERE state = 'available';

CREATE INDEX identity_key_packages_retention_idx
    ON identity.key_packages (retention_until_ms, package_id);

CREATE FUNCTION identity.key_package_retention_prune_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT identity.identity_owner_authorized()
       AND COALESCE(
           current_setting('identity.key_package_retention_prune', true),
           ''
       ) = 'on'
$$;

CREATE FUNCTION identity.enforce_key_package_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'available'
           OR NEW.claimed_at_ms IS NOT NULL
           OR NEW.retention_until_ms <> NEW.expires_at_ms THEN
            RAISE EXCEPTION 'key package must enter available'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF identity.key_package_retention_prune_authorized() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'key package can only be deleted by retention'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state <> 'available'
       OR NEW.state <> 'claimed'
       OR OLD.package_id IS DISTINCT FROM NEW.package_id
       OR OLD.owner_identity_id IS DISTINCT FROM NEW.owner_identity_id
       OR OLD.owner_device_id IS DISTINCT FROM NEW.owner_device_id
       OR OLD.published_head_sequence IS DISTINCT FROM NEW.published_head_sequence
       OR OLD.published_head_hash IS DISTINCT FROM NEW.published_head_hash
       OR OLD.package_digest IS DISTINCT FROM NEW.package_digest
       OR OLD.exact_publish_bytes IS DISTINCT FROM NEW.exact_publish_bytes
       OR OLD.published_at_ms IS DISTINCT FROM NEW.published_at_ms
       OR OLD.expires_at_ms IS DISTINCT FROM NEW.expires_at_ms
       OR NEW.claimed_at_ms IS NULL
       OR NEW.retention_until_ms < OLD.expires_at_ms
       OR NEW.retention_until_ms < NEW.claimed_at_ms THEN
        RAISE EXCEPTION 'key package transition is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION identity.enforce_key_package_immutable_or_prunable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND identity.key_package_retention_prune_authorized() THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'key package receipt relation can only be pruned by retention'
        USING ERRCODE = '23514';
END
$$;

-- Package expiry is authoritative at claim time.  Retention removes an
-- expired/claimed package only after the durable receipt window, so a lost
-- response can be retried with the same claim key before cleanup.
CREATE FUNCTION identity.prune_expired_key_packages(
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
        RAISE EXCEPTION 'key package retention cutoff is invalid'
            USING ERRCODE = '22003';
    END IF;
    IF maximum_rows NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'key package retention batch is invalid'
            USING ERRCODE = '22023';
    END IF;

    PERFORM set_config('identity.key_package_retention_prune', 'on', true);
    WITH expired_packages AS MATERIALIZED (
        SELECT package_id
          FROM identity.key_packages
         WHERE retention_until_ms <= target_cutoff_ms
         ORDER BY retention_until_ms, package_id
         LIMIT maximum_rows
         FOR UPDATE SKIP LOCKED
    ), deleted_claim_receipts AS (
        DELETE FROM identity.key_package_claim_receipts AS receipt
         USING expired_packages AS expired
         WHERE receipt.package_id = expired.package_id
         RETURNING
             receipt.claimant_identity_id,
             receipt.claimant_device_id,
             receipt.idempotency_key_hash
    ), deleted_claims AS (
        DELETE FROM identity.key_package_claims AS claim
         USING deleted_claim_receipts AS receipt
         WHERE receipt.claimant_identity_id = claim.claimant_identity_id
           AND receipt.claimant_device_id = claim.claimant_device_id
           AND receipt.idempotency_key_hash = claim.idempotency_key_hash
         RETURNING 1
    ), deleted_publish_claims AS (
        DELETE FROM identity.key_package_publish_claims AS claim
         USING expired_packages AS expired
         WHERE claim.package_id = expired.package_id
         RETURNING 1
    ), deleted_packages AS (
        DELETE FROM identity.key_packages AS package
         USING expired_packages AS expired
         WHERE package.package_id = expired.package_id
         RETURNING 1
    )
    SELECT count(*) INTO removed FROM deleted_packages;
    RETURN removed;
END
$$;

CREATE TRIGGER identity_key_packages_transition
BEFORE INSERT OR UPDATE OR DELETE ON identity.key_packages
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_key_package_transition();

CREATE TRIGGER identity_key_package_publish_claims_append_only
BEFORE UPDATE OR DELETE ON identity.key_package_publish_claims
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_key_package_immutable_or_prunable();

CREATE TRIGGER identity_key_package_claims_append_only
BEFORE UPDATE OR DELETE ON identity.key_package_claims
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_key_package_immutable_or_prunable();

CREATE TRIGGER identity_key_package_claim_receipts_append_only
BEFORE UPDATE OR DELETE ON identity.key_package_claim_receipts
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_key_package_immutable_or_prunable();

ALTER TABLE identity.key_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.key_packages FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.key_packages
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER TABLE identity.key_package_publish_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.key_package_publish_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.key_package_publish_claims
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER TABLE identity.key_package_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.key_package_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.key_package_claims
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER TABLE identity.key_package_claim_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.key_package_claim_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.key_package_claim_receipts
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

DO $grant$
BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON identity.key_packages TO dtx_identity_runtime;
        GRANT SELECT, INSERT ON identity.key_package_publish_claims TO dtx_identity_runtime;
        GRANT SELECT, INSERT ON identity.key_package_claims TO dtx_identity_runtime;
        GRANT SELECT, INSERT ON identity.key_package_claim_receipts TO dtx_identity_runtime;
        GRANT EXECUTE ON FUNCTION identity.prune_expired_key_packages(bigint, integer)
            TO dtx_identity_runtime;
    END IF;
END
$grant$;

REVOKE ALL ON FUNCTION identity.key_package_retention_prune_authorized() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.enforce_key_package_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.enforce_key_package_immutable_or_prunable() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.prune_expired_key_packages(bigint, integer) FROM PUBLIC;
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
