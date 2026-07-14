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
