-- QR enrollment is a candidate-held capability workflow, not a second
-- identity authority. PostgreSQL retains only a domain-separated 32-byte
-- capability hash and the candidate device's public keys. The normal signed
-- identity log remains the certificate/status source of truth.
CREATE TABLE identity.device_enrollment_challenges (
    challenge_id uuid PRIMARY KEY,
    creation_idempotency_key_hash bytea NOT NULL UNIQUE,
    identity_id text NOT NULL,
    target_device_id uuid NOT NULL,
    target_device_signing_key bytea NOT NULL,
    target_device_encryption_key bytea NOT NULL,
    capability_hash bytea NOT NULL,
    request_digest bytea NOT NULL,
    state text NOT NULL DEFAULT 'open',
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    approved_at_ms bigint,
    cancelled_at_ms bigint,
    approval_request_digest bytea,
    approver_device_id uuid,
    approver_session_id uuid,
    approved_head_sequence bigint,
    approved_head_hash bytea,
    retention_until_ms bigint NOT NULL,
    CONSTRAINT identity_device_enrollment_challenges_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_device_enrollment_challenges_creation_key_size
        CHECK (octet_length(creation_idempotency_key_hash) = 32),
    CONSTRAINT identity_device_enrollment_challenges_target_signing_key_size
        CHECK (octet_length(target_device_signing_key) = 32),
    CONSTRAINT identity_device_enrollment_challenges_target_encryption_key_size
        CHECK (octet_length(target_device_encryption_key) = 32),
    CONSTRAINT identity_device_enrollment_challenges_target_keys_distinct
        CHECK (target_device_signing_key <> target_device_encryption_key),
    CONSTRAINT identity_device_enrollment_challenges_capability_hash_size
        CHECK (octet_length(capability_hash) = 32),
    CONSTRAINT identity_device_enrollment_challenges_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT identity_device_enrollment_challenges_state_valid
        CHECK (state IN ('open', 'approved', 'cancelled')),
    CONSTRAINT identity_device_enrollment_challenges_time_valid
        CHECK (
            created_at_ms BETWEEN -62135596800000 AND 253402300799999
            AND expires_at_ms BETWEEN created_at_ms AND 253402300799999
            AND retention_until_ms BETWEEN created_at_ms AND 253402301699999
        ),
    CONSTRAINT identity_device_enrollment_challenges_state_consistent
        CHECK (
            (
                state = 'open'
                AND approved_at_ms IS NULL
                AND cancelled_at_ms IS NULL
                AND approval_request_digest IS NULL
                AND approver_device_id IS NULL
                AND approver_session_id IS NULL
                AND approved_head_sequence IS NULL
                AND approved_head_hash IS NULL
                AND retention_until_ms = expires_at_ms
            )
            OR (
                state = 'cancelled'
                AND cancelled_at_ms BETWEEN created_at_ms AND expires_at_ms
                AND approved_at_ms IS NULL
                AND approval_request_digest IS NULL
                AND approver_device_id IS NULL
                AND approver_session_id IS NULL
                AND approved_head_sequence IS NULL
                AND approved_head_hash IS NULL
                AND retention_until_ms = expires_at_ms
            )
            OR (
                state = 'approved'
                AND approved_at_ms BETWEEN created_at_ms AND expires_at_ms
                AND cancelled_at_ms IS NULL
                AND octet_length(approval_request_digest) = 32
                AND approver_device_id IS NOT NULL
                AND approver_session_id IS NOT NULL
                AND approved_head_sequence BETWEEN 1 AND 9007199254740991
                AND octet_length(approved_head_hash) = 32
                AND retention_until_ms = approved_at_ms + 900000
            )
        )
);

-- Status polling and security-definer retention both traverse this bounded
-- timeline. Runtime writers never receive DELETE on the relation.
CREATE INDEX identity_device_enrollment_challenges_retention_idx
    ON identity.device_enrollment_challenges (retention_until_ms, challenge_id);

CREATE FUNCTION identity.device_enrollment_retention_prune_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT identity.identity_owner_authorized()
       AND COALESCE(
           current_setting('identity.device_enrollment_retention_prune', true),
           ''
       ) = 'on'
$$;

CREATE FUNCTION identity.enforce_device_enrollment_challenge_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'open'
           OR NEW.approved_at_ms IS NOT NULL
           OR NEW.cancelled_at_ms IS NOT NULL
           OR NEW.approval_request_digest IS NOT NULL
           OR NEW.approver_device_id IS NOT NULL
           OR NEW.approver_session_id IS NOT NULL
           OR NEW.approved_head_sequence IS NOT NULL
           OR NEW.approved_head_hash IS NOT NULL
           OR NEW.retention_until_ms <> NEW.expires_at_ms THEN
            RAISE EXCEPTION 'device enrollment challenge must enter open'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF identity.device_enrollment_retention_prune_authorized() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'device enrollment challenge cannot be deleted'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state <> 'open'
       OR NEW.state NOT IN ('approved', 'cancelled')
       OR OLD.challenge_id IS DISTINCT FROM NEW.challenge_id
       OR OLD.creation_idempotency_key_hash IS DISTINCT FROM NEW.creation_idempotency_key_hash
       OR OLD.identity_id IS DISTINCT FROM NEW.identity_id
       OR OLD.target_device_id IS DISTINCT FROM NEW.target_device_id
       OR OLD.target_device_signing_key IS DISTINCT FROM NEW.target_device_signing_key
       OR OLD.target_device_encryption_key IS DISTINCT FROM NEW.target_device_encryption_key
       OR OLD.capability_hash IS DISTINCT FROM NEW.capability_hash
       OR OLD.request_digest IS DISTINCT FROM NEW.request_digest
       OR OLD.created_at_ms IS DISTINCT FROM NEW.created_at_ms
       OR OLD.expires_at_ms IS DISTINCT FROM NEW.expires_at_ms THEN
        RAISE EXCEPTION 'device enrollment challenge transition is invalid'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.state = 'cancelled' THEN
        IF NEW.cancelled_at_ms IS NULL
           OR NEW.approved_at_ms IS NOT NULL
           OR NEW.approval_request_digest IS NOT NULL
           OR NEW.approver_device_id IS NOT NULL
           OR NEW.approver_session_id IS NOT NULL
           OR NEW.approved_head_sequence IS NOT NULL
           OR NEW.approved_head_hash IS NOT NULL
           OR NEW.retention_until_ms <> NEW.expires_at_ms THEN
            RAISE EXCEPTION 'device enrollment cancellation is invalid'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.approved_at_ms IS NULL
       OR NEW.cancelled_at_ms IS NOT NULL
       OR NEW.approval_request_digest IS NULL
       OR NEW.approver_device_id IS NULL
       OR NEW.approver_session_id IS NULL
       OR NEW.approved_head_sequence IS NULL
       OR NEW.approved_head_hash IS NULL
       OR NEW.retention_until_ms <> NEW.approved_at_ms + 900000 THEN
        RAISE EXCEPTION 'device enrollment approval is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

-- Approved rows stay available through the initial device-session window;
-- open/cancelled rows are removed only after their fixed expiry. This function
-- is bounded and security-definer so the runtime role cannot delete history.
CREATE FUNCTION identity.prune_expired_device_enrollment_challenges(
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

CREATE TRIGGER identity_device_enrollment_challenges_transition
BEFORE INSERT OR UPDATE OR DELETE ON identity.device_enrollment_challenges
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_device_enrollment_challenge_transition();

ALTER TABLE identity.device_enrollment_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.device_enrollment_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.device_enrollment_challenges
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

DO $grant$
BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON identity.device_enrollment_challenges
            TO dtx_identity_runtime;
        GRANT EXECUTE ON FUNCTION identity.prune_expired_device_enrollment_challenges(bigint, integer)
            TO dtx_identity_runtime;
    END IF;
END
$grant$;

REVOKE ALL ON FUNCTION identity.device_enrollment_retention_prune_authorized() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.enforce_device_enrollment_challenge_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.prune_expired_device_enrollment_challenges(bigint, integer) FROM PUBLIC;
