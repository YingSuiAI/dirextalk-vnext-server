-- Device sessions are short-lived transport credentials, not another source
-- of identity authority. The signed identity log remains the sole device
-- certificate/status source; every authenticated use rechecks that projection.
-- Raw challenge nonces and session secrets are never stored, only
-- domain-separated SHA-256 digests.
CREATE TABLE identity.device_session_challenges (
    challenge_id uuid PRIMARY KEY,
    identity_id text NOT NULL,
    device_id uuid NOT NULL,
    nonce_hash bytea NOT NULL,
    audience text NOT NULL,
    state text NOT NULL DEFAULT 'open',
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    session_expires_at_ms bigint NOT NULL,
    consumed_at_ms bigint,
    session_id uuid UNIQUE,
    CONSTRAINT identity_device_session_challenges_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_device_session_challenges_nonce_hash_size
        CHECK (octet_length(nonce_hash) = 32),
    CONSTRAINT identity_device_session_challenges_audience_valid
        CHECK (
            octet_length(audience) BETWEEN 1 AND 256
            AND audience ~ '^[!-~]+$'
        ),
    CONSTRAINT identity_device_session_challenges_state_valid
        CHECK (state IN ('open', 'consumed')),
    CONSTRAINT identity_device_session_challenges_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT identity_device_session_challenges_expiry_valid
        CHECK (
            expires_at_ms BETWEEN created_at_ms AND 253402300799999
            AND session_expires_at_ms BETWEEN expires_at_ms AND 253402300799999
        ),
    CONSTRAINT identity_device_session_challenges_consumption_consistent
        CHECK (
            (state = 'open' AND consumed_at_ms IS NULL AND session_id IS NULL)
            OR (
                state = 'consumed'
                AND consumed_at_ms BETWEEN created_at_ms AND 253402300799999
                AND session_id IS NOT NULL
            )
        )
);

CREATE TABLE identity.device_sessions (
    session_id uuid PRIMARY KEY,
    identity_id text NOT NULL,
    device_id uuid NOT NULL,
    challenge_id uuid NOT NULL UNIQUE,
    session_secret_hash bytea NOT NULL,
    issued_head_sequence bigint NOT NULL,
    issued_head_hash bytea NOT NULL,
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    CONSTRAINT identity_device_sessions_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_device_sessions_challenge_fk
        FOREIGN KEY (challenge_id)
        REFERENCES identity.device_session_challenges (challenge_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_device_sessions_secret_hash_size
        CHECK (octet_length(session_secret_hash) = 32),
    CONSTRAINT identity_device_sessions_head_sequence_safe
        CHECK (issued_head_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT identity_device_sessions_head_hash_size
        CHECK (octet_length(issued_head_hash) = 32),
    CONSTRAINT identity_device_sessions_time_valid
        CHECK (
            issued_at_ms BETWEEN -62135596800000 AND 253402300799999
            AND expires_at_ms BETWEEN issued_at_ms AND 253402300799999
        )
);

ALTER TABLE identity.device_session_challenges
    ADD CONSTRAINT identity_device_session_challenges_session_fk
    FOREIGN KEY (session_id)
    REFERENCES identity.device_sessions (session_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

-- This immutable global claim is deliberately independent of identity-log
-- command receipts. Session creation is a credential issuance command, not a
-- log append; one key cannot silently mint sessions for two identities.
CREATE TABLE identity.device_session_idempotency_claims (
    idempotency_key_hash bytea PRIMARY KEY,
    identity_id text NOT NULL,
    device_id uuid NOT NULL,
    challenge_id uuid NOT NULL,
    session_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT identity_device_session_idempotency_claims_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_device_session_idempotency_claims_challenge_fk
        FOREIGN KEY (challenge_id)
        REFERENCES identity.device_session_challenges (challenge_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_device_session_idempotency_claims_key_hash_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT identity_device_session_idempotency_claims_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT identity_device_session_idempotency_claims_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TABLE identity.device_session_receipts (
    idempotency_key_hash bytea PRIMARY KEY,
    identity_id text NOT NULL,
    device_id uuid NOT NULL,
    challenge_id uuid NOT NULL UNIQUE,
    session_id uuid NOT NULL UNIQUE,
    issued_head_sequence bigint NOT NULL,
    issued_head_hash bytea NOT NULL,
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    CONSTRAINT identity_device_session_receipts_claim_fk
        FOREIGN KEY (idempotency_key_hash)
        REFERENCES identity.device_session_idempotency_claims (idempotency_key_hash)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_device_session_receipts_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_device_session_receipts_challenge_fk
        FOREIGN KEY (challenge_id)
        REFERENCES identity.device_session_challenges (challenge_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_device_session_receipts_session_fk
        FOREIGN KEY (session_id)
        REFERENCES identity.device_sessions (session_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_device_session_receipts_head_sequence_safe
        CHECK (issued_head_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT identity_device_session_receipts_head_hash_size
        CHECK (octet_length(issued_head_hash) = 32),
    CONSTRAINT identity_device_session_receipts_time_valid
        CHECK (
            issued_at_ms BETWEEN -62135596800000 AND 253402300799999
            AND expires_at_ms BETWEEN issued_at_ms AND 253402300799999
        ),
    CONSTRAINT identity_device_session_receipts_bytes_bounded
        CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    CONSTRAINT identity_device_session_receipts_digest_size
        CHECK (octet_length(receipt_digest) = 32)
);

-- Keep the only untrusted entry point bounded per active device. Expired
-- rows are later removed only by the security-definer retention function
-- below; runtime writers themselves never receive DELETE.
CREATE INDEX identity_device_session_challenges_recent_idx
    ON identity.device_session_challenges (identity_id, device_id, created_at_ms DESC);

CREATE FUNCTION identity.device_session_retention_prune_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT identity.identity_owner_authorized()
       AND COALESCE(
           current_setting('identity.device_session_retention_prune', true),
           ''
       ) = 'on'
$$;

CREATE FUNCTION identity.enforce_device_session_immutable_or_prunable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND identity.device_session_retention_prune_authorized() THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'device session relation can only be pruned by retention'
        USING ERRCODE = '23514';
END
$$;

CREATE FUNCTION identity.enforce_device_session_challenge_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'open'
           OR NEW.consumed_at_ms IS NOT NULL
           OR NEW.session_id IS NOT NULL THEN
            RAISE EXCEPTION 'device session challenge must enter open'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF identity.device_session_retention_prune_authorized() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'device session challenge cannot be deleted'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state <> 'open'
       OR NEW.state <> 'consumed'
       OR OLD.challenge_id IS DISTINCT FROM NEW.challenge_id
       OR OLD.identity_id IS DISTINCT FROM NEW.identity_id
       OR OLD.device_id IS DISTINCT FROM NEW.device_id
       OR OLD.nonce_hash IS DISTINCT FROM NEW.nonce_hash
       OR OLD.audience IS DISTINCT FROM NEW.audience
       OR OLD.created_at_ms IS DISTINCT FROM NEW.created_at_ms
       OR OLD.expires_at_ms IS DISTINCT FROM NEW.expires_at_ms
       OR OLD.session_expires_at_ms IS DISTINCT FROM NEW.session_expires_at_ms
       OR NEW.consumed_at_ms IS NULL
       OR NEW.session_id IS NULL THEN
        RAISE EXCEPTION 'device session challenge transition is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

-- Session credentials are useful only while their expiry is in the future.
-- This function can be called by the non-owner runtime but runs as the schema
-- owner, sets a transaction-local trigger guard, and deletes only bounded
-- expired rows. It preserves exact idempotent replay until the session expiry,
-- then removes receipts/claims/sessions/challenges together.
CREATE FUNCTION identity.prune_expired_device_sessions(
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
    IF target_cutoff_ms NOT BETWEEN -62135596800000 AND 253402300799999 THEN
        RAISE EXCEPTION 'device session retention cutoff is invalid'
            USING ERRCODE = '22003';
    END IF;
    IF maximum_rows NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'device session retention batch is invalid'
            USING ERRCODE = '22023';
    END IF;

    PERFORM set_config('identity.device_session_retention_prune', 'on', true);

    WITH expired_sessions AS MATERIALIZED (
        SELECT session_id, challenge_id
          FROM identity.device_sessions
         WHERE expires_at_ms <= target_cutoff_ms
         ORDER BY expires_at_ms, session_id
         LIMIT maximum_rows
         FOR UPDATE SKIP LOCKED
    ),
    deleted_receipts AS (
        DELETE FROM identity.device_session_receipts AS receipt
         USING expired_sessions AS expired
         WHERE receipt.session_id = expired.session_id
         RETURNING 1
    ),
    deleted_claims AS (
        DELETE FROM identity.device_session_idempotency_claims AS claim
         USING expired_sessions AS expired
         WHERE claim.session_id = expired.session_id
         RETURNING 1
    ),
    deleted_challenges AS (
        DELETE FROM identity.device_session_challenges AS challenge
         USING expired_sessions AS expired
         WHERE challenge.challenge_id = expired.challenge_id
         RETURNING 1
    ),
    deleted_sessions AS (
        DELETE FROM identity.device_sessions AS session
         USING expired_sessions AS expired
         WHERE session.session_id = expired.session_id
         RETURNING 1
    )
    SELECT (SELECT count(*) FROM deleted_receipts)
         + (SELECT count(*) FROM deleted_claims)
         + (SELECT count(*) FROM deleted_challenges)
         + (SELECT count(*) FROM deleted_sessions)
      INTO removed;

    WITH expired_open_challenges AS MATERIALIZED (
        SELECT challenge_id
          FROM identity.device_session_challenges
         WHERE state = 'open' AND expires_at_ms <= target_cutoff_ms
         ORDER BY expires_at_ms, challenge_id
         LIMIT maximum_rows
         FOR UPDATE SKIP LOCKED
    ),
    deleted_open_challenges AS (
        DELETE FROM identity.device_session_challenges AS challenge
         USING expired_open_challenges AS expired
         WHERE challenge.challenge_id = expired.challenge_id
         RETURNING 1
    )
    SELECT removed + (SELECT count(*) FROM deleted_open_challenges)
      INTO removed;

    RETURN removed;
END
$$;

CREATE TRIGGER identity_device_session_challenges_transition
BEFORE INSERT OR UPDATE OR DELETE ON identity.device_session_challenges
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_device_session_challenge_transition();

CREATE TRIGGER identity_device_sessions_append_only
BEFORE UPDATE OR DELETE ON identity.device_sessions
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_device_session_immutable_or_prunable();

CREATE TRIGGER identity_device_session_idempotency_claims_append_only
BEFORE UPDATE OR DELETE ON identity.device_session_idempotency_claims
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_device_session_immutable_or_prunable();

CREATE TRIGGER identity_device_session_receipts_append_only
BEFORE UPDATE OR DELETE ON identity.device_session_receipts
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_device_session_immutable_or_prunable();

ALTER TABLE identity.device_session_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.device_session_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.device_session_challenges
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER TABLE identity.device_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.device_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.device_sessions
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER TABLE identity.device_session_idempotency_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.device_session_idempotency_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.device_session_idempotency_claims
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER TABLE identity.device_session_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.device_session_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.device_session_receipts
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

-- Existing deployments created this role after the base migration. Grant only
-- the narrow new relations when it is present; fresh test/host setup may grant
-- the same capability after migrations.
DO $grant$
BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON identity.device_session_challenges
            TO dtx_identity_runtime;
        GRANT SELECT, INSERT ON identity.device_sessions
            TO dtx_identity_runtime;
        GRANT SELECT, INSERT ON identity.device_session_idempotency_claims
            TO dtx_identity_runtime;
        GRANT SELECT, INSERT ON identity.device_session_receipts
            TO dtx_identity_runtime;
        GRANT EXECUTE ON FUNCTION identity.prune_expired_device_sessions(bigint, integer)
            TO dtx_identity_runtime;
    END IF;
END
$grant$;

REVOKE ALL ON FUNCTION identity.device_session_retention_prune_authorized() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.enforce_device_session_immutable_or_prunable() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.enforce_device_session_challenge_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.prune_expired_device_sessions(bigint, integer) FROM PUBLIC;
