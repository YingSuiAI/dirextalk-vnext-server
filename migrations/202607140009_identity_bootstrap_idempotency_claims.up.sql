-- Bootstrap idempotency is global only within the dedicated HTTP bootstrap
-- namespace. Keeping its claim separate from identity.command_receipts
-- preserves the established per-identity append contract for all other
-- identity-log commands and makes upgrades safe for existing receipt rows.
--
-- The deferred FK means a claim, its initial log head, command receipt, and
-- outbox row commit or roll back together. A response loss can therefore
-- replay one durable result, while a different identity or body using the
-- same bootstrap key is rejected before it can create another identity.
CREATE TABLE identity.bootstrap_idempotency_claims (
    idempotency_key_hash bytea PRIMARY KEY,
    identity_id text NOT NULL,
    request_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT identity_bootstrap_idempotency_claims_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_bootstrap_idempotency_claims_key_hash_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT identity_bootstrap_idempotency_claims_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT identity_bootstrap_idempotency_claims_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TRIGGER identity_bootstrap_idempotency_claims_immutable
BEFORE UPDATE OR DELETE ON identity.bootstrap_idempotency_claims
FOR EACH ROW
EXECUTE FUNCTION identity.reject_immutable_mutation();

ALTER TABLE identity.bootstrap_idempotency_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.bootstrap_idempotency_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.bootstrap_idempotency_claims
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

-- Fresh hosts may create the non-owner runtime group after migrations, but an
-- IM1b upgrade already has it. Grant only the immutable claim capabilities
-- when that group exists so an upgraded node can reconnect immediately.
DO $grant$
BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON identity.bootstrap_idempotency_claims
            TO dtx_identity_runtime;
    END IF;
END
$grant$;
