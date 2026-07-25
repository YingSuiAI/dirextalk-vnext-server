-- V47 immutable Completion V2 signing descriptors and receipts.
CREATE TABLE identity.history_recovery_completion_descriptors (
    descriptor_digest bytea PRIMARY KEY CHECK (octet_length(descriptor_digest)=32),
    key_id uuid NOT NULL CHECK (messaging.is_uuid_v7(key_id)),
    public_key bytea NOT NULL CHECK (octet_length(public_key)=32),
    epoch bigint NOT NULL CHECK (epoch BETWEEN 1 AND 9007199254740991),
    rollback_floor_epoch bigint NOT NULL CHECK (rollback_floor_epoch BETWEEN 1 AND 9007199254740991),
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL CHECK (expires_at_ms>issued_at_ms),
    previous_descriptor_digest bytea CHECK (previous_descriptor_digest IS NULL OR octet_length(previous_descriptor_digest)=32),
    signature bytea NOT NULL CHECK (octet_length(signature)=64),
    descriptor_bytes bytea NOT NULL CHECK (octet_length(descriptor_bytes) BETWEEN 1 AND 2271),
    created_at_ms bigint NOT NULL,
    UNIQUE(epoch),
    CHECK (rollback_floor_epoch<=epoch)
);
CREATE TABLE identity.history_recovery_completion_key_head (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    descriptor_digest bytea NOT NULL REFERENCES identity.history_recovery_completion_descriptors(descriptor_digest),
    updated_at_ms bigint NOT NULL
);
CREATE TABLE identity.history_recovery_completions_v2 (
    identity_id text NOT NULL REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
    completion_id uuid NOT NULL CHECK (messaging.is_uuid_v7(completion_id)),
    candidate_device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(candidate_device_id)),
    request_id uuid NOT NULL CHECK (messaging.is_uuid_v7(request_id)),
    grant_digest bytea NOT NULL CHECK (octet_length(grant_digest)=32),
    idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest)=32),
    completion_digest bytea NOT NULL CHECK (octet_length(completion_digest)=32),
    completion_bytes bytea NOT NULL CHECK (octet_length(completion_bytes) BETWEEN 1 AND 3593836),
    descriptor_digest bytea NOT NULL CHECK (octet_length(descriptor_digest)=32),
    descriptor_bytes bytea NOT NULL CHECK (octet_length(descriptor_bytes) BETWEEN 1 AND 2271),
    receipt_digest bytea NOT NULL CHECK (octet_length(receipt_digest)=32),
    receipt_bytes bytea NOT NULL CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 3770),
    accepted_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY(identity_id,completion_id),
    UNIQUE(identity_id,idempotency_digest),
    UNIQUE(identity_id,completion_digest),
    UNIQUE(identity_id,request_id),
    FOREIGN KEY(descriptor_digest) REFERENCES identity.history_recovery_completion_descriptors(descriptor_digest)
);
ALTER TABLE identity.history_recovery_completion_descriptors ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.history_recovery_completion_descriptors FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.history_recovery_completion_key_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.history_recovery_completion_key_head FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.history_recovery_completions_v2 ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.history_recovery_completions_v2 FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.history_recovery_completion_descriptors USING (identity.identity_runtime_authorized()) WITH CHECK (identity.identity_runtime_authorized());
CREATE POLICY identity_runtime_only ON identity.history_recovery_completion_key_head USING (identity.identity_runtime_authorized()) WITH CHECK (identity.identity_runtime_authorized());
CREATE POLICY identity_runtime_only ON identity.history_recovery_completions_v2 USING (identity.identity_runtime_authorized()) WITH CHECK (identity.identity_runtime_authorized());
DO $grants$ BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        GRANT SELECT,INSERT ON identity.history_recovery_completion_descriptors TO dtx_identity_runtime;
        GRANT SELECT,INSERT ON identity.history_recovery_completion_key_head TO dtx_identity_runtime;
        GRANT UPDATE(descriptor_digest,updated_at_ms) ON identity.history_recovery_completion_key_head TO dtx_identity_runtime;
        GRANT SELECT,INSERT ON identity.history_recovery_completions_v2 TO dtx_identity_runtime;
    END IF;
END $grants$;
