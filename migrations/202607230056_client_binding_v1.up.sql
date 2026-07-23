-- Authorization is represented only by a domain-separated digest.  This
-- identity-runtime relation is the one durable authority for a client import.
CREATE TABLE identity.client_bindings (
    binding_id uuid PRIMARY KEY,
    deployment_operation_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    server_origin text NOT NULL,
    tls_root_ca_sha256 bytea NOT NULL,
    authorization_digest bytea NOT NULL,
    artifact_digest bytea NOT NULL,
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    state text NOT NULL,
    identity_id text,
    device_id uuid,
    identity_request_digest bytea,
    identity_idempotency_key_hash bytea,
    consume_request_digest bytea,
    consume_idempotency_key_hash bytea,
    revision bigint NOT NULL DEFAULT 1,
    CONSTRAINT client_bindings_ids_v7 CHECK (system.is_uuid_v7(binding_id) AND system.is_uuid_v7(deployment_operation_id) AND system.is_uuid_v7(tenant_id)),
    CONSTRAINT client_bindings_origin CHECK (server_origin ~ '^https://[^/?#@]+$'),
    CONSTRAINT client_bindings_digest_lengths CHECK (octet_length(tls_root_ca_sha256)=32 AND octet_length(authorization_digest)=32 AND octet_length(artifact_digest)=32 AND (identity_request_digest IS NULL OR octet_length(identity_request_digest)=32) AND (identity_idempotency_key_hash IS NULL OR octet_length(identity_idempotency_key_hash)=32) AND (consume_request_digest IS NULL OR octet_length(consume_request_digest)=32) AND (consume_idempotency_key_hash IS NULL OR octet_length(consume_idempotency_key_hash)=32)),
    CONSTRAINT client_bindings_lifetime CHECK (expires_at_ms BETWEEN issued_at_ms+1 AND issued_at_ms+900000),
    CONSTRAINT client_bindings_state CHECK (state IN ('issued','identity_bound','consumed','expired','revoked')),
    CONSTRAINT client_bindings_shape CHECK ((state='issued' AND identity_id IS NULL AND device_id IS NULL AND identity_request_digest IS NULL AND identity_idempotency_key_hash IS NULL AND consume_request_digest IS NULL AND consume_idempotency_key_hash IS NULL) OR (state='identity_bound' AND identity_id IS NOT NULL AND device_id IS NULL AND identity_request_digest IS NOT NULL AND identity_idempotency_key_hash IS NOT NULL AND consume_request_digest IS NULL AND consume_idempotency_key_hash IS NULL) OR (state='consumed' AND identity_id IS NOT NULL AND device_id IS NOT NULL AND identity_request_digest IS NOT NULL AND identity_idempotency_key_hash IS NOT NULL AND consume_request_digest IS NOT NULL AND consume_idempotency_key_hash IS NOT NULL) OR state IN ('expired','revoked')),
    CONSTRAINT client_bindings_revision CHECK (revision > 0)
);
ALTER TABLE identity.client_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.client_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.client_bindings USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
DO $grant$ BEGIN
  IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE ON identity.client_bindings TO dtx_identity_runtime;
  END IF;
END $grant$;
