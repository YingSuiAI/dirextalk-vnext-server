CREATE TABLE identity.deployment_binding_tickets (
    ticket_id uuid PRIMARY KEY,
    binding_id uuid NOT NULL UNIQUE,
    deployment_operation_id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL,
    server_origin text NOT NULL,
    tls_root_ca_pem text NOT NULL,
    tls_root_ca_sha256 bytea NOT NULL,
    capability_digest bytea NOT NULL UNIQUE,
    status_token_digest bytea NOT NULL UNIQUE,
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    redeemed_at_ms bigint,
    state text NOT NULL,
    revision bigint NOT NULL DEFAULT 1,
    CONSTRAINT deployment_binding_ticket_ids_v7 CHECK (
        system.is_uuid_v7(ticket_id)
        AND system.is_uuid_v7(binding_id)
        AND system.is_uuid_v7(deployment_operation_id)
        AND system.is_uuid_v7(tenant_id)
    ),
    CONSTRAINT deployment_binding_ticket_origin CHECK (server_origin ~ '^https://[^/?#@]+$'),
    CONSTRAINT deployment_binding_ticket_ca CHECK (
        octet_length(tls_root_ca_pem) BETWEEN 1 AND 12288
        AND octet_length(tls_root_ca_sha256)=32
    ),
    CONSTRAINT deployment_binding_ticket_digests CHECK (
        octet_length(capability_digest)=32 AND octet_length(status_token_digest)=32
    ),
    CONSTRAINT deployment_binding_ticket_lifetime CHECK (
        expires_at_ms BETWEEN issued_at_ms+1 AND issued_at_ms+900000
    ),
    CONSTRAINT deployment_binding_ticket_state CHECK (
        state IN ('issued','redeemed','expired','revoked')
    ),
    CONSTRAINT deployment_binding_ticket_shape CHECK (
        (state='issued' AND redeemed_at_ms IS NULL)
        OR (state='redeemed' AND redeemed_at_ms IS NOT NULL)
        OR state IN ('expired','revoked')
    ),
    CONSTRAINT deployment_binding_ticket_revision CHECK (revision > 0)
);

ALTER TABLE identity.deployment_binding_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.deployment_binding_tickets FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.deployment_binding_tickets
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

DO $grant$ BEGIN
  IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE ON identity.deployment_binding_tickets TO dtx_identity_runtime;
  END IF;
END $grant$;
