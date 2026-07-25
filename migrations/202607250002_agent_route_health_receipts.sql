-- Durable, tenant-scoped Route Health request/receipt ledger.
-- Request and receipt bytes remain opaque to SQL; only digests, fences and
-- monotonic native revisions are indexed.  Exact retries return the stored
-- receipt without advancing the head.
CREATE TABLE agent.agent_route_health_receipts (
    tenant_id uuid NOT NULL,
    route_id uuid NOT NULL,
    nonce bytea NOT NULL,
    request_id uuid NOT NULL,
    status_revision bigint NOT NULL,
    request_digest bytea NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    observation_revision bigint NOT NULL,
    observed_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, route_id, nonce),
    CONSTRAINT agent_route_health_receipts_route_fk
        FOREIGN KEY (tenant_id, route_id)
        REFERENCES agent.agent_route_binding_heads (tenant_id, route_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_health_receipts_request_unique
        UNIQUE (tenant_id, route_id, request_id, status_revision),
    CONSTRAINT agent_route_health_receipts_shape CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(route_id)
        AND system.is_uuid_v7(request_id)
        AND octet_length(nonce) = 32
        AND octet_length(request_digest) = 32
        AND octet_length(receipt_bytes) BETWEEN 1 AND 65536
        AND octet_length(receipt_digest) = 32
        AND status_revision > 0
        AND observation_revision > 0
        AND observed_at_ms BETWEEN 0 AND 253402300799999
        AND expires_at_ms > observed_at_ms
        AND expires_at_ms <= 253402300799999
        AND created_at_ms BETWEEN 0 AND 253402300799999
    )
);

CREATE UNIQUE INDEX agent_route_health_receipts_request_digest_unique
    ON agent.agent_route_health_receipts (tenant_id, route_id, request_id, request_digest);

CREATE INDEX agent_route_health_receipts_ttl_idx
    ON agent.agent_route_health_receipts (expires_at_ms);

CREATE TABLE agent.agent_route_health_heads (
    tenant_id uuid NOT NULL,
    route_id uuid NOT NULL,
    observation_revision bigint NOT NULL,
    status_revision bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, route_id),
    CONSTRAINT agent_route_health_heads_route_fk
        FOREIGN KEY (tenant_id, route_id)
        REFERENCES agent.agent_route_binding_heads (tenant_id, route_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_health_heads_values_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(route_id)
        AND observation_revision > 0
        AND status_revision > 0
        AND updated_at_ms BETWEEN 0 AND 253402300799999
    )
);

ALTER TABLE agent.agent_route_health_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_route_health_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_route_health_receipts
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.agent_route_health_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_route_health_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_route_health_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.agent_route_health_receipts, agent.agent_route_health_heads FROM PUBLIC;
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON agent.agent_route_health_receipts TO dtx_agent_runtime;
        GRANT SELECT, INSERT, UPDATE ON agent.agent_route_health_heads TO dtx_agent_runtime;
    END IF;
END
$grant$;
