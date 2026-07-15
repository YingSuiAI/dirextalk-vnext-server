-- V29: durable Owner-side ingress receipts for isolated AgentRoute Runs.
--
-- `route_id` is the MLS/data-plane conversation recorded on agent_runs;
-- `source_conversation_id` is retained here only for grant authorization and
-- audit.  No prompt, MLS ciphertext, mailbox descriptor, capability, or
-- Connector credential is stored in this control-plane relation.

CREATE TABLE agent.agent_route_run_operations (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    run_id uuid NOT NULL,
    source_conversation_id uuid NOT NULL,
    route_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    request_event_id uuid NOT NULL,
    grant_version bigint NOT NULL,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    owner_session_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    committed_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT agent_route_run_operations_route_event_unique
        UNIQUE (tenant_id, route_id, request_event_id),
    CONSTRAINT agent_route_run_operations_run_fk
        FOREIGN KEY (tenant_id, run_id)
        REFERENCES agent.agent_runs (tenant_id, run_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_run_operations_grant_version_fk
        FOREIGN KEY (tenant_id, source_conversation_id, installation_id, grant_version)
        REFERENCES agent.conversation_grant_versions
            (tenant_id, conversation_id, installation_id, grant_version)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_run_operations_ids_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(operation_id)
        AND system.is_uuid_v7(run_id)
        AND system.is_uuid_v7(source_conversation_id)
        AND system.is_uuid_v7(route_id)
        AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(request_event_id)
        AND system.is_uuid_v7(owner_device_id)
        AND system.is_uuid_v7(owner_session_id)
        AND agent.is_public_id(owner_identity_id, 'dtxi1')
    ),
    CONSTRAINT agent_route_run_operations_values_valid CHECK (
        source_conversation_id <> route_id
        AND grant_version BETWEEN 1 AND 9007199254740991
        AND octet_length(request_digest) = 32
        AND octet_length(receipt_bytes) BETWEEN 1 AND 65536
        AND octet_length(receipt_digest) = 32
        AND committed_at_ms BETWEEN 0 AND 253402300799999
    )
);

CREATE INDEX agent_route_run_operations_route_idx
    ON agent.agent_route_run_operations (tenant_id, route_id, committed_at_ms, operation_id);

CREATE TRIGGER agent_route_run_operations_append_only
BEFORE UPDATE OR DELETE ON agent.agent_route_run_operations
FOR EACH ROW EXECUTE FUNCTION agent.reject_immutable_mutation();

ALTER TABLE agent.agent_route_run_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_route_run_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_route_run_operations
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        -- Row locks used by exact replay need UPDATE privilege; the append-only
        -- trigger still rejects every actual UPDATE or DELETE.
        GRANT SELECT, INSERT, UPDATE ON agent.agent_route_run_operations TO dtx_agent_runtime;
    END IF;
END
$grant$;
