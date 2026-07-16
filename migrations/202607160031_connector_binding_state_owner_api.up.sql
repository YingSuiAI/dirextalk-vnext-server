-- V31: durable Owner receipts for Connector Binding enable/disable commands.
-- A committed Binding transition and its exact replay receipt share the same
-- tenant transaction, so a lost HTTP response cannot cause a second state
-- transition or reinterpret an already committed operation.

CREATE TABLE agent.connector_binding_state_owner_operations (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    action text NOT NULL,
    request_digest bytea NOT NULL,
    result_state text NOT NULL,
    result_revision bigint NOT NULL,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    owner_session_id uuid NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    committed_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT connector_binding_state_owner_operations_binding_fk
        FOREIGN KEY (tenant_id, binding_id)
        REFERENCES agent.connector_bindings (tenant_id, binding_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_binding_state_owner_operations_ids_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(operation_id)
        AND system.is_uuid_v7(binding_id)
        AND system.is_uuid_v7(owner_device_id)
        AND system.is_uuid_v7(owner_session_id)
        AND agent.is_public_id(owner_identity_id, 'dtxi1')
    ),
    CONSTRAINT connector_binding_state_owner_operations_values_valid CHECK (
        action IN ('enable', 'disable')
        AND octet_length(request_digest) = 32
        AND result_state IN ('enabled', 'disabled')
        AND result_revision BETWEEN 1 AND 9007199254740991
        AND octet_length(receipt_bytes) BETWEEN 1 AND 65536
        AND octet_length(receipt_digest) = 32
        AND committed_at_ms BETWEEN 0 AND 253402300799999
    )
);

CREATE TRIGGER connector_binding_state_owner_operations_append_only
BEFORE UPDATE OR DELETE ON agent.connector_binding_state_owner_operations
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

ALTER TABLE agent.connector_binding_state_owner_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_binding_state_owner_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_binding_state_owner_operations
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON agent.connector_binding_state_owner_operations
            TO dtx_agent_runtime;
        -- The Owner command may only transition the existing Binding aggregate.
        -- These are the exact rows touched by BindingSetRepository; RLS keeps
        -- every read and write inside the authenticated tenant transaction.
        GRANT SELECT ON agent.installations, agent.agent_devices,
            agent.connector_instances, agent.connector_conformance,
            agent.installation_routing_policies, agent.connector_bindings,
            agent.binding_set_heads
            TO dtx_agent_runtime;
        GRANT INSERT ON agent.connector_conformance,
            agent.installation_routing_policies, agent.connector_bindings,
            agent.binding_set_heads
            TO dtx_agent_runtime;
        GRANT UPDATE ON agent.connector_bindings, agent.binding_set_heads
            TO dtx_agent_runtime;
    END IF;
END
$grant$;
