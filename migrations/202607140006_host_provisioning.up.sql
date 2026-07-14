CREATE TABLE agent.host_provisioning_operations (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    host_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT host_provisioning_operations_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_provisioning_operations_host_fk
        FOREIGN KEY (tenant_id, host_id)
        REFERENCES agent.hosts (tenant_id, host_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_provisioning_operations_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT host_provisioning_operations_operation_id_v7
        CHECK (system.is_uuid_v7(operation_id)),
    CONSTRAINT host_provisioning_operations_host_id_v7
        CHECK (system.is_uuid_v7(host_id)),
    CONSTRAINT host_provisioning_operations_request_digest_valid
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT host_provisioning_operations_created_at_valid
        CHECK (created_at_ms BETWEEN 0 AND 9007199254740991)
);

CREATE TRIGGER host_provisioning_operations_append_only
BEFORE UPDATE OR DELETE ON agent.host_provisioning_operations
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

ALTER TABLE agent.host_provisioning_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.host_provisioning_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.host_provisioning_operations
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.host_provisioning_operations FROM PUBLIC;
