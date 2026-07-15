-- V27: narrow Owner authorization for private-conversation Agent grants.
-- The Agent runtime must never receive direct SELECT access to group
-- membership tables merely to check the conversation owner at this boundary.

CREATE FUNCTION groups.private_conversation_owner_authorized(
    requested_tenant_id uuid,
    requested_conversation_id uuid,
    requested_owner_identity_id text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, groups, system
AS $$
BEGIN
    -- The caller's tenant context is still authoritative even though this
    -- function runs with the schema owner's narrowly scoped read authority.
    IF requested_tenant_id IS DISTINCT FROM system.current_tenant_id() THEN
        RETURN false;
    END IF;

    PERFORM 1
      FROM groups.policy_heads
     WHERE tenant_id = requested_tenant_id
       AND scope_kind = 'private_conversation'
       AND scope_id = requested_conversation_id::text
       AND owner_identity_id = requested_owner_identity_id
     FOR SHARE;
    RETURN FOUND;
END
$$;

REVOKE ALL ON FUNCTION groups.private_conversation_owner_authorized(uuid, uuid, text) FROM PUBLIC;

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA groups TO dtx_agent_runtime;
        GRANT EXECUTE ON FUNCTION groups.private_conversation_owner_authorized(uuid, uuid, text)
            TO dtx_agent_runtime;
    END IF;
END
$grant$;

-- Durable receipts keep exact idempotent replay independent of the mutable
-- grant head.  This relation is deliberately agent-local; it does not widen
-- access to any groups relation.
CREATE TABLE agent.conversation_grant_owner_operations (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    action text NOT NULL,
    request_digest bytea NOT NULL,
    grant_id uuid NOT NULL,
    grant_version bigint NOT NULL,
    revoked boolean NOT NULL,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    owner_session_id uuid NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    committed_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT conversation_grant_owner_operations_grant_version_fk
        FOREIGN KEY (tenant_id, conversation_id, installation_id, grant_version, grant_id)
        REFERENCES agent.conversation_grant_versions
            (tenant_id, conversation_id, installation_id, grant_version, grant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_grant_owner_operations_ids_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(operation_id)
        AND system.is_uuid_v7(conversation_id)
        AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(grant_id)
        AND system.is_uuid_v7(owner_device_id)
        AND system.is_uuid_v7(owner_session_id)
        AND agent.is_public_id(owner_identity_id, 'dtxi1')
    ),
    CONSTRAINT conversation_grant_owner_operations_values_valid CHECK (
        action IN ('grant', 'revoke')
        AND octet_length(request_digest) = 32
        AND grant_version BETWEEN 1 AND 9007199254740991
        AND octet_length(receipt_bytes) BETWEEN 1 AND 65536
        AND octet_length(receipt_digest) = 32
        AND committed_at_ms BETWEEN 0 AND 253402300799999
    )
);

CREATE TRIGGER conversation_grant_owner_operations_append_only
BEFORE UPDATE OR DELETE ON agent.conversation_grant_owner_operations
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

ALTER TABLE agent.conversation_grant_owner_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.conversation_grant_owner_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.conversation_grant_owner_operations
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON agent.conversation_grant_owner_operations
            TO dtx_agent_runtime;
    END IF;
END
$grant$;
