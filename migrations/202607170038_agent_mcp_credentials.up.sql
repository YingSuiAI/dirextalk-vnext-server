-- Short-lived, digest-only Agent MCP credentials.
--
-- Raw bearer material is generated and retained by the local peer operator.
-- The registered digest is exactly:
-- SHA-256("dirextalk.agent-mcp-token.v1\0" || raw_32_token_bytes).
-- The server stores only that digest and revalidates the complete
-- installation/binding/device/conversation scope on every request.

CREATE TABLE agent.mcp_credentials (
    tenant_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    token_digest bytea NOT NULL,
    installation_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    agent_device_id uuid NOT NULL,
    node_id text NOT NULL,
    conversation_id uuid NOT NULL,
    capability text NOT NULL,
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    revoked_at_ms bigint,
    PRIMARY KEY (tenant_id, credential_id),
    CONSTRAINT agent_mcp_credentials_token_digest_unique UNIQUE (token_digest),
    CONSTRAINT agent_mcp_credentials_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_mcp_credentials_installation_fk
        FOREIGN KEY (tenant_id, installation_id)
        REFERENCES agent.installations (tenant_id, installation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_mcp_credentials_binding_fk
        FOREIGN KEY (tenant_id, binding_id)
        REFERENCES agent.connector_bindings (tenant_id, binding_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_mcp_credentials_agent_device_fk
        FOREIGN KEY (tenant_id, installation_id, agent_device_id)
        REFERENCES agent.agent_devices (tenant_id, installation_id, agent_device_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_mcp_credentials_grant_fk
        FOREIGN KEY (tenant_id, conversation_id, installation_id)
        REFERENCES agent.conversation_grant_heads
            (tenant_id, conversation_id, installation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_mcp_credentials_ids_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(credential_id)
        AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(binding_id)
        AND system.is_uuid_v7(agent_device_id)
        AND system.is_uuid_v7(conversation_id)
    ),
    CONSTRAINT agent_mcp_credentials_digest_size
        CHECK (octet_length(token_digest) = 32),
    CONSTRAINT agent_mcp_credentials_node_id_valid CHECK (
        char_length(node_id) BETWEEN 1 AND 128
        AND octet_length(node_id) BETWEEN 1 AND 128
        AND node_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT agent_mcp_credentials_capability_exact
        CHECK (capability = 'mcp.references.v1'),
    CONSTRAINT agent_mcp_credentials_lifetime_valid CHECK (
        created_at_ms BETWEEN 0 AND 253402300799998
        AND expires_at_ms BETWEEN created_at_ms + 1
                              AND created_at_ms + 86400000
        AND expires_at_ms <= 253402300799999
        AND (revoked_at_ms IS NULL
             OR revoked_at_ms BETWEEN created_at_ms AND 253402300799999)
    )
);

CREATE INDEX agent_mcp_credentials_active_digest_idx
    ON agent.mcp_credentials (tenant_id, token_digest, expires_at_ms)
    WHERE revoked_at_ms IS NULL;
CREATE INDEX agent_mcp_credentials_binding_expiry_idx
    ON agent.mcp_credentials (tenant_id, binding_id, expires_at_ms)
    WHERE revoked_at_ms IS NULL;

CREATE FUNCTION agent.enforce_mcp_credential_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent MCP credentials cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.token_digest IS DISTINCT FROM OLD.token_digest
       OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
       OR NEW.binding_id IS DISTINCT FROM OLD.binding_id
       OR NEW.agent_device_id IS DISTINCT FROM OLD.agent_device_id
       OR NEW.node_id IS DISTINCT FROM OLD.node_id
       OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
       OR NEW.capability IS DISTINCT FROM OLD.capability
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
       OR OLD.revoked_at_ms IS NOT NULL
       OR NEW.revoked_at_ms IS NULL
    THEN
        RAISE EXCEPTION 'invalid Agent MCP credential transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER agent_mcp_credentials_transition
BEFORE UPDATE OR DELETE ON agent.mcp_credentials
FOR EACH ROW EXECUTE FUNCTION agent.enforce_mcp_credential_transition();

ALTER TABLE agent.mcp_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.mcp_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.mcp_credentials
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

-- Digest-only peer-operator registration seam. Locking the binding row makes
-- the two-live-credential rotation bound race-free.
CREATE FUNCTION agent.register_mcp_credential_digest(
    requested_tenant_id uuid,
    requested_credential_id uuid,
    requested_token_digest bytea,
    requested_installation_id uuid,
    requested_binding_id uuid,
    requested_agent_device_id uuid,
    requested_node_id text,
    requested_conversation_id uuid,
    requested_capability text,
    requested_created_at_ms bigint,
    requested_expires_at_ms bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, agent, system
AS $$
DECLARE
    active_count integer;
BEGIN
    IF requested_tenant_id IS DISTINCT FROM system.current_tenant_id() THEN
        RAISE EXCEPTION 'tenant scope rejected' USING ERRCODE = '42501';
    END IF;

    PERFORM 1
      FROM agent.connector_bindings
     WHERE tenant_id = requested_tenant_id
       AND binding_id = requested_binding_id
       AND installation_id = requested_installation_id
       AND agent_device_id = requested_agent_device_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'binding scope rejected' USING ERRCODE = '23503';
    END IF;

    SELECT count(*)
      INTO active_count
      FROM agent.mcp_credentials
     WHERE tenant_id = requested_tenant_id
       AND binding_id = requested_binding_id
       AND revoked_at_ms IS NULL
       AND expires_at_ms > requested_created_at_ms;
    IF active_count >= 2 THEN
        RAISE EXCEPTION 'at most two live Agent MCP credentials are allowed'
            USING ERRCODE = '23514';
    END IF;

    INSERT INTO agent.mcp_credentials (
        tenant_id, credential_id, token_digest, installation_id, binding_id,
        agent_device_id, node_id, conversation_id, capability,
        created_at_ms, expires_at_ms, revoked_at_ms
    ) VALUES (
        requested_tenant_id, requested_credential_id, requested_token_digest,
        requested_installation_id, requested_binding_id,
        requested_agent_device_id, requested_node_id,
        requested_conversation_id, requested_capability,
        requested_created_at_ms, requested_expires_at_ms, NULL
    );
END
$$;

CREATE FUNCTION agent.revoke_mcp_credential_digest(
    requested_tenant_id uuid,
    requested_credential_id uuid,
    requested_token_digest bytea,
    requested_revoked_at_ms bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, agent, system
AS $$
BEGIN
    IF requested_tenant_id IS DISTINCT FROM system.current_tenant_id() THEN
        RAISE EXCEPTION 'tenant scope rejected' USING ERRCODE = '42501';
    END IF;
    UPDATE agent.mcp_credentials
       SET revoked_at_ms = requested_revoked_at_ms
     WHERE tenant_id = requested_tenant_id
       AND credential_id = requested_credential_id
       AND token_digest = requested_token_digest
       AND revoked_at_ms IS NULL;
    RETURN FOUND;
END
$$;

-- Runtime authentication returns only the exact authorized conversation ID.
-- All mutable authority facts are joined and revalidated on every invocation.
CREATE FUNCTION agent.authenticate_mcp_reference_credential(
    requested_tenant_id uuid,
    requested_token_digest bytea,
    requested_node_id text,
    requested_now_ms bigint
)
RETURNS TABLE(conversation_id uuid)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, agent, system
AS $$
    SELECT credential.conversation_id
      FROM agent.mcp_credentials AS credential
      JOIN agent.installations AS installation
        ON installation.tenant_id = credential.tenant_id
       AND installation.installation_id = credential.installation_id
      JOIN agent.agent_devices AS device
        ON device.tenant_id = credential.tenant_id
       AND device.installation_id = credential.installation_id
       AND device.agent_device_id = credential.agent_device_id
      JOIN agent.connector_bindings AS binding
        ON binding.tenant_id = credential.tenant_id
       AND binding.binding_id = credential.binding_id
       AND binding.installation_id = credential.installation_id
       AND binding.agent_device_id = credential.agent_device_id
      JOIN agent.conversation_grant_heads AS grant_head
        ON grant_head.tenant_id = credential.tenant_id
       AND grant_head.conversation_id = credential.conversation_id
       AND grant_head.installation_id = credential.installation_id
      JOIN agent.conversation_grant_versions AS grant_version
        ON grant_version.tenant_id = grant_head.tenant_id
       AND grant_version.conversation_id = grant_head.conversation_id
       AND grant_version.installation_id = grant_head.installation_id
       AND grant_version.grant_version = grant_head.current_grant_version
       AND grant_version.grant_id = grant_head.current_grant_id
     WHERE requested_tenant_id = system.current_tenant_id()
       AND credential.tenant_id = requested_tenant_id
       AND credential.token_digest = requested_token_digest
       AND credential.node_id = requested_node_id
       AND credential.capability = 'mcp.references.v1'
       AND credential.revoked_at_ms IS NULL
       AND credential.expires_at_ms > requested_now_ms
       AND installation.desired_state = 'enabled'
       AND installation.observed_state = 'ready'
       AND device.state = 'active'
       AND binding.state = 'enabled'
       AND grant_version.revoked_at_ms IS NULL
       AND (grant_version.expires_at_ms IS NULL
            OR grant_version.expires_at_ms > requested_now_ms)
       AND NOT EXISTS (
            SELECT 1
              FROM agent.agent_installation_revocations AS revocation
             WHERE revocation.tenant_id = credential.tenant_id
               AND revocation.installation_id = credential.installation_id
               AND (revocation.scope = 1
                    OR (revocation.scope = 2
                        AND revocation.agent_device_id = credential.agent_device_id))
       )
$$;

-- V37 accidentally enforced the query limit as bytes. JSON Schema maxLength
-- counts Unicode scalar values, so the database accepts at most 256 scalars
-- and separately caps UTF-8 at 1024 bytes.
CREATE OR REPLACE FUNCTION groups.mcp_visible_private_conversations(
    requested_tenant_id uuid,
    requested_identity_id text,
    requested_query text,
    requested_limit integer
)
RETURNS TABLE(scope_id text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, groups, system
AS $$
BEGIN
    IF requested_tenant_id IS DISTINCT FROM system.current_tenant_id()
        OR requested_identity_id !~ '^dtxi1[a-z2-7]{52}$'
        OR char_length(requested_query) > 256
        OR octet_length(requested_query) > 1024
        OR requested_limit NOT BETWEEN 1 AND 32
    THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT policy.scope_id
      FROM groups.policy_heads AS policy
     WHERE policy.tenant_id = requested_tenant_id
       AND policy.scope_kind = 'private_conversation'
       AND (
            policy.owner_identity_id = requested_identity_id
            OR EXISTS (
                SELECT 1
                  FROM groups.members AS member
                 WHERE member.tenant_id = policy.tenant_id
                   AND member.scope_kind = policy.scope_kind
                   AND member.scope_id = policy.scope_id
                   AND member.identity_id = requested_identity_id
            )
       )
       AND (
            requested_query = ''
            OR strpos(lower(policy.scope_id), lower(requested_query)) > 0
       )
     ORDER BY policy.scope_id
     LIMIT requested_limit;
END
$$;

REVOKE ALL ON agent.mcp_credentials FROM PUBLIC;
REVOKE ALL ON FUNCTION
    agent.register_mcp_credential_digest(
        uuid, uuid, bytea, uuid, uuid, uuid, text, uuid, text, bigint, bigint
    ),
    agent.revoke_mcp_credential_digest(uuid, uuid, bytea, bigint),
    agent.authenticate_mcp_reference_credential(uuid, bytea, text, bigint)
    FROM PUBLIC;

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION
            agent.authenticate_mcp_reference_credential(uuid, bytea, text, bigint)
            TO dtx_agent_runtime;
    END IF;
    IF to_regrole('dtx_agent_peer_admin') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA agent TO dtx_agent_peer_admin;
        GRANT EXECUTE ON FUNCTION
            agent.register_mcp_credential_digest(
                uuid, uuid, bytea, uuid, uuid, uuid, text, uuid, text, bigint, bigint
            ),
            agent.revoke_mcp_credential_digest(uuid, uuid, bytea, bigint)
            TO dtx_agent_peer_admin;
    END IF;
END
$grant$;
