DO $revoke$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        REVOKE EXECUTE ON FUNCTION
            agent.authenticate_mcp_reference_credential(uuid, bytea, text, bigint)
            FROM dtx_agent_runtime;
    END IF;
    IF to_regrole('dtx_agent_peer_admin') IS NOT NULL THEN
        REVOKE EXECUTE ON FUNCTION
            agent.register_mcp_credential_digest(
                uuid, uuid, bytea, uuid, uuid, uuid, text, uuid, text, bigint, bigint
            ),
            agent.revoke_mcp_credential_digest(uuid, uuid, bytea, bigint)
            FROM dtx_agent_peer_admin;
        REVOKE USAGE ON SCHEMA agent FROM dtx_agent_peer_admin;
    END IF;
END
$revoke$;

DROP FUNCTION agent.authenticate_mcp_reference_credential(uuid, bytea, text, bigint);
DROP FUNCTION agent.revoke_mcp_credential_digest(uuid, uuid, bytea, bigint);
DROP FUNCTION agent.register_mcp_credential_digest(
    uuid, uuid, bytea, uuid, uuid, uuid, text, uuid, text, bigint, bigint
);
DROP TRIGGER agent_mcp_credentials_transition ON agent.mcp_credentials;
DROP FUNCTION agent.enforce_mcp_credential_transition();
DROP TABLE agent.mcp_credentials;

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
        OR octet_length(requested_query) > 256
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
