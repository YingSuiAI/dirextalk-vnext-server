DO $revoke$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        REVOKE EXECUTE ON FUNCTION
            groups.mcp_visible_private_conversations(uuid, text, text, integer),
            directory.mcp_public_reference_facts(uuid, integer, integer, bigint)
            FROM dtx_agent_runtime;
        REVOKE USAGE ON SCHEMA directory FROM dtx_agent_runtime;
    END IF;
END
$revoke$;

DROP FUNCTION directory.mcp_public_reference_facts(uuid, integer, integer, bigint);
DROP FUNCTION groups.mcp_visible_private_conversations(uuid, text, text, integer);
