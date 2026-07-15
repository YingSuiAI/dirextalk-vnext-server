DO $revoke$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        REVOKE UPDATE ON agent.conversation_grant_heads FROM dtx_agent_runtime;
        REVOKE INSERT ON agent.conversation_grant_ids,
            agent.conversation_grant_versions,
            agent.conversation_grant_heads,
            agent.conversation_grant_permissions
            FROM dtx_agent_runtime;
    END IF;
END
$revoke$;
