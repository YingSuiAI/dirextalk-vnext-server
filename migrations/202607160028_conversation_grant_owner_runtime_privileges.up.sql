-- V28: the V27 Owner API writes only the fixed Conversation Grant aggregate.
-- Keep these table rights separate from V27 so databases that already applied
-- its receipt schema receive the new capability without a checksum rewrite.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT INSERT ON agent.conversation_grant_ids,
            agent.conversation_grant_versions,
            agent.conversation_grant_heads,
            agent.conversation_grant_permissions
            TO dtx_agent_runtime;
        GRANT UPDATE ON agent.conversation_grant_heads TO dtx_agent_runtime;
    END IF;
END
$grant$;
