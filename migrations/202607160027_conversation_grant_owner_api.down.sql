DO $revoke$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        REVOKE ALL ON agent.conversation_grant_owner_operations FROM dtx_agent_runtime;
        REVOKE EXECUTE ON FUNCTION groups.private_conversation_owner_authorized(uuid, uuid, text)
            FROM dtx_agent_runtime;
        REVOKE USAGE ON SCHEMA groups FROM dtx_agent_runtime;
    END IF;
END
$revoke$;

DROP TABLE agent.conversation_grant_owner_operations;
DROP FUNCTION groups.private_conversation_owner_authorized(uuid, uuid, text);
