DO $revoke$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        REVOKE SELECT, INSERT ON agent.agent_definitions FROM dtx_agent_runtime;
        REVOKE SELECT, INSERT, UPDATE ON agent.agent_definition_heads
            FROM dtx_agent_runtime;
        REVOKE INSERT, UPDATE ON agent.installations, agent.agent_devices
            FROM dtx_agent_runtime;
        REVOKE SELECT ON agent.host_credentials FROM dtx_agent_runtime;
    END IF;
END
$revoke$;
