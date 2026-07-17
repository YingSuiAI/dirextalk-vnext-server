-- V39: the root-operated acceptance finalizer uses the service credential but
-- writes only the fixed Agent Definition/Installation/Device topology. Grant
-- the exact missing relations; V31 already owns the Connector/Binding rights.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON agent.agent_definitions TO dtx_agent_runtime;
        GRANT SELECT, INSERT, UPDATE ON agent.agent_definition_heads
            TO dtx_agent_runtime;
        GRANT INSERT, UPDATE ON agent.installations, agent.agent_devices
            TO dtx_agent_runtime;
        GRANT SELECT ON agent.host_credentials TO dtx_agent_runtime;
    END IF;
END
$grant$;
