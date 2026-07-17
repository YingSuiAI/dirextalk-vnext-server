DO $revoke$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        REVOKE INSERT ON agent.hosts, agent.host_credentials FROM dtx_agent_runtime;
    END IF;
END
$revoke$;
