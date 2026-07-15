DO $revoke$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        REVOKE ALL ON agent.agent_route_run_operations FROM dtx_agent_runtime;
    END IF;
END
$revoke$;

DROP TABLE agent.agent_route_run_operations;
