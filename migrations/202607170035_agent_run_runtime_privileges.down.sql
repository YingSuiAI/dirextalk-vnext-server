DO $revoke$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        REVOKE SELECT, INSERT, UPDATE ON agent.agent_run_execution_heads
            FROM dtx_agent_runtime;
        REVOKE SELECT, INSERT ON agent.agent_run_checkpoints,
            agent.agent_run_outputs,
            agent.agent_run_terminals,
            agent.agent_run_cancellation_intents
            FROM dtx_agent_runtime;
    END IF;
END
$revoke$;
