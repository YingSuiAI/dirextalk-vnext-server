-- V35: grant the Agent runtime exactly the AR3 execution-reporting and
-- cancellation rights introduced by V16/V17.
--
-- Keep this forward-only repair separate from the already-applied schema
-- migrations so existing databases receive the missing capability without a
-- checksum rewrite.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON agent.agent_run_execution_heads
            TO dtx_agent_runtime;
        GRANT SELECT, INSERT ON agent.agent_run_checkpoints,
            agent.agent_run_outputs,
            agent.agent_run_terminals,
            agent.agent_run_cancellation_intents
            TO dtx_agent_runtime;
    END IF;
END
$grant$;
