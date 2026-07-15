DROP TRIGGER IF EXISTS agent_run_cancellation_notify ON agent.agent_run_cancellation_intents;
DROP FUNCTION IF EXISTS agent.notify_agent_run_cancellation();
DROP TABLE IF EXISTS agent.agent_run_cancellation_intents;
