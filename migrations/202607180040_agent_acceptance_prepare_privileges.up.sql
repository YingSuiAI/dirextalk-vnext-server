-- V40: acceptance-prepare creates a new Owner-scoped Host and its initial
-- credential history when the retained client identity changes. Connector
-- runtime grants already cover the new Connector rows; add only the two Host
-- inserts that the canonical acceptance foundation requires.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT INSERT ON agent.hosts, agent.host_credentials TO dtx_agent_runtime;
    END IF;
END
$grant$;
