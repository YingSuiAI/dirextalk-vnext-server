-- Never make durable Hermes rows unreadable merely to satisfy an older
-- binary. Operators must remove or migrate every Hermes Connector fact before
-- rehearsing this rollback.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM agent.connector_instances WHERE adapter_kind = 'hermes_acp'
        UNION ALL
        SELECT 1 FROM agent.connector_revisions WHERE adapter_kind = 'hermes_acp'
        UNION ALL
        SELECT 1 FROM agent.connector_conformance WHERE adapter_kind = 'hermes_acp'
    ) THEN
        RAISE EXCEPTION 'cannot remove Hermes ACP adapter while durable Hermes rows exist'
            USING ERRCODE = '55000';
    END IF;
END
$$;

ALTER TABLE agent.connector_instances
    DROP CONSTRAINT connector_instances_adapter_kind_valid;
ALTER TABLE agent.connector_instances
    ADD CONSTRAINT connector_instances_adapter_kind_valid
    CHECK (adapter_kind IN (
        'codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp'
    ));

ALTER TABLE agent.connector_revisions
    DROP CONSTRAINT connector_revisions_adapter_kind_valid;
ALTER TABLE agent.connector_revisions
    ADD CONSTRAINT connector_revisions_adapter_kind_valid
    CHECK (adapter_kind IN (
        'codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp'
    ));

ALTER TABLE agent.connector_conformance
    DROP CONSTRAINT connector_conformance_adapter_kind_valid;
ALTER TABLE agent.connector_conformance
    ADD CONSTRAINT connector_conformance_adapter_kind_valid
    CHECK (adapter_kind IN (
        'codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp'
    ));
