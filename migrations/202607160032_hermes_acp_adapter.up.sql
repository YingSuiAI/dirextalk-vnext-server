-- V4 adds first-class Hermes ACP support without changing any published
-- Connector projection below V4. These are the three durable adapter-kind
-- boundaries introduced by the original Agent Control schema.
ALTER TABLE agent.connector_instances
    DROP CONSTRAINT connector_instances_adapter_kind_valid;
ALTER TABLE agent.connector_instances
    ADD CONSTRAINT connector_instances_adapter_kind_valid
    CHECK (adapter_kind IN (
        'codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp', 'hermes_acp'
    ));

ALTER TABLE agent.connector_revisions
    DROP CONSTRAINT connector_revisions_adapter_kind_valid;
ALTER TABLE agent.connector_revisions
    ADD CONSTRAINT connector_revisions_adapter_kind_valid
    CHECK (adapter_kind IN (
        'codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp', 'hermes_acp'
    ));

ALTER TABLE agent.connector_conformance
    DROP CONSTRAINT connector_conformance_adapter_kind_valid;
ALTER TABLE agent.connector_conformance
    ADD CONSTRAINT connector_conformance_adapter_kind_valid
    CHECK (adapter_kind IN (
        'codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp', 'hermes_acp'
    ));
