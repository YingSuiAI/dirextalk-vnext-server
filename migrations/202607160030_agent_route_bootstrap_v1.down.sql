DROP TABLE agent.agent_route_binding_heads;
DROP TABLE agent.agent_route_bootstrap_outbox;
DROP TABLE agent.agent_route_bootstraps;

ALTER TABLE agent.connector_control_commands DISABLE TRIGGER connector_control_commands_append_only;
DELETE FROM agent.connector_control_commands
 WHERE command_kind IN ('prepare_agent_route_recipient', 'deliver_agent_route_bootstrap');
ALTER TABLE agent.connector_control_commands ENABLE TRIGGER connector_control_commands_append_only;
DELETE FROM agent.connector_control_operations
 WHERE operation_kind IN ('prepare_agent_route_recipient', 'deliver_agent_route_bootstrap');
ALTER TABLE agent.connector_control_commands
    DROP CONSTRAINT connector_control_commands_kind_valid,
    ADD CONSTRAINT connector_control_commands_kind_valid
        CHECK (command_kind IN (
            'apply_config', 'rotate_credential', 'close_stream',
            'deliver_agent_provisioning', 'revoke_agent_provisioning'
        ));
ALTER TABLE agent.connector_control_operations
    DROP CONSTRAINT connector_control_operations_kind_valid,
    ADD CONSTRAINT connector_control_operations_kind_valid
        CHECK (operation_kind IN (
            'enrollment', 'apply_config', 'rotate_credential', 'close_stream',
            'deliver_agent_provisioning', 'revoke_agent_provisioning'
        ));
