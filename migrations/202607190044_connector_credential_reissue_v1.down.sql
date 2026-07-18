DROP TABLE agent.connector_credential_reissue_intents;
ALTER TABLE agent.connector_control_credentials DROP CONSTRAINT connector_control_credentials_origin_valid;
ALTER TABLE agent.connector_control_credentials ADD CONSTRAINT connector_control_credentials_origin_valid CHECK ((origin_kind = 'enrollment' AND enrollment_intent_id IS NOT NULL AND predecessor_credential_id IS NULL) OR (origin_kind = 'rotation' AND enrollment_intent_id IS NULL AND predecessor_credential_id IS NOT NULL));
ALTER TABLE agent.connector_control_credentials ADD CONSTRAINT connector_control_credentials_generation_unique UNIQUE (tenant_id, connector_id, connector_generation), ADD CONSTRAINT connector_control_credentials_revision_unique UNIQUE (tenant_id, connector_id, credential_revision);
ALTER TABLE agent.connector_control_operations DROP CONSTRAINT connector_control_operations_kind_valid;
ALTER TABLE agent.connector_control_operations ADD CONSTRAINT connector_control_operations_kind_valid CHECK (operation_kind IN ('enrollment', 'apply_config', 'rotate_credential', 'close_stream'));
