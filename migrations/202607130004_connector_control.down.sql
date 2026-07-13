DROP FUNCTION agent.prune_connector_runtime_claim_history(uuid, uuid, integer);
DROP TRIGGER connector_instance_revocation_bundle ON agent.connector_instances;
DROP TRIGGER connector_lease_revocation_bundle ON agent.connector_leases;
DROP TRIGGER connector_lease_reactivated_bundle ON agent.connector_leases;
DROP TRIGGER connector_stream_revocation_bundle ON agent.connector_control_stream_heads;
DROP TRIGGER connector_credential_revocation_bundle ON agent.connector_control_credential_heads;
DROP TABLE agent.connector_runtime_claim_heads;
DROP TABLE agent.connector_runtime_claims;
DROP TABLE agent.connector_control_credential_heads;
DROP TABLE agent.connector_control_credential_revisions;
DROP TABLE agent.connector_control_credential_rotations;
DROP FUNCTION agent.enforce_connector_credential_rotation_command();
DROP TABLE agent.connector_control_commands;
DROP FUNCTION agent.enforce_connector_terminal_revoke_commit();
DROP FUNCTION agent.enforce_connector_revocation_bundle();
DROP TABLE agent.connector_control_stream_heads;
DROP TRIGGER connector_instance_control_stream_fence ON agent.connector_instances;
ALTER TABLE agent.connector_enrollment_intents
    DROP CONSTRAINT connector_enrollment_intents_credential_fk;
DROP TABLE agent.connector_control_credentials;
DROP TABLE agent.connector_enrollment_intents;
DROP TABLE agent.connector_control_operations;

DROP FUNCTION agent.advance_connector_control_command_tail();
DROP FUNCTION agent.enforce_connector_control_command_insert();
DROP FUNCTION agent.enforce_connector_control_stream_fence();
DROP FUNCTION agent.enforce_connector_control_stream_head_transition();
DROP FUNCTION agent.enforce_connector_runtime_claim_head_transition();
DROP FUNCTION agent.enforce_connector_runtime_claim_published();
DROP FUNCTION agent.enforce_connector_runtime_claim_insert();
DROP FUNCTION agent.connector_run_ids_valid(uuid[]);
DROP FUNCTION agent.connector_runtime_error_code_valid(text);
DROP FUNCTION agent.connector_claim_codes_valid(text[]);
DROP FUNCTION agent.connector_runtime_name_valid(text, integer);
DROP FUNCTION agent.enforce_connector_credential_head_transition();
DROP FUNCTION agent.enforce_connector_credential_revision_published();
DROP FUNCTION agent.enforce_connector_credential_revision_insert();
DROP FUNCTION agent.enforce_connector_enrollment_consumed();
DROP FUNCTION agent.enforce_connector_credential_rotation_insert();
DROP FUNCTION agent.enforce_connector_control_credential_insert();
DROP FUNCTION agent.connector_certificate_chain_valid(bytea[]);
DROP FUNCTION agent.enforce_connector_enrollment_transition();
DROP FUNCTION agent.enforce_connector_control_operation_published();

ALTER TABLE agent.connector_leases
    DROP CONSTRAINT connector_leases_runtime_fence_unique;
ALTER TABLE agent.connector_instances
    DROP CONSTRAINT connector_instances_host_scope_unique;
