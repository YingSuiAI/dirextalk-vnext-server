-- Production Agent Control privilege allowlist. Reset the managed role before
-- applying the exact rights exercised by the existing persistence boundary.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA system, agent, identity, groups, directory
    FROM dtx_agent_runtime;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA system, agent, identity, groups, directory
    FROM dtx_agent_runtime;
REVOKE ALL PRIVILEGES ON SCHEMA system, agent, identity, groups, directory
    FROM dtx_agent_runtime;

GRANT USAGE ON SCHEMA system, agent TO dtx_agent_runtime;
GRANT EXECUTE ON FUNCTION system.current_tenant_id(), system.is_uuid_v7(uuid),
    system.is_stable_code(text, integer), system.enforce_completed_inbox(),
    system.enforce_inbox_transition() TO dtx_agent_runtime;
GRANT SELECT ON system.schema_versions TO dtx_agent_runtime;
GRANT SELECT, INSERT, UPDATE ON system.tenant_stream_heads TO dtx_agent_runtime;
GRANT SELECT, INSERT ON system.durable_events, system.audit_events TO dtx_agent_runtime;
GRANT SELECT, INSERT, UPDATE ON system.outbox_events, system.inbox_dedup,
    system.projection_cursors TO dtx_agent_runtime;

GRANT EXECUTE ON FUNCTION agent.is_public_id(text, text),
    agent.connector_certificate_chain_valid(bytea[]),
    agent.connector_runtime_name_valid(text, integer),
    agent.connector_claim_codes_valid(text[]), agent.connector_run_ids_valid(uuid[]),
    agent.connector_runtime_error_code_valid(text),
    agent.prune_connector_runtime_claim_history(uuid, uuid, integer),
    agent.router_stable_names(text[]) TO dtx_agent_runtime;

GRANT SELECT, INSERT, UPDATE ON agent.agent_definition_heads,
    agent.installations, agent.agent_devices, agent.hosts, agent.host_credentials,
    agent.host_credential_authorization_heads, agent.connector_enrollment_intents,
    agent.connector_credential_reissue_intents, agent.connector_control_credential_heads,
    agent.connector_runtime_claim_heads, agent.connector_control_stream_heads,
    agent.connector_instances, agent.connector_boots, agent.connector_leases,
    agent.binding_set_heads, agent.installation_routing_policies, agent.connector_bindings,
    agent.conversation_grant_heads, agent.agent_runs, agent.connector_run_capacity_heads,
    agent.binding_run_capacity_heads, agent.agent_run_offers, agent.agent_run_leases,
    agent.agent_run_execution_heads, agent.agent_route_run_operations,
    agent.agent_route_bootstraps, agent.agent_route_bootstrap_outbox,
    agent.agent_route_binding_heads TO dtx_agent_runtime;

GRANT SELECT, INSERT ON agent.agent_definitions, agent.agent_identity_approvals,
    agent.agent_installation_revocations, agent.host_provisioning_operations,
    agent.host_credential_authorization_credentials,
    agent.host_credential_authorization_revisions,
    agent.host_credential_authorization_states, agent.connector_control_operations,
    agent.connector_control_credentials, agent.connector_control_credential_revisions,
    agent.connector_control_credential_rotations, agent.connector_runtime_claims,
    agent.connector_control_commands, agent.connector_revisions,
    agent.connector_conformance, agent.conversation_grant_ids,
    agent.conversation_grant_versions, agent.conversation_grant_permissions,
    agent.conversation_grant_cloud_connections, agent.agent_run_candidates,
    agent.agent_run_checkpoints, agent.agent_run_outputs, agent.agent_run_terminals,
    agent.agent_run_cancellation_intents, agent.conversation_grant_owner_operations,
    agent.connector_binding_state_owner_operations TO dtx_agent_runtime;

GRANT SELECT, INSERT, UPDATE ON agent.agent_provisioning_recipients,
    agent.agent_provisioning_deliveries, agent.agent_provisioning_outbox TO dtx_agent_runtime;

GRANT USAGE ON SCHEMA identity, groups, directory TO dtx_agent_runtime;
GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
    TO dtx_agent_runtime;
GRANT EXECUTE ON FUNCTION identity.identity_agent_reader_authorized(),
    groups.private_conversation_owner_authorized(uuid, uuid, text),
    groups.mcp_visible_private_conversations(uuid, text, text, integer),
    directory.mcp_public_reference_facts(uuid, integer, integer, bigint),
    agent.authenticate_mcp_reference_credential(uuid, bytea, text, bigint)
    TO dtx_agent_runtime;

-- Explicit denials are kept as executable review evidence.
REVOKE CREATE ON SCHEMA system, agent, identity, groups, directory FROM dtx_agent_runtime;
REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA system, agent, identity, groups, directory
    FROM dtx_agent_runtime;
