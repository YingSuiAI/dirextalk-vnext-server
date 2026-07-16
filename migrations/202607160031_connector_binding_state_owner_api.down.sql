DO $revoke$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        REVOKE ALL ON agent.connector_binding_state_owner_operations FROM dtx_agent_runtime;
        REVOKE UPDATE ON agent.connector_bindings, agent.binding_set_heads
            FROM dtx_agent_runtime;
        REVOKE INSERT ON agent.connector_conformance,
            agent.installation_routing_policies, agent.connector_bindings,
            agent.binding_set_heads
            FROM dtx_agent_runtime;
        REVOKE SELECT ON agent.installations, agent.agent_devices,
            agent.connector_instances, agent.connector_conformance,
            agent.installation_routing_policies, agent.connector_bindings,
            agent.binding_set_heads
            FROM dtx_agent_runtime;
    END IF;
END
$revoke$;

DROP TABLE agent.connector_binding_state_owner_operations;
