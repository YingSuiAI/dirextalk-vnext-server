-- AR3: durable, exactly fenced Agent Run cancellation intents.

CREATE TABLE agent.agent_run_cancellation_intents (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    request_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    offer_attempt bigint NOT NULL,
    run_lease_id uuid NOT NULL,
    run_lease_epoch bigint NOT NULL,
    run_lease_deadline_ms bigint NOT NULL,
    connector_boot_id uuid NOT NULL,
    connector_generation bigint NOT NULL,
    connector_lease_id uuid NOT NULL,
    connector_lease_epoch bigint NOT NULL,
    connector_cancel_sequence bigint NOT NULL,
    stable_reason text NOT NULL,
    requested_at_ms bigint NOT NULL,
    cancel_deadline_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    CONSTRAINT agent_run_cancellation_intents_run_fk
        FOREIGN KEY (tenant_id, run_id)
        REFERENCES agent.agent_runs (tenant_id, run_id) ON DELETE RESTRICT,
    CONSTRAINT agent_run_cancellation_intents_run_lease_fk
        FOREIGN KEY (tenant_id, run_id, run_lease_id)
        REFERENCES agent.agent_run_leases (tenant_id, run_id, run_lease_id) ON DELETE RESTRICT,
    CONSTRAINT agent_run_cancellation_intents_connector_lease_fk
        FOREIGN KEY (tenant_id, connector_id, connector_lease_id)
        REFERENCES agent.connector_leases (tenant_id, connector_id, lease_id) ON DELETE RESTRICT,
    CONSTRAINT agent_run_cancellation_intents_ids_v7 CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(run_id)
        AND system.is_uuid_v7(request_id) AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(binding_id) AND system.is_uuid_v7(connector_id)
        AND system.is_uuid_v7(run_lease_id) AND system.is_uuid_v7(connector_boot_id)
        AND system.is_uuid_v7(connector_lease_id)
    ),
    CONSTRAINT agent_run_cancellation_intents_values CHECK (
        offer_attempt BETWEEN 1 AND 9007199254740991
        AND run_lease_epoch BETWEEN 1 AND 9007199254740991
        AND connector_generation BETWEEN 1 AND 9007199254740991
        AND connector_lease_epoch BETWEEN 1 AND 9007199254740991
        AND connector_cancel_sequence BETWEEN 1 AND 9007199254740991
        AND stable_reason ~ '^[A-Z][A-Z0-9_]{2,63}$'
        AND requested_at_ms BETWEEN 0 AND 9007199254740990
        AND cancel_deadline_ms BETWEEN requested_at_ms + 1 AND 9007199254740991
        AND cancel_deadline_ms <= run_lease_deadline_ms
    )
);

CREATE INDEX agent_run_cancellation_intents_delivery_idx
    ON agent.agent_run_cancellation_intents (
        tenant_id, connector_id, connector_boot_id, connector_generation,
        connector_lease_id, connector_lease_epoch, connector_cancel_sequence
    );
CREATE UNIQUE INDEX agent_run_cancellation_intents_connector_sequence_unique
    ON agent.agent_run_cancellation_intents
        (tenant_id, connector_id, connector_cancel_sequence);

CREATE FUNCTION agent.notify_agent_run_cancellation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, agent AS $$
BEGIN
    PERFORM pg_notify('dtx_agent_run_offer_v1', NEW.tenant_id::text || ':' || NEW.connector_id::text);
    RETURN NULL;
END;
$$;

CREATE TRIGGER agent_run_cancellation_notify
AFTER INSERT ON agent.agent_run_cancellation_intents
FOR EACH ROW EXECUTE FUNCTION agent.notify_agent_run_cancellation();

ALTER TABLE agent.agent_run_cancellation_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_cancellation_intents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_cancellation_intents
    USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.agent_run_cancellation_intents FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.notify_agent_run_cancellation() FROM PUBLIC;
