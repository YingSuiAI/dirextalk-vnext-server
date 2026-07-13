-- MC3: explicit-target Agent Router heads, immutable candidates, offers, and fenced leases.

CREATE FUNCTION agent.router_stable_names(names text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT cardinality(names) BETWEEN 0 AND 64
       AND NOT EXISTS (
            SELECT 1
              FROM unnest(names) AS value
             WHERE octet_length(value) NOT BETWEEN 1 AND 128
                OR value !~ '^[a-z0-9][a-z0-9._:/-]*$'
       )
       AND cardinality(names) = (
            SELECT count(DISTINCT value) FROM unnest(names) AS value
       )
$$;

CREATE TABLE agent.agent_runs (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    request_id uuid NOT NULL,
    idempotency_digest bytea NOT NULL,
    request_digest bytea NOT NULL,
    installation_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    request_event_id uuid NOT NULL,
    preferred_connector_id uuid,
    required_capability_codes text[] NOT NULL,
    dispatch_mode text NOT NULL,
    routing_policy text NOT NULL,
    routing_policy_revision bigint NOT NULL,
    grant_version bigint NOT NULL,
    queue_deadline_ms bigint NOT NULL,
    state text NOT NULL,
    candidate_cursor integer NOT NULL,
    candidate_count integer NOT NULL,
    highest_offer_attempt bigint NOT NULL DEFAULT 0,
    highest_run_lease_epoch bigint NOT NULL DEFAULT 0,
    current_offer_id uuid,
    current_run_lease_id uuid,
    aggregate_revision bigint NOT NULL,
    server_time_high_water_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    CONSTRAINT agent_runs_request_unique UNIQUE (tenant_id, request_id),
    CONSTRAINT agent_runs_idempotency_unique UNIQUE (tenant_id, idempotency_digest),
    CONSTRAINT agent_runs_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_runs_installation_fk
        FOREIGN KEY (tenant_id, installation_id)
        REFERENCES agent.installations (tenant_id, installation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_runs_preferred_connector_fk
        FOREIGN KEY (tenant_id, preferred_connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_runs_ids_v7 CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(run_id)
        AND system.is_uuid_v7(request_id)
        AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(conversation_id)
        AND system.is_uuid_v7(request_event_id)
        AND (preferred_connector_id IS NULL OR system.is_uuid_v7(preferred_connector_id))
        AND (current_offer_id IS NULL OR system.is_uuid_v7(current_offer_id))
        AND (current_run_lease_id IS NULL OR system.is_uuid_v7(current_run_lease_id))
    ),
    CONSTRAINT agent_runs_digests_size CHECK (
        octet_length(idempotency_digest) = 32 AND octet_length(request_digest) = 32
    ),
    CONSTRAINT agent_runs_capabilities_valid
        CHECK (agent.router_stable_names(required_capability_codes)),
    CONSTRAINT agent_runs_dispatch_valid CHECK (
        dispatch_mode IN ('single', 'failover')
        AND routing_policy IN ('exclusive', 'ordered_failover')
        AND (dispatch_mode = 'single' OR routing_policy = 'ordered_failover')
    ),
    CONSTRAINT agent_runs_versions_safe CHECK (
        routing_policy_revision BETWEEN 1 AND 9007199254740991
        AND grant_version BETWEEN 1 AND 9007199254740991
        AND highest_offer_attempt BETWEEN 0 AND 9007199254740991
        AND highest_run_lease_epoch BETWEEN 0 AND 9007199254740991
        AND aggregate_revision BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT agent_runs_state_valid CHECK (
        state IN ('queued', 'offered', 'leased', 'reconcile_required', 'expired')
    ),
    CONSTRAINT agent_runs_candidates_valid CHECK (
        candidate_count BETWEEN 1 AND 64
        AND candidate_cursor BETWEEN 0 AND candidate_count - 1
        AND (dispatch_mode <> 'single' OR candidate_count = 1)
    ),
    CONSTRAINT agent_runs_current_refs_consistent CHECK (
        (state IN ('queued', 'expired') AND current_offer_id IS NULL AND current_run_lease_id IS NULL)
        OR (state = 'offered' AND current_offer_id IS NOT NULL AND current_run_lease_id IS NULL)
        OR (state IN ('leased', 'reconcile_required')
            AND current_offer_id IS NOT NULL AND current_run_lease_id IS NOT NULL)
    ),
    CONSTRAINT agent_runs_time_valid CHECK (
        created_at_ms BETWEEN 0 AND 9007199254740990
        AND queue_deadline_ms BETWEEN created_at_ms + 1 AND 9007199254740991
        AND updated_at_ms BETWEEN created_at_ms AND 9007199254740991
        AND server_time_high_water_ms BETWEEN updated_at_ms AND 9007199254740991
    )
);

-- The active-stream reconciler repeatedly walks only one state at a time.
-- These partial indexes keep that bounded work proportional to live Router
-- state instead of the tenant's complete Run history.
CREATE INDEX agent_runs_queued_reconcile_idx
    ON agent.agent_runs (tenant_id, updated_at_ms, run_id)
    INCLUDE (queue_deadline_ms)
    WHERE state = 'queued';
CREATE INDEX agent_runs_queued_due_idx
    ON agent.agent_runs (tenant_id, queue_deadline_ms, updated_at_ms, run_id)
    WHERE state = 'queued';
CREATE INDEX agent_runs_offered_reconcile_idx
    ON agent.agent_runs (tenant_id, updated_at_ms, run_id)
    WHERE state = 'offered';
CREATE INDEX agent_runs_leased_reconcile_idx
    ON agent.agent_runs (tenant_id, updated_at_ms, run_id)
    WHERE state = 'leased';

CREATE TABLE agent.agent_run_candidates (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    candidate_ordinal integer NOT NULL,
    binding_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    priority integer NOT NULL,
    max_concurrency bigint NOT NULL,
    PRIMARY KEY (tenant_id, run_id, candidate_ordinal),
    CONSTRAINT agent_run_candidates_exact_unique
        UNIQUE (tenant_id, run_id, candidate_ordinal, binding_id, connector_id),
    CONSTRAINT agent_run_candidates_binding_unique
        UNIQUE (tenant_id, run_id, binding_id),
    CONSTRAINT agent_run_candidates_connector_unique
        UNIQUE (tenant_id, run_id, connector_id),
    CONSTRAINT agent_run_candidates_run_fk
        FOREIGN KEY (tenant_id, run_id)
        REFERENCES agent.agent_runs (tenant_id, run_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_run_candidates_binding_fk
        FOREIGN KEY (tenant_id, binding_id)
        REFERENCES agent.connector_bindings (tenant_id, binding_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_run_candidates_ids_v7 CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(run_id)
        AND system.is_uuid_v7(binding_id) AND system.is_uuid_v7(connector_id)
    ),
    CONSTRAINT agent_run_candidates_ordinal_valid
        CHECK (candidate_ordinal BETWEEN 0 AND 63),
    CONSTRAINT agent_run_candidates_priority_valid CHECK (priority BETWEEN 0 AND 65535),
    CONSTRAINT agent_run_candidates_capacity_valid
        CHECK (max_concurrency BETWEEN 1 AND 4294967295)
);

CREATE TABLE agent.connector_run_capacity_heads (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    last_offer_sequence bigint NOT NULL DEFAULT 0,
    active_reservation_count bigint NOT NULL DEFAULT 0,
    observation_lease_id uuid,
    observation_heartbeat_sequence bigint NOT NULL DEFAULT 0,
    observation_claim_revision bigint NOT NULL DEFAULT 0,
    observation_reservation_baseline bigint NOT NULL DEFAULT 0,
    observation_available_count bigint NOT NULL DEFAULT 0,
    capacity_revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id),
    CONSTRAINT connector_run_capacity_heads_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_run_capacity_heads_observation_lease_fk
        FOREIGN KEY (tenant_id, connector_id, observation_lease_id)
        REFERENCES agent.connector_leases (tenant_id, connector_id, lease_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_run_capacity_heads_values_safe CHECK (
        last_offer_sequence BETWEEN 0 AND 9007199254740991
        AND active_reservation_count BETWEEN 0 AND 4294967295
        AND observation_heartbeat_sequence BETWEEN 0 AND 9007199254740991
        AND observation_claim_revision BETWEEN 0 AND 9007199254740991
        AND observation_reservation_baseline BETWEEN 0 AND 4294967295
        AND observation_available_count BETWEEN 0 AND 4294967295
        AND capacity_revision BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT connector_run_capacity_heads_observation_valid CHECK (
        (observation_lease_id IS NULL
            AND observation_heartbeat_sequence = 0
            AND observation_claim_revision = 0
            AND observation_reservation_baseline = 0
            AND observation_available_count = 0)
        OR (system.is_uuid_v7(observation_lease_id)
            AND observation_heartbeat_sequence > 0
            AND observation_claim_revision > 0)
    ),
    CONSTRAINT connector_run_capacity_heads_time_valid CHECK (
        created_at_ms BETWEEN 0 AND 9007199254740991
        AND updated_at_ms BETWEEN created_at_ms AND 9007199254740991
    )
);

CREATE TABLE agent.binding_run_capacity_heads (
    tenant_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    active_reservation_count bigint NOT NULL DEFAULT 0,
    capacity_revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, binding_id),
    CONSTRAINT binding_run_capacity_heads_binding_fk
        FOREIGN KEY (tenant_id, binding_id)
        REFERENCES agent.connector_bindings (tenant_id, binding_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT binding_run_capacity_heads_values_safe CHECK (
        active_reservation_count BETWEEN 0 AND 4294967295
        AND capacity_revision BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT binding_run_capacity_heads_time_valid CHECK (
        created_at_ms BETWEEN 0 AND 9007199254740991
        AND updated_at_ms BETWEEN created_at_ms AND 9007199254740991
    )
);

CREATE TABLE agent.agent_run_offers (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    offer_id uuid NOT NULL,
    offer_attempt bigint NOT NULL,
    connector_offer_sequence bigint NOT NULL,
    candidate_ordinal integer NOT NULL,
    binding_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    connector_boot_id uuid NOT NULL,
    connector_generation bigint NOT NULL,
    connector_lease_id uuid NOT NULL,
    connector_lease_epoch bigint NOT NULL,
    offered_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    status text NOT NULL,
    PRIMARY KEY (tenant_id, run_id, offer_id),
    CONSTRAINT agent_run_offers_attempt_unique UNIQUE (tenant_id, run_id, offer_attempt),
    CONSTRAINT agent_run_offers_connector_sequence_unique
        UNIQUE (tenant_id, connector_id, connector_offer_sequence),
    CONSTRAINT agent_run_offers_run_fk
        FOREIGN KEY (tenant_id, run_id)
        REFERENCES agent.agent_runs (tenant_id, run_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_run_offers_candidate_fk
        FOREIGN KEY (tenant_id, run_id, candidate_ordinal, binding_id, connector_id)
        REFERENCES agent.agent_run_candidates
            (tenant_id, run_id, candidate_ordinal, binding_id, connector_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_run_offers_connector_lease_fk
        FOREIGN KEY (tenant_id, connector_id, connector_lease_id)
        REFERENCES agent.connector_leases (tenant_id, connector_id, lease_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_run_offers_ids_v7 CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(run_id)
        AND system.is_uuid_v7(offer_id) AND system.is_uuid_v7(binding_id)
        AND system.is_uuid_v7(connector_id) AND system.is_uuid_v7(connector_boot_id)
        AND system.is_uuid_v7(connector_lease_id)
    ),
    CONSTRAINT agent_run_offers_counters_safe CHECK (
        offer_attempt BETWEEN 1 AND 9007199254740991
        AND connector_offer_sequence BETWEEN 1 AND 9007199254740991
        AND connector_generation BETWEEN 1 AND 9007199254740991
        AND connector_lease_epoch BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT agent_run_offers_status_valid CHECK (status IN ('offered', 'claimed', 'expired')),
    CONSTRAINT agent_run_offers_time_valid CHECK (
        offered_at_ms BETWEEN 0 AND 9007199254740990
        AND expires_at_ms BETWEEN offered_at_ms + 1 AND 9007199254740991
        AND expires_at_ms - offered_at_ms <= 300000
    )
);

CREATE UNIQUE INDEX agent_run_offers_one_active_per_run
    ON agent.agent_run_offers (tenant_id, run_id) WHERE status = 'offered';
CREATE INDEX agent_run_offers_live_connector_idx
    ON agent.agent_run_offers
        (tenant_id, connector_id, connector_boot_id, connector_generation,
         connector_lease_id, connector_lease_epoch, connector_offer_sequence)
    WHERE status = 'offered';
CREATE INDEX agent_run_offers_due_idx
    ON agent.agent_run_offers (tenant_id, expires_at_ms, run_id, offer_id)
    WHERE status = 'offered';

CREATE TABLE agent.agent_run_leases (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    run_lease_id uuid NOT NULL,
    run_lease_epoch bigint NOT NULL,
    offer_id uuid NOT NULL,
    offer_attempt bigint NOT NULL,
    candidate_ordinal integer NOT NULL,
    binding_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    connector_boot_id uuid NOT NULL,
    connector_generation bigint NOT NULL,
    connector_lease_id uuid NOT NULL,
    connector_lease_epoch bigint NOT NULL,
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    status text NOT NULL,
    PRIMARY KEY (tenant_id, run_id, run_lease_id),
    CONSTRAINT agent_run_leases_epoch_unique UNIQUE (tenant_id, run_id, run_lease_epoch),
    CONSTRAINT agent_run_leases_offer_unique UNIQUE (tenant_id, run_id, offer_id),
    CONSTRAINT agent_run_leases_offer_fk
        FOREIGN KEY (tenant_id, run_id, offer_id)
        REFERENCES agent.agent_run_offers (tenant_id, run_id, offer_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_run_leases_candidate_fk
        FOREIGN KEY (tenant_id, run_id, candidate_ordinal, binding_id, connector_id)
        REFERENCES agent.agent_run_candidates
            (tenant_id, run_id, candidate_ordinal, binding_id, connector_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_run_leases_connector_lease_fk
        FOREIGN KEY (tenant_id, connector_id, connector_lease_id)
        REFERENCES agent.connector_leases (tenant_id, connector_id, lease_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_run_leases_ids_v7 CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(run_id)
        AND system.is_uuid_v7(run_lease_id) AND system.is_uuid_v7(offer_id)
        AND system.is_uuid_v7(binding_id) AND system.is_uuid_v7(connector_id)
        AND system.is_uuid_v7(connector_boot_id) AND system.is_uuid_v7(connector_lease_id)
    ),
    CONSTRAINT agent_run_leases_counters_safe CHECK (
        run_lease_epoch BETWEEN 1 AND 9007199254740991
        AND offer_attempt BETWEEN 1 AND 9007199254740991
        AND connector_generation BETWEEN 1 AND 9007199254740991
        AND connector_lease_epoch BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT agent_run_leases_status_valid CHECK (status IN ('active', 'released', 'expired')),
    CONSTRAINT agent_run_leases_time_valid CHECK (
        issued_at_ms BETWEEN 0 AND 9007199254740990
        AND expires_at_ms BETWEEN issued_at_ms + 1 AND 9007199254740991
        AND expires_at_ms - issued_at_ms <= 300000
    )
);

CREATE UNIQUE INDEX agent_run_leases_one_active_per_run
    ON agent.agent_run_leases (tenant_id, run_id) WHERE status = 'active';
CREATE INDEX agent_run_leases_active_connector_idx
    ON agent.agent_run_leases (tenant_id, connector_id) WHERE status = 'active';
CREATE INDEX agent_run_leases_active_binding_idx
    ON agent.agent_run_leases (tenant_id, binding_id) WHERE status = 'active';
CREATE INDEX agent_run_leases_due_idx
    ON agent.agent_run_leases (tenant_id, expires_at_ms, run_id, run_lease_id)
    WHERE status = 'active';

ALTER TABLE agent.agent_runs
    ADD CONSTRAINT agent_runs_current_offer_fk
        FOREIGN KEY (tenant_id, run_id, current_offer_id)
        REFERENCES agent.agent_run_offers (tenant_id, run_id, offer_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT agent_runs_current_lease_fk
        FOREIGN KEY (tenant_id, run_id, current_run_lease_id)
        REFERENCES agent.agent_run_leases (tenant_id, run_id, run_lease_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION agent.enforce_agent_run_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent Run heads cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.tenant_id, NEW.run_id, NEW.request_id, NEW.idempotency_digest,
               NEW.request_digest, NEW.installation_id, NEW.conversation_id,
               NEW.request_event_id, NEW.preferred_connector_id,
               NEW.required_capability_codes, NEW.dispatch_mode, NEW.routing_policy,
               NEW.routing_policy_revision, NEW.grant_version, NEW.queue_deadline_ms,
               NEW.candidate_count, NEW.created_at_ms)
           IS DISTINCT FROM
           ROW(OLD.tenant_id, OLD.run_id, OLD.request_id, OLD.idempotency_digest,
               OLD.request_digest, OLD.installation_id, OLD.conversation_id,
               OLD.request_event_id, OLD.preferred_connector_id,
               OLD.required_capability_codes, OLD.dispatch_mode, OLD.routing_policy,
               OLD.routing_policy_revision, OLD.grant_version, OLD.queue_deadline_ms,
               OLD.candidate_count, OLD.created_at_ms)
        THEN
            RAISE EXCEPTION 'Agent Run immutable request changed' USING ERRCODE = '23514';
        END IF;
        IF NEW.aggregate_revision <> OLD.aggregate_revision + 1
           OR NEW.server_time_high_water_ms < OLD.server_time_high_water_ms
           OR NEW.updated_at_ms < OLD.updated_at_ms
           OR NEW.highest_offer_attempt < OLD.highest_offer_attempt
           OR NEW.highest_run_lease_epoch < OLD.highest_run_lease_epoch
        THEN
            RAISE EXCEPTION 'Agent Run revision or server time is not monotonic'
                USING ERRCODE = '23514';
        END IF;
        IF NOT (
            (OLD.state = 'queued' AND NEW.state IN ('queued', 'offered', 'expired'))
            OR (OLD.state = 'offered' AND NEW.state IN ('queued', 'leased', 'expired'))
            OR (OLD.state = 'leased' AND NEW.state = 'reconcile_required')
        ) THEN
            RAISE EXCEPTION 'Agent Run state transition is invalid' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER agent_run_head_transition
BEFORE UPDATE OR DELETE ON agent.agent_runs
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_head_transition();

CREATE TRIGGER agent_run_candidates_immutable
BEFORE UPDATE OR DELETE ON agent.agent_run_candidates
FOR EACH ROW EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE FUNCTION agent.enforce_agent_run_offer_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent Run offers cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF ROW(NEW.tenant_id, NEW.run_id, NEW.offer_id, NEW.offer_attempt,
           NEW.connector_offer_sequence, NEW.candidate_ordinal, NEW.binding_id,
           NEW.connector_id, NEW.connector_boot_id, NEW.connector_generation,
           NEW.connector_lease_id, NEW.connector_lease_epoch,
           NEW.offered_at_ms, NEW.expires_at_ms)
       IS DISTINCT FROM
       ROW(OLD.tenant_id, OLD.run_id, OLD.offer_id, OLD.offer_attempt,
           OLD.connector_offer_sequence, OLD.candidate_ordinal, OLD.binding_id,
           OLD.connector_id, OLD.connector_boot_id, OLD.connector_generation,
           OLD.connector_lease_id, OLD.connector_lease_epoch,
           OLD.offered_at_ms, OLD.expires_at_ms)
       OR OLD.status <> 'offered' OR NEW.status NOT IN ('claimed', 'expired')
    THEN
        RAISE EXCEPTION 'Agent Run offer transition is invalid' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER agent_run_offer_transition
BEFORE UPDATE OR DELETE ON agent.agent_run_offers
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_offer_transition();

CREATE FUNCTION agent.enforce_agent_run_lease_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent Run leases cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF ROW(NEW.tenant_id, NEW.run_id, NEW.run_lease_id, NEW.run_lease_epoch,
           NEW.offer_id, NEW.offer_attempt, NEW.candidate_ordinal, NEW.binding_id,
           NEW.connector_id, NEW.connector_boot_id, NEW.connector_generation,
           NEW.connector_lease_id, NEW.connector_lease_epoch,
           NEW.issued_at_ms, NEW.expires_at_ms)
       IS DISTINCT FROM
       ROW(OLD.tenant_id, OLD.run_id, OLD.run_lease_id, OLD.run_lease_epoch,
           OLD.offer_id, OLD.offer_attempt, OLD.candidate_ordinal, OLD.binding_id,
           OLD.connector_id, OLD.connector_boot_id, OLD.connector_generation,
           OLD.connector_lease_id, OLD.connector_lease_epoch,
           OLD.issued_at_ms, OLD.expires_at_ms)
       OR OLD.status <> 'active' OR NEW.status NOT IN ('released', 'expired')
    THEN
        RAISE EXCEPTION 'Agent Run lease transition is invalid' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER agent_run_lease_transition
BEFORE UPDATE OR DELETE ON agent.agent_run_leases
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_lease_transition();

CREATE FUNCTION agent.enforce_connector_run_capacity_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent Run capacity heads cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF NEW.tenant_id <> OLD.tenant_id
       OR NEW.capacity_revision <> OLD.capacity_revision + 1
       OR NEW.updated_at_ms < OLD.updated_at_ms
       OR abs(NEW.active_reservation_count - OLD.active_reservation_count) > 1
    THEN
        RAISE EXCEPTION 'Agent Run capacity transition is invalid' USING ERRCODE = '23514';
    END IF;
    IF NEW.connector_id <> OLD.connector_id
       OR NEW.last_offer_sequence < OLD.last_offer_sequence
    THEN
        RAISE EXCEPTION 'Connector Run capacity transition is invalid' USING ERRCODE = '23514';
    END IF;
    IF ROW(NEW.observation_lease_id, NEW.observation_heartbeat_sequence,
           NEW.observation_claim_revision)
       IS DISTINCT FROM
       ROW(OLD.observation_lease_id, OLD.observation_heartbeat_sequence,
           OLD.observation_claim_revision)
    THEN
        IF NEW.observation_lease_id IS NULL
           OR NEW.observation_reservation_baseline <> OLD.active_reservation_count
           OR (NEW.observation_lease_id = OLD.observation_lease_id
               AND (NEW.observation_heartbeat_sequence <= OLD.observation_heartbeat_sequence
                    OR NEW.observation_claim_revision <= OLD.observation_claim_revision))
        THEN
            RAISE EXCEPTION 'Connector Run capacity observation is invalid'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.observation_reservation_baseline <> OLD.observation_reservation_baseline
       OR NEW.observation_available_count <> OLD.observation_available_count
    THEN
        RAISE EXCEPTION 'Connector Run capacity observation changed without a new report'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_run_capacity_head_transition
BEFORE UPDATE OR DELETE ON agent.connector_run_capacity_heads
FOR EACH ROW EXECUTE FUNCTION agent.enforce_connector_run_capacity_head_transition();

CREATE FUNCTION agent.enforce_binding_run_capacity_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent Run capacity heads cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF NEW.tenant_id <> OLD.tenant_id
       OR NEW.binding_id <> OLD.binding_id
       OR NEW.capacity_revision <> OLD.capacity_revision + 1
       OR NEW.updated_at_ms < OLD.updated_at_ms
       OR abs(NEW.active_reservation_count - OLD.active_reservation_count) > 1
    THEN
        RAISE EXCEPTION 'Binding Run capacity transition is invalid' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER binding_run_capacity_head_transition
BEFORE UPDATE OR DELETE ON agent.binding_run_capacity_heads
FOR EACH ROW EXECUTE FUNCTION agent.enforce_binding_run_capacity_head_transition();

CREATE FUNCTION agent.enforce_agent_run_candidate_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_installation uuid;
    binding_installation uuid;
    binding_connector uuid;
    binding_priority integer;
    binding_capacity bigint;
    binding_state text;
BEGIN
    SELECT installation_id INTO STRICT target_installation
      FROM agent.agent_runs WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id;
    SELECT installation_id, connector_id, priority, max_concurrency, state
      INTO STRICT binding_installation, binding_connector, binding_priority,
                  binding_capacity, binding_state
      FROM agent.connector_bindings
     WHERE tenant_id = NEW.tenant_id AND binding_id = NEW.binding_id;
    IF binding_installation <> target_installation OR binding_connector <> NEW.connector_id
       OR binding_priority <> NEW.priority OR binding_capacity <> NEW.max_concurrency
       OR binding_state <> 'enabled'
    THEN
        RAISE EXCEPTION 'Agent Run candidate is outside its explicit target'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER agent_run_candidate_scope
AFTER INSERT ON agent.agent_run_candidates
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_candidate_scope();

CREATE FUNCTION agent.enforce_agent_run_candidate_count()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_count integer;
    run_dispatch text;
    preferred_connector uuid;
    actual_count bigint;
    minimum_ordinal integer;
    maximum_ordinal integer;
BEGIN
    SELECT candidate_count, dispatch_mode, preferred_connector_id
      INTO STRICT expected_count, run_dispatch, preferred_connector
      FROM agent.agent_runs WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id;
    SELECT count(*), min(candidate_ordinal), max(candidate_ordinal)
      INTO actual_count, minimum_ordinal, maximum_ordinal
      FROM agent.agent_run_candidates WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id;
    IF actual_count <> expected_count
       OR minimum_ordinal <> 0
       OR maximum_ordinal <> expected_count - 1
       OR (preferred_connector IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM agent.agent_run_candidates
             WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id
               AND candidate_ordinal = 0 AND connector_id = preferred_connector
       ))
       OR (run_dispatch = 'failover' AND EXISTS (
            SELECT 1
              FROM agent.agent_run_candidates current_candidate
              JOIN agent.agent_run_candidates next_candidate
                ON next_candidate.tenant_id = current_candidate.tenant_id
               AND next_candidate.run_id = current_candidate.run_id
               AND next_candidate.candidate_ordinal = current_candidate.candidate_ordinal + 1
             WHERE current_candidate.tenant_id = NEW.tenant_id
               AND current_candidate.run_id = NEW.run_id
               AND next_candidate.priority <= current_candidate.priority
       ))
    THEN
        RAISE EXCEPTION 'Agent Run candidate set is not canonical' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER agent_run_candidate_count_from_run
AFTER INSERT ON agent.agent_runs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_candidate_count();
CREATE CONSTRAINT TRIGGER agent_run_candidate_count_from_candidate
AFTER INSERT ON agent.agent_run_candidates
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_candidate_count();

CREATE FUNCTION agent.enforce_agent_run_offer_bundle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    run_deadline bigint;
    lease_boot uuid;
    lease_generation bigint;
    lease_epoch bigint;
    lease_expiry bigint;
BEGIN
    SELECT r.queue_deadline_ms INTO STRICT run_deadline
      FROM agent.agent_runs AS r
     WHERE r.tenant_id = NEW.tenant_id AND r.run_id = NEW.run_id;
    SELECT l.boot_id, l.generation, l.lease_epoch, l.expires_at_ms
      INTO STRICT lease_boot, lease_generation, lease_epoch, lease_expiry
      FROM agent.connector_leases AS l
     WHERE l.tenant_id = NEW.tenant_id AND l.connector_id = NEW.connector_id
       AND l.lease_id = NEW.connector_lease_id;
    IF NEW.expires_at_ms > run_deadline OR NEW.expires_at_ms > lease_expiry
       OR NEW.connector_boot_id <> lease_boot
       OR NEW.connector_generation <> lease_generation
       OR NEW.connector_lease_epoch <> lease_epoch
    THEN
        RAISE EXCEPTION 'Agent Run offer fence is inconsistent' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER agent_run_offer_bundle
AFTER INSERT OR UPDATE ON agent.agent_run_offers
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_offer_bundle();

CREATE FUNCTION agent.enforce_agent_run_lease_bundle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    offered agent.agent_run_offers%ROWTYPE;
    control_expiry bigint;
BEGIN
    SELECT o.* INTO STRICT offered
      FROM agent.agent_run_offers AS o
     WHERE o.tenant_id = NEW.tenant_id AND o.run_id = NEW.run_id
       AND o.offer_id = NEW.offer_id;
    SELECT l.expires_at_ms INTO STRICT control_expiry
      FROM agent.connector_leases AS l
     WHERE l.tenant_id = NEW.tenant_id AND l.connector_id = NEW.connector_id
       AND l.lease_id = NEW.connector_lease_id;
    IF offered.offer_attempt <> NEW.offer_attempt
       OR offered.candidate_ordinal <> NEW.candidate_ordinal
       OR offered.binding_id <> NEW.binding_id OR offered.connector_id <> NEW.connector_id
       OR offered.connector_boot_id <> NEW.connector_boot_id
       OR offered.connector_generation <> NEW.connector_generation
       OR offered.connector_lease_id <> NEW.connector_lease_id
       OR offered.connector_lease_epoch <> NEW.connector_lease_epoch
       OR NEW.expires_at_ms > control_expiry
    THEN
        RAISE EXCEPTION 'Agent Run lease fence is inconsistent' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER agent_run_lease_bundle
AFTER INSERT OR UPDATE ON agent.agent_run_leases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_lease_bundle();

CREATE FUNCTION agent.enforce_agent_run_state_bundle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    run_head agent.agent_runs%ROWTYPE;
    current_offer_status text;
    current_offer_attempt bigint;
    current_offer_candidate integer;
    current_lease_status text;
    current_lease_epoch bigint;
    current_lease_offer uuid;
    current_lease_attempt bigint;
    current_lease_candidate integer;
    active_offer_count bigint;
    active_lease_count bigint;
BEGIN
    SELECT * INTO STRICT run_head
      FROM agent.agent_runs
     WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id;

    SELECT count(*) FILTER (WHERE status = 'offered')
      INTO active_offer_count
      FROM agent.agent_run_offers
     WHERE tenant_id = run_head.tenant_id AND run_id = run_head.run_id;
    SELECT count(*) FILTER (WHERE status = 'active')
      INTO active_lease_count
      FROM agent.agent_run_leases
     WHERE tenant_id = run_head.tenant_id AND run_id = run_head.run_id;

    IF run_head.current_offer_id IS NOT NULL THEN
        SELECT status, offer_attempt, candidate_ordinal
          INTO current_offer_status, current_offer_attempt, current_offer_candidate
          FROM agent.agent_run_offers
         WHERE tenant_id = run_head.tenant_id AND run_id = run_head.run_id
           AND offer_id = run_head.current_offer_id;
    END IF;
    IF run_head.current_run_lease_id IS NOT NULL THEN
        SELECT status, run_lease_epoch, offer_id, offer_attempt, candidate_ordinal
          INTO current_lease_status, current_lease_epoch, current_lease_offer,
               current_lease_attempt, current_lease_candidate
          FROM agent.agent_run_leases
         WHERE tenant_id = run_head.tenant_id AND run_id = run_head.run_id
           AND run_lease_id = run_head.current_run_lease_id;
    END IF;

    IF run_head.state IN ('queued', 'expired') THEN
        IF active_offer_count <> 0 OR active_lease_count <> 0 THEN
            RAISE EXCEPTION 'Queued or expired Agent Run retains active routing rows'
                USING ERRCODE = '23514';
        END IF;
    ELSIF run_head.state = 'offered' THEN
        IF active_offer_count <> 1 OR active_lease_count <> 0
           OR current_offer_status IS DISTINCT FROM 'offered'
           OR current_offer_attempt IS DISTINCT FROM run_head.highest_offer_attempt
           OR current_offer_candidate IS DISTINCT FROM run_head.candidate_cursor
        THEN
            RAISE EXCEPTION 'Offered Agent Run head diverges from its offer'
                USING ERRCODE = '23514';
        END IF;
    ELSIF run_head.state = 'leased' THEN
        IF active_offer_count <> 0 OR active_lease_count <> 1
           OR current_offer_status IS DISTINCT FROM 'claimed'
           OR current_lease_status IS DISTINCT FROM 'active'
           OR current_lease_offer IS DISTINCT FROM run_head.current_offer_id
           OR current_lease_attempt IS DISTINCT FROM current_offer_attempt
           OR current_lease_candidate IS DISTINCT FROM run_head.candidate_cursor
           OR current_lease_epoch IS DISTINCT FROM run_head.highest_run_lease_epoch
        THEN
            RAISE EXCEPTION 'Leased Agent Run head diverges from its lease'
                USING ERRCODE = '23514';
        END IF;
    ELSIF run_head.state = 'reconcile_required' THEN
        IF active_offer_count <> 0 OR active_lease_count <> 0
           OR current_offer_status IS DISTINCT FROM 'claimed'
           OR current_lease_status IS NULL
           OR current_lease_status NOT IN ('released', 'expired')
           OR current_lease_offer IS DISTINCT FROM run_head.current_offer_id
           OR current_lease_attempt IS DISTINCT FROM current_offer_attempt
           OR current_lease_candidate IS DISTINCT FROM run_head.candidate_cursor
           OR current_lease_epoch IS DISTINCT FROM run_head.highest_run_lease_epoch
        THEN
            RAISE EXCEPTION 'Reconciled Agent Run head diverges from terminal lease status'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER agent_run_state_bundle_from_run
AFTER INSERT OR UPDATE ON agent.agent_runs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_state_bundle();
CREATE CONSTRAINT TRIGGER agent_run_state_bundle_from_offer
AFTER INSERT OR UPDATE ON agent.agent_run_offers
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_state_bundle();
CREATE CONSTRAINT TRIGGER agent_run_state_bundle_from_lease
AFTER INSERT OR UPDATE ON agent.agent_run_leases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_state_bundle();

CREATE FUNCTION agent.notify_agent_run_offer()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('dtx_agent_run_offer_v1', NEW.tenant_id::text || ':' || NEW.connector_id::text);
    RETURN NULL;
END
$$;

CREATE TRIGGER agent_run_offer_notify
AFTER INSERT ON agent.agent_run_offers
FOR EACH ROW EXECUTE FUNCTION agent.notify_agent_run_offer();

ALTER TABLE agent.agent_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_runs
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.agent_run_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_candidates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_candidates
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_run_capacity_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_run_capacity_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_run_capacity_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.binding_run_capacity_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.binding_run_capacity_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.binding_run_capacity_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.agent_run_offers ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_offers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_offers
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.agent_run_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_leases FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_leases
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.agent_runs FROM PUBLIC;
REVOKE ALL ON agent.agent_run_candidates FROM PUBLIC;
REVOKE ALL ON agent.connector_run_capacity_heads FROM PUBLIC;
REVOKE ALL ON agent.binding_run_capacity_heads FROM PUBLIC;
REVOKE ALL ON agent.agent_run_offers FROM PUBLIC;
REVOKE ALL ON agent.agent_run_leases FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.router_stable_names(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_offer_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_lease_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_run_capacity_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_binding_run_capacity_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_candidate_scope() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_candidate_count() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_offer_bundle() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_lease_bundle() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.notify_agent_run_offer() FROM PUBLIC;
