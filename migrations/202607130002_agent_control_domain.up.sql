CREATE SCHEMA agent;

CREATE FUNCTION agent.is_public_id(candidate text, expected_prefix text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT expected_prefix IN ('dtxi1', 'dtxa1')
       AND octet_length(candidate) = 57
       AND left(candidate, 5) = expected_prefix
       AND substring(candidate FROM 6) ~ '^[a-z2-7]{51}[aq]$'
$$;

CREATE FUNCTION agent.reject_immutable_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
        USING ERRCODE = '55000';
END
$$;

CREATE TABLE agent.agent_definition_heads (
    agent_id text PRIMARY KEY,
    publisher_id text NOT NULL,
    current_version bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT agent_definition_heads_publisher_scope_unique
        UNIQUE (agent_id, publisher_id),
    CONSTRAINT agent_definition_heads_version_scope_unique
        UNIQUE (agent_id, current_version),
    CONSTRAINT agent_definition_heads_agent_id_valid
        CHECK (agent.is_public_id(agent_id, 'dtxa1')),
    CONSTRAINT agent_definition_heads_publisher_id_valid
        CHECK (agent.is_public_id(publisher_id, 'dtxi1')),
    CONSTRAINT agent_definition_heads_version_safe
        CHECK (current_version BETWEEN 1 AND 9007199254740991),
    CONSTRAINT agent_definition_heads_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT agent_definition_heads_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE TABLE agent.agent_definitions (
    agent_id text NOT NULL,
    definition_version bigint NOT NULL,
    publisher_id text NOT NULL,
    descriptor_hash bytea NOT NULL,
    expires_at_ms bigint NOT NULL,
    admitted_at_ms bigint NOT NULL,
    PRIMARY KEY (agent_id, definition_version),
    CONSTRAINT agent_definitions_content_unique
        UNIQUE (agent_id, definition_version, descriptor_hash),
    CONSTRAINT agent_definitions_publisher_fk
        FOREIGN KEY (agent_id, publisher_id)
        REFERENCES agent.agent_definition_heads (agent_id, publisher_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_definitions_agent_id_valid
        CHECK (agent.is_public_id(agent_id, 'dtxa1')),
    CONSTRAINT agent_definitions_publisher_id_valid
        CHECK (agent.is_public_id(publisher_id, 'dtxi1')),
    CONSTRAINT agent_definitions_version_safe
        CHECK (definition_version BETWEEN 1 AND 9007199254740991),
    CONSTRAINT agent_definitions_descriptor_hash_size
        CHECK (octet_length(descriptor_hash) = 32),
    CONSTRAINT agent_definitions_admitted_at_valid
        CHECK (admitted_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT agent_definitions_expires_at_valid
        CHECK (
            expires_at_ms BETWEEN -62135596800000 AND 253402300799999
            AND expires_at_ms > admitted_at_ms
        )
);

ALTER TABLE agent.agent_definition_heads
    ADD CONSTRAINT agent_definition_heads_current_definition_fk
    FOREIGN KEY (agent_id, current_version)
    REFERENCES agent.agent_definitions (agent_id, definition_version)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION agent.enforce_definition_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent definition heads cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.agent_id IS DISTINCT FROM OLD.agent_id
       OR NEW.publisher_id IS DISTINCT FROM OLD.publisher_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.current_version <= OLD.current_version
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Agent definition head transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER agent_definition_heads_transition
BEFORE UPDATE OR DELETE ON agent.agent_definition_heads
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_definition_head_transition();

CREATE FUNCTION agent.enforce_definition_admission()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    head agent.agent_definition_heads%ROWTYPE;
    existing agent.agent_definitions%ROWTYPE;
BEGIN
    SELECT * INTO existing
      FROM agent.agent_definitions
     WHERE agent_id = NEW.agent_id
       AND definition_version = NEW.definition_version;
    IF FOUND THEN
        IF existing.publisher_id IS DISTINCT FROM NEW.publisher_id
           OR existing.descriptor_hash IS DISTINCT FROM NEW.descriptor_hash
           OR existing.expires_at_ms IS DISTINCT FROM NEW.expires_at_ms THEN
            RAISE EXCEPTION 'Agent definition version content conflicts'
                USING ERRCODE = '23505';
        END IF;
        RETURN NEW;
    END IF;

    INSERT INTO agent.agent_definition_heads (
        agent_id, publisher_id, current_version, created_at_ms, updated_at_ms
    ) VALUES (
        NEW.agent_id, NEW.publisher_id, NEW.definition_version,
        NEW.admitted_at_ms, NEW.admitted_at_ms
    ) ON CONFLICT (agent_id) DO NOTHING;

    SELECT * INTO STRICT head
      FROM agent.agent_definition_heads
     WHERE agent_id = NEW.agent_id
     FOR UPDATE;
    IF head.publisher_id IS DISTINCT FROM NEW.publisher_id THEN
        RAISE EXCEPTION 'Agent definition publisher cannot change'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.definition_version < head.current_version THEN
        RAISE EXCEPTION 'Agent definition version cannot regress'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.definition_version > head.current_version THEN
        UPDATE agent.agent_definition_heads
           SET current_version = NEW.definition_version,
               updated_at_ms = NEW.admitted_at_ms
         WHERE agent_id = NEW.agent_id;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER agent_definitions_admission
BEFORE INSERT ON agent.agent_definitions
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_definition_admission();

CREATE TRIGGER agent_definitions_append_only
BEFORE UPDATE OR DELETE ON agent.agent_definitions
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.installations (
    tenant_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    agent_id text NOT NULL,
    owner_id text NOT NULL,
    execution_mode text NOT NULL,
    descriptor_version bigint NOT NULL,
    descriptor_hash bytea NOT NULL,
    policy_revision bigint NOT NULL,
    desired_state text NOT NULL,
    observed_state text NOT NULL,
    aggregate_revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, installation_id),
    CONSTRAINT installations_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT installations_definition_fk
        FOREIGN KEY (agent_id, descriptor_version, descriptor_hash)
        REFERENCES agent.agent_definitions
            (agent_id, definition_version, descriptor_hash)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT installations_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT installations_installation_id_v7
        CHECK (system.is_uuid_v7(installation_id)),
    CONSTRAINT installations_agent_id_valid
        CHECK (agent.is_public_id(agent_id, 'dtxa1')),
    CONSTRAINT installations_owner_id_valid
        CHECK (agent.is_public_id(owner_id, 'dtxi1')),
    CONSTRAINT installations_execution_mode_valid
        CHECK (execution_mode IN ('connector_managed', 'server_managed')),
    CONSTRAINT installations_descriptor_version_safe
        CHECK (descriptor_version BETWEEN 1 AND 9007199254740991),
    CONSTRAINT installations_descriptor_hash_size
        CHECK (octet_length(descriptor_hash) = 32),
    CONSTRAINT installations_policy_revision_safe
        CHECK (policy_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT installations_desired_state_valid
        CHECK (desired_state IN ('enabled', 'disabled', 'revoked')),
    CONSTRAINT installations_observed_state_valid
        CHECK (observed_state IN ('installing', 'ready', 'degraded', 'upgrade_required')),
    CONSTRAINT installations_aggregate_revision_safe
        CHECK (aggregate_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT installations_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT installations_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE TABLE agent.agent_devices (
    tenant_id uuid NOT NULL,
    agent_device_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    credential_fingerprint bytea NOT NULL,
    state text NOT NULL,
    aggregate_revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, agent_device_id),
    CONSTRAINT agent_devices_installation_scope_unique
        UNIQUE (tenant_id, installation_id, agent_device_id),
    CONSTRAINT agent_devices_credential_unique
        UNIQUE (tenant_id, credential_fingerprint),
    CONSTRAINT agent_devices_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_devices_installation_fk
        FOREIGN KEY (tenant_id, installation_id)
        REFERENCES agent.installations (tenant_id, installation_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_devices_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT agent_devices_agent_device_id_v7
        CHECK (system.is_uuid_v7(agent_device_id)),
    CONSTRAINT agent_devices_installation_id_v7
        CHECK (system.is_uuid_v7(installation_id)),
    CONSTRAINT agent_devices_credential_fingerprint_size
        CHECK (octet_length(credential_fingerprint) = 32),
    CONSTRAINT agent_devices_state_valid
        CHECK (state IN ('provisioning', 'active', 'revoked')),
    CONSTRAINT agent_devices_aggregate_revision_safe
        CHECK (aggregate_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT agent_devices_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT agent_devices_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE TABLE agent.hosts (
    tenant_id uuid NOT NULL,
    host_id uuid NOT NULL,
    owner_id text NOT NULL,
    lifecycle text NOT NULL,
    desired_revision bigint NOT NULL,
    observed_revision bigint,
    reported_health text,
    heartbeat_observed_at_ms bigint,
    heartbeat_expires_at_ms bigint,
    aggregate_revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, host_id),
    CONSTRAINT hosts_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT hosts_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT hosts_host_id_v7
        CHECK (system.is_uuid_v7(host_id)),
    CONSTRAINT hosts_owner_id_valid
        CHECK (agent.is_public_id(owner_id, 'dtxi1')),
    CONSTRAINT hosts_lifecycle_valid
        CHECK (lifecycle IN ('awaiting_enrollment', 'active', 'quarantined', 'revoked')),
    CONSTRAINT hosts_desired_revision_safe
        CHECK (desired_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT hosts_observed_revision_safe
        CHECK (
            observed_revision IS NULL
            OR observed_revision BETWEEN 1 AND desired_revision
        ),
    CONSTRAINT hosts_reported_health_valid
        CHECK (reported_health IS NULL OR reported_health IN ('healthy', 'degraded')),
    CONSTRAINT hosts_heartbeat_consistent
        CHECK (
            (
                reported_health IS NULL
                AND heartbeat_observed_at_ms IS NULL
                AND heartbeat_expires_at_ms IS NULL
            )
            OR (
                lifecycle = 'active'
                AND reported_health IS NOT NULL
                AND heartbeat_observed_at_ms BETWEEN -62135596800000 AND 253402300799998
                AND heartbeat_expires_at_ms BETWEEN heartbeat_observed_at_ms + 1
                    AND 253402300799999
            )
        ),
    CONSTRAINT hosts_aggregate_revision_safe
        CHECK (aggregate_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT hosts_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT hosts_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE TABLE agent.host_credentials (
    tenant_id uuid NOT NULL,
    host_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    status text NOT NULL,
    PRIMARY KEY (tenant_id, credential_id),
    CONSTRAINT host_credentials_host_credential_unique
        UNIQUE (tenant_id, host_id, credential_id),
    CONSTRAINT host_credentials_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_credentials_host_fk
        FOREIGN KEY (tenant_id, host_id)
        REFERENCES agent.hosts (tenant_id, host_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_credentials_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT host_credentials_host_id_v7
        CHECK (system.is_uuid_v7(host_id)),
    CONSTRAINT host_credentials_credential_id_v7
        CHECK (system.is_uuid_v7(credential_id)),
    CONSTRAINT host_credentials_status_valid
        CHECK (status IN ('current', 'retired'))
);

CREATE UNIQUE INDEX host_credentials_one_current_idx
    ON agent.host_credentials (tenant_id, host_id)
    WHERE status = 'current';

CREATE TABLE agent.connector_instances (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    host_id uuid NOT NULL,
    adapter_kind text NOT NULL,
    generation bigint NOT NULL,
    desired_state text NOT NULL,
    observed_state text NOT NULL,
    max_concurrency bigint NOT NULL,
    spec_revision bigint NOT NULL,
    highest_lease_epoch bigint NOT NULL DEFAULT 0,
    server_time_high_water_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id),
    CONSTRAINT connector_instances_adapter_scope_unique
        UNIQUE (tenant_id, connector_id, adapter_kind),
    CONSTRAINT connector_instances_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_instances_host_fk
        FOREIGN KEY (tenant_id, host_id)
        REFERENCES agent.hosts (tenant_id, host_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_instances_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT connector_instances_connector_id_v7
        CHECK (system.is_uuid_v7(connector_id)),
    CONSTRAINT connector_instances_host_id_v7
        CHECK (system.is_uuid_v7(host_id)),
    CONSTRAINT connector_instances_adapter_kind_valid
        CHECK (adapter_kind IN ('codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp')),
    CONSTRAINT connector_instances_generation_safe
        CHECK (generation BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_instances_desired_state_valid
        CHECK (desired_state IN ('running', 'draining', 'stopped', 'revoked')),
    CONSTRAINT connector_instances_observed_state_valid
        CHECK (
            observed_state IN (
                'enrolling', 'starting', 'ready', 'busy', 'degraded', 'draining',
                'offline', 'failed', 'quarantined', 'revoked'
            )
        ),
    CONSTRAINT connector_instances_revocation_consistent
        CHECK (desired_state <> 'revoked' OR observed_state = 'revoked'),
    CONSTRAINT connector_instances_max_concurrency_valid
        CHECK (max_concurrency BETWEEN 1 AND 4294967295),
    CONSTRAINT connector_instances_spec_revision_safe
        CHECK (spec_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_instances_highest_lease_epoch_safe
        CHECK (highest_lease_epoch BETWEEN 0 AND 9007199254740991),
    CONSTRAINT connector_instances_server_time_valid
        CHECK (
            server_time_high_water_ms IS NULL
            OR server_time_high_water_ms BETWEEN -62135596800000 AND 253402300799999
        ),
    CONSTRAINT connector_instances_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT connector_instances_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE TABLE agent.connector_revisions (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    spec_revision bigint NOT NULL,
    generation bigint NOT NULL,
    adapter_kind text NOT NULL,
    desired_state text NOT NULL,
    max_concurrency bigint NOT NULL,
    recorded_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id, spec_revision),
    CONSTRAINT connector_revisions_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_revisions_connector_fk
        FOREIGN KEY (tenant_id, connector_id, adapter_kind)
        REFERENCES agent.connector_instances (tenant_id, connector_id, adapter_kind)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_revisions_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT connector_revisions_connector_id_v7
        CHECK (system.is_uuid_v7(connector_id)),
    CONSTRAINT connector_revisions_spec_revision_safe
        CHECK (spec_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_revisions_generation_safe
        CHECK (generation BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_revisions_adapter_kind_valid
        CHECK (adapter_kind IN ('codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp')),
    CONSTRAINT connector_revisions_desired_state_valid
        CHECK (desired_state IN ('running', 'draining', 'stopped', 'revoked')),
    CONSTRAINT connector_revisions_max_concurrency_valid
        CHECK (max_concurrency BETWEEN 1 AND 4294967295),
    CONSTRAINT connector_revisions_recorded_at_valid
        CHECK (recorded_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TRIGGER connector_revisions_append_only
BEFORE UPDATE OR DELETE ON agent.connector_revisions
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.connector_boots (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    boot_id uuid NOT NULL,
    boot_sequence bigint NOT NULL,
    generation bigint NOT NULL,
    started_at_ms bigint NOT NULL,
    ended_at_ms bigint,
    PRIMARY KEY (tenant_id, connector_id, boot_id),
    CONSTRAINT connector_boots_fence_unique
        UNIQUE (tenant_id, connector_id, boot_id, generation),
    CONSTRAINT connector_boots_boot_id_unique
        UNIQUE (tenant_id, boot_id),
    CONSTRAINT connector_boots_sequence_unique
        UNIQUE (tenant_id, connector_id, boot_sequence),
    CONSTRAINT connector_boots_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_boots_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_boots_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT connector_boots_connector_id_v7
        CHECK (system.is_uuid_v7(connector_id)),
    CONSTRAINT connector_boots_boot_id_v7
        CHECK (system.is_uuid_v7(boot_id)),
    CONSTRAINT connector_boots_sequence_safe
        CHECK (boot_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_boots_generation_safe
        CHECK (generation BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_boots_started_at_valid
        CHECK (started_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT connector_boots_ended_at_valid
        CHECK (
            ended_at_ms IS NULL
            OR ended_at_ms BETWEEN started_at_ms AND 253402300799999
        )
);

CREATE UNIQUE INDEX connector_boots_one_current_idx
    ON agent.connector_boots (tenant_id, connector_id)
    WHERE ended_at_ms IS NULL;

CREATE TABLE agent.connector_leases (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    boot_id uuid NOT NULL,
    generation bigint NOT NULL,
    lease_epoch bigint NOT NULL,
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    ttl_ms bigint NOT NULL,
    status text NOT NULL,
    last_heartbeat_sequence bigint NOT NULL DEFAULT 0,
    last_heartbeat_at_ms bigint,
    observed_state text,
    capacity_available bigint,
    PRIMARY KEY (tenant_id, connector_id, lease_id),
    CONSTRAINT connector_leases_lease_id_unique
        UNIQUE (tenant_id, lease_id),
    CONSTRAINT connector_leases_epoch_unique
        UNIQUE (tenant_id, connector_id, lease_epoch),
    CONSTRAINT connector_leases_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_leases_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_leases_boot_fk
        FOREIGN KEY (tenant_id, connector_id, boot_id, generation)
        REFERENCES agent.connector_boots (tenant_id, connector_id, boot_id, generation)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_leases_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT connector_leases_connector_id_v7
        CHECK (system.is_uuid_v7(connector_id)),
    CONSTRAINT connector_leases_lease_id_v7
        CHECK (system.is_uuid_v7(lease_id)),
    CONSTRAINT connector_leases_boot_id_v7
        CHECK (system.is_uuid_v7(boot_id)),
    CONSTRAINT connector_leases_generation_safe
        CHECK (generation BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_leases_epoch_safe
        CHECK (lease_epoch BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_leases_issued_at_valid
        CHECK (issued_at_ms BETWEEN -62135596800000 AND 253402300799998),
    CONSTRAINT connector_leases_ttl_valid
        CHECK (ttl_ms BETWEEN 1 AND 86400000),
    CONSTRAINT connector_leases_expires_at_valid
        CHECK (expires_at_ms BETWEEN issued_at_ms + 1 AND 253402300799999),
    CONSTRAINT connector_leases_status_valid
        CHECK (status IN ('active', 'expired', 'revoked', 'superseded')),
    CONSTRAINT connector_leases_heartbeat_sequence_safe
        CHECK (last_heartbeat_sequence BETWEEN 0 AND 9007199254740991),
    CONSTRAINT connector_leases_observed_state_valid
        CHECK (
            observed_state IS NULL
            OR observed_state IN (
                'enrolling', 'starting', 'ready', 'busy', 'degraded', 'draining',
                'failed', 'quarantined'
            )
        ),
    CONSTRAINT connector_leases_heartbeat_consistent
        CHECK (
            (
                last_heartbeat_sequence = 0
                AND last_heartbeat_at_ms IS NULL
                AND observed_state IS NULL
                AND capacity_available IS NULL
                AND expires_at_ms = issued_at_ms + ttl_ms
            )
            OR (
                last_heartbeat_sequence BETWEEN 1 AND 9007199254740991
                AND last_heartbeat_at_ms BETWEEN issued_at_ms AND 253402300799999
                AND observed_state IS NOT NULL
                AND capacity_available BETWEEN 0 AND 4294967295
                AND expires_at_ms = last_heartbeat_at_ms + ttl_ms
            )
        )
);

CREATE UNIQUE INDEX connector_leases_one_active_idx
    ON agent.connector_leases (tenant_id, connector_id)
    WHERE status = 'active';

CREATE TABLE agent.connector_conformance (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    adapter_kind text NOT NULL,
    registry_revision bigint NOT NULL,
    supports_multi_session boolean NOT NULL,
    admitted_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id),
    CONSTRAINT connector_conformance_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_conformance_connector_fk
        FOREIGN KEY (tenant_id, connector_id, adapter_kind)
        REFERENCES agent.connector_instances (tenant_id, connector_id, adapter_kind)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_conformance_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT connector_conformance_connector_id_v7
        CHECK (system.is_uuid_v7(connector_id)),
    CONSTRAINT connector_conformance_adapter_kind_valid
        CHECK (adapter_kind IN ('codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp')),
    CONSTRAINT connector_conformance_registry_revision_safe
        CHECK (registry_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_conformance_admitted_at_valid
        CHECK (admitted_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TRIGGER connector_conformance_append_only
BEFORE UPDATE OR DELETE ON agent.connector_conformance
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.binding_set_heads (
    tenant_id uuid PRIMARY KEY,
    mutation_sequence bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT binding_set_heads_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT binding_set_heads_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT binding_set_heads_sequence_safe
        CHECK (mutation_sequence BETWEEN 0 AND 9007199254740991),
    CONSTRAINT binding_set_heads_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT binding_set_heads_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE FUNCTION agent.enforce_binding_set_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Binding Set heads cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.mutation_sequence <> OLD.mutation_sequence + 1
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Binding Set head transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER binding_set_heads_transition
BEFORE UPDATE OR DELETE ON agent.binding_set_heads
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_binding_set_head_transition();

CREATE TABLE agent.installation_routing_policies (
    tenant_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    routing_policy text NOT NULL,
    policy_revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, installation_id),
    CONSTRAINT installation_routing_policies_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT installation_routing_policies_installation_fk
        FOREIGN KEY (tenant_id, installation_id)
        REFERENCES agent.installations (tenant_id, installation_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT installation_routing_policies_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT installation_routing_policies_installation_id_v7
        CHECK (system.is_uuid_v7(installation_id)),
    CONSTRAINT installation_routing_policies_policy_valid
        CHECK (routing_policy IN ('exclusive', 'ordered_failover')),
    CONSTRAINT installation_routing_policies_revision_safe
        CHECK (policy_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT installation_routing_policies_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT installation_routing_policies_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE TABLE agent.connector_bindings (
    tenant_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    agent_device_id uuid NOT NULL,
    priority integer NOT NULL,
    max_concurrency bigint NOT NULL,
    state text NOT NULL,
    aggregate_revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, binding_id),
    CONSTRAINT connector_bindings_installation_connector_unique
        UNIQUE (tenant_id, installation_id, connector_id),
    CONSTRAINT connector_bindings_agent_device_unique
        UNIQUE (tenant_id, agent_device_id),
    CONSTRAINT connector_bindings_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_bindings_routing_policy_fk
        FOREIGN KEY (tenant_id, installation_id)
        REFERENCES agent.installation_routing_policies (tenant_id, installation_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_bindings_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_bindings_agent_device_fk
        FOREIGN KEY (tenant_id, installation_id, agent_device_id)
        REFERENCES agent.agent_devices (tenant_id, installation_id, agent_device_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_bindings_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT connector_bindings_binding_id_v7
        CHECK (system.is_uuid_v7(binding_id)),
    CONSTRAINT connector_bindings_installation_id_v7
        CHECK (system.is_uuid_v7(installation_id)),
    CONSTRAINT connector_bindings_connector_id_v7
        CHECK (system.is_uuid_v7(connector_id)),
    CONSTRAINT connector_bindings_agent_device_id_v7
        CHECK (system.is_uuid_v7(agent_device_id)),
    CONSTRAINT connector_bindings_priority_valid
        CHECK (priority BETWEEN 0 AND 65535),
    CONSTRAINT connector_bindings_max_concurrency_valid
        CHECK (max_concurrency BETWEEN 1 AND 4294967295),
    CONSTRAINT connector_bindings_state_valid
        CHECK (state IN ('disabled', 'enabled', 'revoked')),
    CONSTRAINT connector_bindings_revision_safe
        CHECK (aggregate_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_bindings_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT connector_bindings_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE TABLE agent.conversation_grant_ids (
    tenant_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    reserved_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, grant_id),
    CONSTRAINT conversation_grant_ids_scope_unique
        UNIQUE (tenant_id, conversation_id, installation_id, grant_id),
    CONSTRAINT conversation_grant_ids_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_grant_ids_installation_fk
        FOREIGN KEY (tenant_id, installation_id)
        REFERENCES agent.installations (tenant_id, installation_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_grant_ids_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT conversation_grant_ids_grant_id_v7
        CHECK (system.is_uuid_v7(grant_id)),
    CONSTRAINT conversation_grant_ids_conversation_id_v7
        CHECK (system.is_uuid_v7(conversation_id)),
    CONSTRAINT conversation_grant_ids_installation_id_v7
        CHECK (system.is_uuid_v7(installation_id)),
    CONSTRAINT conversation_grant_ids_reserved_at_valid
        CHECK (reserved_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TRIGGER conversation_grant_ids_append_only
BEFORE UPDATE OR DELETE ON agent.conversation_grant_ids
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.conversation_grant_versions (
    tenant_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    grant_version bigint NOT NULL,
    grant_id uuid NOT NULL,
    trigger_policy text NOT NULL,
    privacy_policy_hash bytea NOT NULL,
    approved_by_device_id uuid NOT NULL,
    approved_at_ms bigint NOT NULL,
    expires_at_ms bigint,
    revoked_at_ms bigint,
    recorded_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, conversation_id, installation_id, grant_version),
    CONSTRAINT conversation_grant_versions_head_target_unique
        UNIQUE (
            tenant_id, conversation_id, installation_id, grant_version, grant_id
        ),
    CONSTRAINT conversation_grant_versions_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_grant_versions_grant_id_fk
        FOREIGN KEY (tenant_id, conversation_id, installation_id, grant_id)
        REFERENCES agent.conversation_grant_ids
            (tenant_id, conversation_id, installation_id, grant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_grant_versions_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT conversation_grant_versions_conversation_id_v7
        CHECK (system.is_uuid_v7(conversation_id)),
    CONSTRAINT conversation_grant_versions_installation_id_v7
        CHECK (system.is_uuid_v7(installation_id)),
    CONSTRAINT conversation_grant_versions_grant_id_v7
        CHECK (system.is_uuid_v7(grant_id)),
    CONSTRAINT conversation_grant_versions_grant_version_safe
        CHECK (grant_version BETWEEN 1 AND 9007199254740991),
    CONSTRAINT conversation_grant_versions_trigger_policy_valid
        CHECK (trigger_policy IN ('mention_only', 'explicit_command', 'manual_only', 'all_messages')),
    CONSTRAINT conversation_grant_versions_privacy_policy_hash_size
        CHECK (octet_length(privacy_policy_hash) = 32),
    CONSTRAINT conversation_grant_versions_approved_device_id_v7
        CHECK (system.is_uuid_v7(approved_by_device_id)),
    CONSTRAINT conversation_grant_versions_approved_at_valid
        CHECK (approved_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT conversation_grant_versions_expires_at_valid
        CHECK (
            expires_at_ms IS NULL
            OR expires_at_ms BETWEEN approved_at_ms + 1 AND 253402300799999
        ),
    CONSTRAINT conversation_grant_versions_revoked_at_valid
        CHECK (
            revoked_at_ms IS NULL
            OR revoked_at_ms BETWEEN approved_at_ms AND 253402300799999
        ),
    CONSTRAINT conversation_grant_versions_recorded_at_valid
        CHECK (recorded_at_ms BETWEEN approved_at_ms AND 253402300799999)
);

CREATE TRIGGER conversation_grant_versions_append_only
BEFORE UPDATE OR DELETE ON agent.conversation_grant_versions
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.conversation_grant_heads (
    tenant_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    current_grant_version bigint NOT NULL,
    current_grant_id uuid NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, conversation_id, installation_id),
    CONSTRAINT conversation_grant_heads_current_version_unique
        UNIQUE (tenant_id, conversation_id, installation_id, current_grant_version),
    CONSTRAINT conversation_grant_heads_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_grant_heads_current_version_fk
        FOREIGN KEY (
            tenant_id, conversation_id, installation_id,
            current_grant_version, current_grant_id
        )
        REFERENCES agent.conversation_grant_versions (
            tenant_id, conversation_id, installation_id, grant_version, grant_id
        )
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_grant_heads_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT conversation_grant_heads_conversation_id_v7
        CHECK (system.is_uuid_v7(conversation_id)),
    CONSTRAINT conversation_grant_heads_installation_id_v7
        CHECK (system.is_uuid_v7(installation_id)),
    CONSTRAINT conversation_grant_heads_current_grant_id_v7
        CHECK (system.is_uuid_v7(current_grant_id)),
    CONSTRAINT conversation_grant_heads_version_safe
        CHECK (current_grant_version BETWEEN 1 AND 9007199254740991),
    CONSTRAINT conversation_grant_heads_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT conversation_grant_heads_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE TABLE agent.conversation_grant_permissions (
    tenant_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    grant_version bigint NOT NULL,
    permission text NOT NULL,
    PRIMARY KEY (
        tenant_id, conversation_id, installation_id, grant_version, permission
    ),
    CONSTRAINT conversation_grant_permissions_version_fk
        FOREIGN KEY (tenant_id, conversation_id, installation_id, grant_version)
        REFERENCES agent.conversation_grant_versions
            (tenant_id, conversation_id, installation_id, grant_version)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_grant_permissions_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT conversation_grant_permissions_conversation_id_v7
        CHECK (system.is_uuid_v7(conversation_id)),
    CONSTRAINT conversation_grant_permissions_installation_id_v7
        CHECK (system.is_uuid_v7(installation_id)),
    CONSTRAINT conversation_grant_permissions_version_safe
        CHECK (grant_version BETWEEN 1 AND 9007199254740991),
    CONSTRAINT conversation_grant_permissions_permission_valid
        CHECK (
            permission IN (
                'read_future_messages', 'read_shared_history', 'read_attachments',
                'send_messages', 'create_channel_comments', 'invoke_tools',
                'start_server_jobs'
            )
        )
);

CREATE TRIGGER conversation_grant_permissions_append_only
BEFORE UPDATE OR DELETE ON agent.conversation_grant_permissions
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.conversation_grant_cloud_connections (
    tenant_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    grant_version bigint NOT NULL,
    cloud_connection_id uuid NOT NULL,
    PRIMARY KEY (
        tenant_id, conversation_id, installation_id,
        grant_version, cloud_connection_id
    ),
    CONSTRAINT conversation_grant_cloud_connections_version_fk
        FOREIGN KEY (tenant_id, conversation_id, installation_id, grant_version)
        REFERENCES agent.conversation_grant_versions
            (tenant_id, conversation_id, installation_id, grant_version)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_grant_cloud_connections_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT conversation_grant_cloud_connections_conversation_id_v7
        CHECK (system.is_uuid_v7(conversation_id)),
    CONSTRAINT conversation_grant_cloud_connections_installation_id_v7
        CHECK (system.is_uuid_v7(installation_id)),
    CONSTRAINT conversation_grant_cloud_connections_version_safe
        CHECK (grant_version BETWEEN 1 AND 9007199254740991),
    CONSTRAINT conversation_grant_cloud_connections_connection_id_v7
        CHECK (system.is_uuid_v7(cloud_connection_id))
);

CREATE TRIGGER conversation_grant_cloud_connections_append_only
BEFORE UPDATE OR DELETE ON agent.conversation_grant_cloud_connections
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE FUNCTION agent.enforce_host_credential_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'host credential history cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.host_id IS DISTINCT FROM OLD.host_id
       OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR OLD.status <> 'current'
       OR NEW.status <> 'retired' THEN
        RAISE EXCEPTION 'invalid host credential history transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER host_credentials_transition
BEFORE UPDATE OR DELETE ON agent.host_credentials
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_host_credential_transition();

CREATE FUNCTION agent.enforce_connector_boot_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'connector boot history cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
       OR NEW.boot_id IS DISTINCT FROM OLD.boot_id
       OR NEW.boot_sequence IS DISTINCT FROM OLD.boot_sequence
       OR NEW.generation IS DISTINCT FROM OLD.generation
       OR NEW.started_at_ms IS DISTINCT FROM OLD.started_at_ms
       OR OLD.ended_at_ms IS NOT NULL
       OR NEW.ended_at_ms IS NULL THEN
        RAISE EXCEPTION 'invalid connector boot history transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_boots_transition
BEFORE UPDATE OR DELETE ON agent.connector_boots
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_boot_transition();

CREATE FUNCTION agent.enforce_connector_lease_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'connector lease history cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
       OR NEW.lease_id IS DISTINCT FROM OLD.lease_id
       OR NEW.boot_id IS DISTINCT FROM OLD.boot_id
       OR NEW.generation IS DISTINCT FROM OLD.generation
       OR NEW.lease_epoch IS DISTINCT FROM OLD.lease_epoch
       OR NEW.issued_at_ms IS DISTINCT FROM OLD.issued_at_ms
       OR NEW.ttl_ms IS DISTINCT FROM OLD.ttl_ms
       OR OLD.status <> 'active'
       OR NEW.expires_at_ms < OLD.expires_at_ms
       OR NEW.last_heartbeat_sequence < OLD.last_heartbeat_sequence THEN
        RAISE EXCEPTION 'invalid connector lease transition'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.last_heartbeat_sequence = OLD.last_heartbeat_sequence THEN
        IF NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
           OR NEW.last_heartbeat_at_ms IS DISTINCT FROM OLD.last_heartbeat_at_ms
           OR NEW.observed_state IS DISTINCT FROM OLD.observed_state
           OR NEW.capacity_available IS DISTINCT FROM OLD.capacity_available THEN
            RAISE EXCEPTION 'lease heartbeat replay conflicts with accepted payload'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.status NOT IN ('expired', 'revoked', 'superseded') THEN
            RAISE EXCEPTION 'lease update did not advance heartbeat or status'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NEW.last_heartbeat_at_ms IS NULL
           OR (
                OLD.last_heartbeat_at_ms IS NOT NULL
                AND NEW.last_heartbeat_at_ms < OLD.last_heartbeat_at_ms
           ) THEN
            RAISE EXCEPTION 'invalid lease heartbeat advance'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_leases_transition
BEFORE UPDATE OR DELETE ON agent.connector_leases
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_lease_transition();

CREATE FUNCTION agent.enforce_grant_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'conversation grant heads cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
       OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.current_grant_version <> OLD.current_grant_version + 1
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid conversation grant head transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER conversation_grant_heads_transition
BEFORE UPDATE OR DELETE ON agent.conversation_grant_heads
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_grant_head_transition();

CREATE FUNCTION agent.enforce_installation_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent installations cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
       OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
       OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
       OR NEW.execution_mode IS DISTINCT FROM OLD.execution_mode
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.aggregate_revision <> OLD.aggregate_revision + 1
       OR NEW.descriptor_version < OLD.descriptor_version
       OR NEW.policy_revision < OLD.policy_revision
       OR OLD.desired_state = 'revoked'
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Agent installation transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER installations_transition
BEFORE UPDATE OR DELETE ON agent.installations
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_installation_transition();

CREATE FUNCTION agent.enforce_agent_device_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent Devices cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.agent_device_id IS DISTINCT FROM OLD.agent_device_id
       OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
       OR NEW.credential_fingerprint IS DISTINCT FROM OLD.credential_fingerprint
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.aggregate_revision <> OLD.aggregate_revision + 1
       OR OLD.state = 'revoked'
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Agent Device transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER agent_devices_transition
BEFORE UPDATE OR DELETE ON agent.agent_devices
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_agent_device_transition();

CREATE FUNCTION agent.enforce_host_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent Hosts cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.host_id IS DISTINCT FROM OLD.host_id
       OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.aggregate_revision <> OLD.aggregate_revision + 1
       OR NEW.desired_revision < OLD.desired_revision
       OR (
            OLD.observed_revision IS NOT NULL
            AND (
                NEW.observed_revision IS NULL
                OR NEW.observed_revision < OLD.observed_revision
            )
       )
       OR OLD.lifecycle = 'revoked'
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Agent Host transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER hosts_transition
BEFORE UPDATE OR DELETE ON agent.hosts
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_host_transition();

CREATE FUNCTION agent.enforce_connector_instance_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'connector instances cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
       OR NEW.host_id IS DISTINCT FROM OLD.host_id
       OR NEW.adapter_kind IS DISTINCT FROM OLD.adapter_kind
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.generation NOT BETWEEN OLD.generation AND OLD.generation + 1
       OR NEW.spec_revision NOT BETWEEN OLD.spec_revision AND OLD.spec_revision + 1
       OR NEW.highest_lease_epoch NOT BETWEEN OLD.highest_lease_epoch
            AND OLD.highest_lease_epoch + 1
       OR (NEW.generation > OLD.generation AND NEW.spec_revision = OLD.spec_revision)
       OR (
            (
                NEW.desired_state IS DISTINCT FROM OLD.desired_state
                OR NEW.max_concurrency IS DISTINCT FROM OLD.max_concurrency
            )
            AND NEW.spec_revision = OLD.spec_revision
       )
       OR (
            OLD.server_time_high_water_ms IS NOT NULL
            AND (
                NEW.server_time_high_water_ms IS NULL
                OR NEW.server_time_high_water_ms < OLD.server_time_high_water_ms
            )
       )
       OR OLD.desired_state = 'revoked'
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid connector instance transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_instances_transition
BEFORE UPDATE OR DELETE ON agent.connector_instances
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_instance_transition();

CREATE FUNCTION agent.enforce_routing_policy_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'installation routing policies cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.policy_revision <> OLD.policy_revision + 1
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid installation routing policy transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER installation_routing_policies_transition
BEFORE UPDATE OR DELETE ON agent.installation_routing_policies
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_routing_policy_transition();

CREATE FUNCTION agent.enforce_connector_binding_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'connector bindings cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.binding_id IS DISTINCT FROM OLD.binding_id
       OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
       OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
       OR NEW.agent_device_id IS DISTINCT FROM OLD.agent_device_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.aggregate_revision <> OLD.aggregate_revision + 1
       OR OLD.state = 'revoked'
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid connector binding transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_bindings_transition
BEFORE UPDATE OR DELETE ON agent.connector_bindings
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_binding_transition();

ALTER TABLE agent.installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.installations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.installations
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.agent_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_devices
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.hosts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.hosts
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.host_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.host_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.host_credentials
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_instances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_instances
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_revisions
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_boots ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_boots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_boots
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_leases FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_leases
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_conformance ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_conformance FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_conformance
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.binding_set_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.binding_set_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.binding_set_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.installation_routing_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.installation_routing_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.installation_routing_policies
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_bindings
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.conversation_grant_ids ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.conversation_grant_ids FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.conversation_grant_ids
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.conversation_grant_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.conversation_grant_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.conversation_grant_versions
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.conversation_grant_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.conversation_grant_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.conversation_grant_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.conversation_grant_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.conversation_grant_permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.conversation_grant_permissions
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.conversation_grant_cloud_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.conversation_grant_cloud_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.conversation_grant_cloud_connections
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON SCHEMA agent FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA agent FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.is_public_id(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.reject_immutable_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_definition_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_definition_admission() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_binding_set_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_host_credential_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_boot_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_lease_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_grant_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_installation_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_device_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_host_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_instance_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_routing_policy_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_binding_transition() FROM PUBLIC;
