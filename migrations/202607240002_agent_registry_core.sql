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
    agent_identity_id text,
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
    CONSTRAINT installations_agent_identity_id_valid
        CHECK (agent_identity_id IS NULL OR agent.is_public_id(agent_identity_id, 'dtxi1')),
    CONSTRAINT installations_agent_identity_unique
        UNIQUE (tenant_id, agent_identity_id),
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
    identity_device_id uuid NOT NULL,
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
    CONSTRAINT agent_devices_identity_device_unique
        UNIQUE (tenant_id, identity_device_id),
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
    CONSTRAINT agent_devices_identity_device_id_v7
        CHECK (system.is_uuid_v7(identity_device_id)),
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
