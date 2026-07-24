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
