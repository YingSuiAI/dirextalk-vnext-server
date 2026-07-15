-- V23: bind-once Agent identity approval and opaque Connector provisioning delivery.

CREATE FUNCTION identity.identity_agent_reader_authorized()
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT COALESCE(pg_has_role(current_user, to_regrole('dtx_agent_runtime'), 'MEMBER'), false)
$$;

ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (
        CASE
            WHEN COALESCE(pg_has_role(current_user, to_regrole('dtx_agent_runtime'), 'MEMBER'), false)
                THEN has_function_privilege(current_user, 'identity.identity_agent_reader_authorized()'::regprocedure, 'EXECUTE')
            WHEN COALESCE(pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'), false)
                THEN has_function_privilege(current_user, 'identity.identity_group_reader_authorized()'::regprocedure, 'EXECUTE')
            ELSE COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
              OR COALESCE(pg_has_role(current_user, to_regrole('dtx_mailbox_runtime'), 'MEMBER'), false)
              OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity')
        END
    )
    WITH CHECK (
        COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
        OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity')
    );
ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (
        CASE
            WHEN COALESCE(pg_has_role(current_user, to_regrole('dtx_agent_runtime'), 'MEMBER'), false)
                THEN has_function_privilege(current_user, 'identity.identity_agent_reader_authorized()'::regprocedure, 'EXECUTE')
            WHEN COALESCE(pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'), false)
                THEN has_function_privilege(current_user, 'identity.identity_group_reader_authorized()'::regprocedure, 'EXECUTE')
            ELSE COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
              OR COALESCE(pg_has_role(current_user, to_regrole('dtx_mailbox_runtime'), 'MEMBER'), false)
              OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity')
        END
    )
    WITH CHECK (
        COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
        OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity')
    );
ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (
        CASE
            WHEN COALESCE(pg_has_role(current_user, to_regrole('dtx_agent_runtime'), 'MEMBER'), false)
                THEN has_function_privilege(current_user, 'identity.identity_agent_reader_authorized()'::regprocedure, 'EXECUTE')
            WHEN COALESCE(pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'), false)
                THEN has_function_privilege(current_user, 'identity.identity_group_reader_authorized()'::regprocedure, 'EXECUTE')
            ELSE COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
              OR COALESCE(pg_has_role(current_user, to_regrole('dtx_mailbox_runtime'), 'MEMBER'), false)
              OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity')
        END
    )
    WITH CHECK (
        COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
        OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity')
    );

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA identity TO dtx_agent_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_agent_reader_authorized() TO dtx_agent_runtime;
        GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries TO dtx_agent_runtime;
    END IF;
END
$grant$;
REVOKE ALL ON FUNCTION identity.identity_agent_reader_authorized() FROM PUBLIC;

ALTER TABLE agent.installations ADD COLUMN agent_identity_id text;
ALTER TABLE agent.installations
    ADD CONSTRAINT installations_agent_identity_id_valid
        CHECK (agent_identity_id IS NULL OR agent.is_public_id(agent_identity_id, 'dtxi1')),
    ADD CONSTRAINT installations_agent_identity_unique
        UNIQUE (tenant_id, agent_identity_id);

ALTER TABLE agent.agent_devices ADD COLUMN identity_device_id uuid;
UPDATE agent.agent_devices SET identity_device_id = agent_device_id;
ALTER TABLE agent.agent_devices
    ALTER COLUMN identity_device_id SET NOT NULL,
    ADD CONSTRAINT agent_devices_identity_device_id_v7
        CHECK (system.is_uuid_v7(identity_device_id)),
    ADD CONSTRAINT agent_devices_identity_device_unique
        UNIQUE (tenant_id, identity_device_id);

CREATE OR REPLACE FUNCTION agent.enforce_installation_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent installations cannot be deleted' USING ERRCODE = '55000';
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
       OR NEW.updated_at_ms < OLD.updated_at_ms
       OR (OLD.agent_identity_id IS NOT NULL
           AND NEW.agent_identity_id IS DISTINCT FROM OLD.agent_identity_id)
       OR (NEW.observed_state = 'ready' AND NEW.agent_identity_id IS NULL) THEN
        RAISE EXCEPTION 'invalid Agent installation transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION agent.enforce_agent_device_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent Devices cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.agent_device_id IS DISTINCT FROM OLD.agent_device_id
       OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
       OR NEW.identity_device_id IS DISTINCT FROM OLD.identity_device_id
       OR NEW.credential_fingerprint IS DISTINCT FROM OLD.credential_fingerprint
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.aggregate_revision <> OLD.aggregate_revision + 1
       OR OLD.state = 'revoked'
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Agent Device transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TABLE agent.agent_identity_approvals (
    tenant_id uuid NOT NULL,
    approval_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    agent_device_id uuid NOT NULL,
    agent_identity_id text NOT NULL,
    identity_device_id uuid NOT NULL,
    identity_head_sequence bigint NOT NULL,
    identity_head_hash bytea NOT NULL,
    credential_fingerprint bytea NOT NULL,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    owner_session_id uuid NOT NULL,
    owner_operation_id uuid NOT NULL,
    owner_operation_expires_at_ms bigint NOT NULL,
    expected_installation_revision bigint NOT NULL,
    committed_installation_revision bigint NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    request_digest bytea NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    approved_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, approval_id),
    CONSTRAINT agent_identity_approvals_installation_unique UNIQUE (tenant_id, installation_id),
    CONSTRAINT agent_identity_approvals_identity_unique UNIQUE (tenant_id, agent_identity_id),
    CONSTRAINT agent_identity_approvals_device_unique UNIQUE (tenant_id, identity_device_id),
    CONSTRAINT agent_identity_approvals_operation_unique UNIQUE (tenant_id, owner_operation_id),
    CONSTRAINT agent_identity_approvals_idempotency_unique UNIQUE (tenant_id, idempotency_key_hash),
    CONSTRAINT agent_identity_approvals_installation_fk FOREIGN KEY (tenant_id, installation_id)
        REFERENCES agent.installations (tenant_id, installation_id) ON DELETE RESTRICT,
    CONSTRAINT agent_identity_approvals_binding_fk FOREIGN KEY (tenant_id, binding_id)
        REFERENCES agent.connector_bindings (tenant_id, binding_id) ON DELETE RESTRICT,
    CONSTRAINT agent_identity_approvals_agent_device_fk
        FOREIGN KEY (tenant_id, installation_id, agent_device_id)
        REFERENCES agent.agent_devices (tenant_id, installation_id, agent_device_id) ON DELETE RESTRICT,
    CONSTRAINT agent_identity_approvals_ids_valid CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(approval_id)
        AND system.is_uuid_v7(installation_id) AND system.is_uuid_v7(binding_id)
        AND system.is_uuid_v7(agent_device_id) AND system.is_uuid_v7(identity_device_id)
        AND system.is_uuid_v7(owner_device_id) AND system.is_uuid_v7(owner_session_id)
        AND system.is_uuid_v7(owner_operation_id)
        AND agent.is_public_id(agent_identity_id, 'dtxi1')
        AND agent.is_public_id(owner_identity_id, 'dtxi1')
    ),
    CONSTRAINT agent_identity_approvals_values_valid CHECK (
        identity_head_sequence BETWEEN 1 AND 9007199254740991
        AND octet_length(identity_head_hash) = 32
        AND octet_length(credential_fingerprint) = 32
        AND expected_installation_revision BETWEEN 1 AND 9007199254740990
        AND committed_installation_revision = expected_installation_revision + 1
        AND octet_length(idempotency_key_hash) = 32
        AND octet_length(request_digest) = 32
        AND octet_length(receipt_bytes) BETWEEN 1 AND 65536
        AND octet_length(receipt_digest) = 32
        AND approved_at_ms BETWEEN 0 AND owner_operation_expires_at_ms - 1
    )
);

CREATE TABLE agent.agent_provisioning_recipients (
    tenant_id uuid NOT NULL,
    recipient_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    agent_device_id uuid NOT NULL,
    provisioning_revision bigint NOT NULL,
    recipient_key_id uuid NOT NULL,
    recipient_public_key bytea NOT NULL,
    credential_id uuid NOT NULL,
    credential_generation bigint NOT NULL,
    connector_credential_fingerprint bytea NOT NULL,
    descriptor_digest bytea NOT NULL,
    announce_signature bytea NOT NULL,
    expires_at_ms bigint NOT NULL,
    announced_at_ms bigint NOT NULL,
    state text NOT NULL,
    claimed_delivery_id uuid,
    PRIMARY KEY (tenant_id, recipient_id),
    CONSTRAINT agent_provisioning_recipients_open_binding_unique
        UNIQUE NULLS NOT DISTINCT (tenant_id, binding_id, claimed_delivery_id),
    CONSTRAINT agent_provisioning_recipients_binding_fk FOREIGN KEY (tenant_id, binding_id)
        REFERENCES agent.connector_bindings (tenant_id, binding_id) ON DELETE RESTRICT,
    CONSTRAINT agent_provisioning_recipients_connector_fk FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id) ON DELETE RESTRICT,
    CONSTRAINT agent_provisioning_recipients_ids_valid CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(recipient_id)
        AND system.is_uuid_v7(connector_id) AND system.is_uuid_v7(binding_id)
        AND system.is_uuid_v7(installation_id) AND system.is_uuid_v7(agent_device_id)
        AND system.is_uuid_v7(recipient_key_id) AND system.is_uuid_v7(credential_id)
        AND (claimed_delivery_id IS NULL OR system.is_uuid_v7(claimed_delivery_id))
    ),
    CONSTRAINT agent_provisioning_recipients_values_valid CHECK (
        provisioning_revision BETWEEN 1 AND 9007199254740991
        AND credential_generation BETWEEN 1 AND 9007199254740991
        AND octet_length(recipient_public_key) = 32
        AND octet_length(connector_credential_fingerprint) = 32
        AND octet_length(descriptor_digest) = 32
        AND octet_length(announce_signature) = 64
        AND announced_at_ms BETWEEN 0 AND expires_at_ms - 1
        AND expires_at_ms <= announced_at_ms + 600000
        AND ((state = 'open' AND claimed_delivery_id IS NULL)
          OR (state IN ('claimed', 'revoked', 'expired')))
    )
);

CREATE TABLE agent.agent_provisioning_deliveries (
    tenant_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    approval_id uuid NOT NULL,
    recipient_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    agent_device_id uuid NOT NULL,
    recipient_key_id uuid NOT NULL,
    provisioning_revision bigint NOT NULL,
    command_sequence bigint NOT NULL,
    command_payload_digest bytea NOT NULL,
    encoded_command_digest bytea NOT NULL,
    capsule_header bytea NOT NULL,
    capsule_digest bytea NOT NULL,
    sealed_capsule bytea NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    request_digest bytea NOT NULL,
    state text NOT NULL,
    result_digest bytea,
    rejection_code text,
    created_at_ms bigint NOT NULL,
    dispatched_at_ms bigint,
    resolved_at_ms bigint,
    PRIMARY KEY (tenant_id, delivery_id),
    CONSTRAINT agent_provisioning_deliveries_approval_unique UNIQUE (tenant_id, approval_id),
    CONSTRAINT agent_provisioning_deliveries_recipient_unique UNIQUE (tenant_id, recipient_id),
    CONSTRAINT agent_provisioning_deliveries_idempotency_unique UNIQUE (tenant_id, idempotency_key_hash),
    CONSTRAINT agent_provisioning_deliveries_approval_fk FOREIGN KEY (tenant_id, approval_id)
        REFERENCES agent.agent_identity_approvals (tenant_id, approval_id) ON DELETE RESTRICT,
    CONSTRAINT agent_provisioning_deliveries_recipient_fk FOREIGN KEY (tenant_id, recipient_id)
        REFERENCES agent.agent_provisioning_recipients (tenant_id, recipient_id) ON DELETE RESTRICT,
    CONSTRAINT agent_provisioning_deliveries_binding_fk FOREIGN KEY (tenant_id, binding_id)
        REFERENCES agent.connector_bindings (tenant_id, binding_id) ON DELETE RESTRICT,
    CONSTRAINT agent_provisioning_deliveries_ids_valid CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(delivery_id)
        AND system.is_uuid_v7(installation_id) AND system.is_uuid_v7(approval_id)
        AND system.is_uuid_v7(recipient_id) AND system.is_uuid_v7(connector_id)
        AND system.is_uuid_v7(binding_id) AND system.is_uuid_v7(agent_device_id)
        AND system.is_uuid_v7(recipient_key_id)
    ),
    CONSTRAINT agent_provisioning_deliveries_values_valid CHECK (
        provisioning_revision BETWEEN 1 AND 9007199254740991
        AND command_sequence BETWEEN 1 AND 9007199254740991
        AND octet_length(command_payload_digest) = 32
        AND octet_length(encoded_command_digest) = 32
        AND octet_length(capsule_header) BETWEEN 1 AND 4096
        AND octet_length(capsule_digest) = 32
        AND octet_length(sealed_capsule) BETWEEN 1 AND 196608
        AND octet_length(idempotency_key_hash) = 32
        AND octet_length(request_digest) = 32
        AND state IN ('pending', 'dispatched', 'installed', 'rejected', 'revoked')
        AND ((state IN ('pending', 'dispatched') AND result_digest IS NULL AND rejection_code IS NULL AND resolved_at_ms IS NULL)
          OR (state = 'installed' AND octet_length(result_digest) = 32 AND rejection_code IS NULL AND resolved_at_ms IS NOT NULL)
          OR (state = 'rejected' AND octet_length(result_digest) = 32 AND rejection_code ~ '^[A-Z][A-Z0-9_]{2,63}$' AND resolved_at_ms IS NOT NULL)
          OR (state = 'revoked' AND result_digest IS NULL AND rejection_code IS NULL AND resolved_at_ms IS NOT NULL))
    )
);

ALTER TABLE agent.agent_provisioning_recipients
    ADD CONSTRAINT agent_provisioning_recipients_delivery_fk
    FOREIGN KEY (tenant_id, claimed_delivery_id)
    REFERENCES agent.agent_provisioning_deliveries (tenant_id, delivery_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE agent.agent_provisioning_outbox (
    tenant_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    command_sequence bigint NOT NULL,
    command_digest bytea NOT NULL,
    dispatched_at_ms bigint,
    attempt_count bigint NOT NULL DEFAULT 0,
    next_attempt_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, delivery_id),
    CONSTRAINT agent_provisioning_outbox_sequence_unique UNIQUE (tenant_id, connector_id, command_sequence),
    CONSTRAINT agent_provisioning_outbox_delivery_fk FOREIGN KEY (tenant_id, delivery_id)
        REFERENCES agent.agent_provisioning_deliveries (tenant_id, delivery_id) ON DELETE RESTRICT,
    CONSTRAINT agent_provisioning_outbox_values_valid CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(delivery_id)
        AND system.is_uuid_v7(connector_id)
        AND command_sequence BETWEEN 1 AND 9007199254740991
        AND octet_length(command_digest) = 32
        AND attempt_count BETWEEN 0 AND 9007199254740991
        AND next_attempt_at_ms BETWEEN 0 AND 9007199254740991
    )
);

CREATE TABLE agent.agent_installation_revocations (
    tenant_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    request_digest bytea NOT NULL,
    stop_command_digest bytea NOT NULL,
    revoked_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, installation_id),
    CONSTRAINT agent_installation_revocations_operation_unique UNIQUE (tenant_id, operation_id),
    CONSTRAINT agent_installation_revocations_installation_fk FOREIGN KEY (tenant_id, installation_id)
        REFERENCES agent.installations (tenant_id, installation_id) ON DELETE RESTRICT,
    CONSTRAINT agent_installation_revocations_values_valid CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(operation_id)
        AND octet_length(idempotency_key_hash) = 32
        AND octet_length(request_digest) = 32
        AND octet_length(stop_command_digest) = 32
        AND revoked_at_ms BETWEEN 0 AND 9007199254740991
    )
);

CREATE TRIGGER agent_identity_approvals_append_only BEFORE UPDATE OR DELETE
ON agent.agent_identity_approvals FOR EACH ROW EXECUTE FUNCTION agent.reject_immutable_mutation();
CREATE TRIGGER agent_installation_revocations_append_only BEFORE UPDATE OR DELETE
ON agent.agent_installation_revocations FOR EACH ROW EXECUTE FUNCTION agent.reject_immutable_mutation();

ALTER TABLE agent.agent_identity_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_identity_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_identity_approvals USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_provisioning_recipients ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_provisioning_recipients FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_provisioning_recipients USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_provisioning_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_provisioning_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_provisioning_deliveries USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_provisioning_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_provisioning_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_provisioning_outbox USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_installation_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_installation_revocations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_installation_revocations USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.agent_identity_approvals, agent.agent_provisioning_recipients,
    agent.agent_provisioning_deliveries, agent.agent_provisioning_outbox,
    agent.agent_installation_revocations FROM PUBLIC;

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON agent.agent_identity_approvals,
            agent.agent_installation_revocations TO dtx_agent_runtime;
        GRANT SELECT, INSERT, UPDATE ON agent.agent_provisioning_recipients,
            agent.agent_provisioning_deliveries, agent.agent_provisioning_outbox
            TO dtx_agent_runtime;
    END IF;
END
$grant$;
