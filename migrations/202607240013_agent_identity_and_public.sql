-- V23: bind-once Agent identity approval and opaque Connector provisioning delivery.

ALTER TABLE agent.connector_control_operations
    DROP CONSTRAINT connector_control_operations_kind_valid,
    ADD CONSTRAINT connector_control_operations_kind_valid
        CHECK (operation_kind IN (
            'enrollment', 'apply_config', 'rotate_credential', 'close_stream',
            'deliver_agent_provisioning', 'revoke_agent_provisioning'
        ));
ALTER TABLE agent.connector_control_commands
    DROP CONSTRAINT connector_control_commands_kind_valid,
    ADD CONSTRAINT connector_control_commands_kind_valid
        CHECK (command_kind IN (
            'apply_config', 'rotate_credential', 'close_stream',
            'deliver_agent_provisioning', 'revoke_agent_provisioning'
        ));

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
    binding_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    agent_device_id uuid,
    scope smallint NOT NULL,
    committed_revision bigint NOT NULL,
    command_sequence bigint NOT NULL,
    command_payload_digest bytea NOT NULL,
    encoded_command_digest bytea NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    request_digest bytea NOT NULL,
    revoked_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT agent_installation_revocations_operation_unique UNIQUE (tenant_id, operation_id),
    CONSTRAINT agent_installation_revocations_idempotency_unique UNIQUE (tenant_id, idempotency_key_hash),
    CONSTRAINT agent_installation_revocations_installation_fk FOREIGN KEY (tenant_id, installation_id)
        REFERENCES agent.installations (tenant_id, installation_id) ON DELETE RESTRICT,
    CONSTRAINT agent_installation_revocations_binding_fk FOREIGN KEY (tenant_id, binding_id)
        REFERENCES agent.connector_bindings (tenant_id, binding_id) ON DELETE RESTRICT,
    CONSTRAINT agent_installation_revocations_values_valid CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(operation_id) AND system.is_uuid_v7(binding_id)
        AND system.is_uuid_v7(connector_id)
        AND (agent_device_id IS NULL OR system.is_uuid_v7(agent_device_id))
        AND scope IN (1, 2)
        AND ((scope = 1 AND agent_device_id IS NULL) OR (scope = 2 AND agent_device_id IS NOT NULL))
        AND committed_revision BETWEEN 1 AND 9007199254740991
        AND command_sequence BETWEEN 1 AND 9007199254740991
        AND octet_length(idempotency_key_hash) = 32
        AND octet_length(request_digest) = 32
        AND octet_length(command_payload_digest) = 32
        AND octet_length(encoded_command_digest) = 32
        AND revoked_at_ms BETWEEN 0 AND 9007199254740991
    )
);

CREATE UNIQUE INDEX agent_installation_revocations_installation_scope_unique
    ON agent.agent_installation_revocations (tenant_id, installation_id)
    WHERE scope = 1;
CREATE UNIQUE INDEX agent_installation_revocations_device_scope_unique
    ON agent.agent_installation_revocations (tenant_id, installation_id, agent_device_id)
    WHERE scope = 2;

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
-- PD2: public feeds are publisher-signed, append-only facts. They are not MLS timelines.
CREATE SCHEMA directory;

CREATE FUNCTION directory.public_feed_runtime_authorized()
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT COALESCE(pg_has_role(current_user, to_regrole('dtx_public_feed_runtime'), 'MEMBER'), false)
$$;
CREATE FUNCTION directory.public_feed_owner_authorized()
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT current_user = pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'directory'
$$;
CREATE FUNCTION directory.current_tenant_id()
RETURNS uuid LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT NULLIF(current_setting('dtx.tenant_id', true), '')::uuid
$$;

CREATE TABLE directory.public_subjects (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  subject_kind smallint NOT NULL CHECK (subject_kind IN (1, 2)),
  publisher_identity_id text NOT NULL,
  publisher_signing_key bytea NOT NULL CHECK (octet_length(publisher_signing_key) = 32),
  descriptor_head_sequence bigint NOT NULL CHECK (descriptor_head_sequence > 0),
  descriptor_head_hash bytea NOT NULL CHECK (octet_length(descriptor_head_hash) = 32),
  descriptor_expires_at_ms bigint NOT NULL,
  descriptor_tombstoned boolean NOT NULL DEFAULT false,
  feed_head_sequence bigint,
  feed_head_hash bytea,
  feed_tombstoned boolean NOT NULL DEFAULT false,
  PRIMARY KEY (tenant_id, subject_id),
  CHECK ((feed_head_sequence IS NULL) = (feed_head_hash IS NULL)),
  CHECK (feed_head_sequence IS NULL OR feed_head_sequence > 0),
  CHECK (feed_head_hash IS NULL OR octet_length(feed_head_hash) = 32),
  CHECK (subject_id LIKE CASE subject_kind WHEN 1 THEN 'dtxc1%' ELSE 'dtxa1%' END)
);

CREATE TABLE directory.descriptor_versions (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  previous_entry_hash bytea,
  entry_hash bytea NOT NULL CHECK (octet_length(entry_hash) = 32),
  exact_cbor bytea NOT NULL CHECK (octet_length(exact_cbor) > 0),
  tombstone boolean NOT NULL,
  PRIMARY KEY (tenant_id, subject_id, sequence),
  UNIQUE (tenant_id, entry_hash),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id),
  CHECK (previous_entry_hash IS NULL OR octet_length(previous_entry_hash) = 32)
);

CREATE TABLE directory.feed_entries (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  previous_entry_hash bytea,
  entry_hash bytea NOT NULL CHECK (octet_length(entry_hash) = 32),
  published_at_ms bigint NOT NULL,
  exact_cbor bytea NOT NULL CHECK (octet_length(exact_cbor) > 0),
  tombstone boolean NOT NULL,
  PRIMARY KEY (tenant_id, subject_id, sequence),
  UNIQUE (tenant_id, entry_hash),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id),
  CHECK (previous_entry_hash IS NULL OR octet_length(previous_entry_hash) = 32)
);

-- Moderation is a separate signed statement projection. It can never rewrite or occupy feed sequence.
CREATE TABLE directory.moderation_labels (
  tenant_id uuid NOT NULL,
  label_digest bytea NOT NULL CHECK (octet_length(label_digest) = 32),
  subject_id text NOT NULL,
  target_entry_hash bytea NOT NULL CHECK (octet_length(target_entry_hash) = 32),
  issuer_identity_id text NOT NULL,
  exact_signed_statement bytea NOT NULL CHECK (octet_length(exact_signed_statement) > 0),
  created_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, label_digest),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id)
);

CREATE FUNCTION directory.reject_immutable_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  RAISE EXCEPTION 'directory signed history is immutable' USING ERRCODE = '55000';
END $$;
CREATE TRIGGER descriptor_versions_append_only BEFORE UPDATE OR DELETE ON directory.descriptor_versions FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();
CREATE TRIGGER feed_entries_append_only BEFORE UPDATE OR DELETE ON directory.feed_entries FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();
CREATE TRIGGER moderation_labels_append_only BEFORE UPDATE OR DELETE ON directory.moderation_labels FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();

ALTER TABLE directory.public_subjects ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.public_subjects FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.descriptor_versions ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.descriptor_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.feed_entries ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.feed_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.moderation_labels ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.moderation_labels FORCE ROW LEVEL SECURITY;

CREATE POLICY directory_tenant_only ON directory.public_subjects USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.descriptor_versions USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.feed_entries USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.moderation_labels USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id()));

DO $grant$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NOT NULL THEN
  GRANT USAGE ON SCHEMA directory TO dtx_public_feed_runtime;
  GRANT EXECUTE ON FUNCTION directory.public_feed_runtime_authorized(), directory.public_feed_owner_authorized(), directory.current_tenant_id() TO dtx_public_feed_runtime;
  GRANT SELECT, INSERT, UPDATE ON directory.public_subjects TO dtx_public_feed_runtime;
  GRANT SELECT, INSERT ON directory.descriptor_versions, directory.feed_entries, directory.moderation_labels TO dtx_public_feed_runtime;
END IF; END $grant$;
REVOKE ALL ON SCHEMA directory FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA directory FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA directory FROM PUBLIC;
-- PD3 Indexer state is per logical Indexer. Signed descriptor/feed facts remain exact bytes.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE directory.index_registrations (
  tenant_id uuid NOT NULL,
  registration_id uuid NOT NULL,
  indexer_id uuid NOT NULL,
  subject_id text NOT NULL,
  subject_kind smallint NOT NULL CHECK (subject_kind IN (1,2)),
  status smallint NOT NULL CHECK (status BETWEEN 1 AND 5),
  descriptor_sequence bigint NOT NULL CHECK (descriptor_sequence > 0),
  descriptor_hash bytea NOT NULL CHECK (octet_length(descriptor_hash)=32),
  descriptor_exact_cbor bytea NOT NULL,
  feed_origin text,
  feed_sequence bigint,
  feed_hash bytea,
  search_document text NOT NULL DEFAULT '',
  search_vector tsvector GENERATED ALWAYS AS (to_tsvector('simple'::regconfig, search_document)) STORED,
  failure_code text,
  created_at_ms bigint NOT NULL,
  updated_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, registration_id),
  UNIQUE (tenant_id, indexer_id, subject_id),
  CHECK (system.is_uuid_v7(registration_id)),
  CHECK (system.is_uuid_v7(indexer_id)),
  CHECK (subject_id LIKE CASE subject_kind WHEN 1 THEN 'dtxc1%' ELSE 'dtxa1%' END),
  CHECK ((feed_sequence IS NULL) = (feed_hash IS NULL)),
  CHECK (feed_sequence IS NULL OR feed_sequence > 0),
  CHECK (feed_hash IS NULL OR octet_length(feed_hash)=32),
  CHECK (failure_code IS NULL OR octet_length(failure_code) BETWEEN 1 AND 64)
);
CREATE INDEX index_registrations_exact_subject ON directory.index_registrations (tenant_id,indexer_id,subject_id) WHERE status=2;
CREATE INDEX index_registrations_fts ON directory.index_registrations USING gin(search_vector) WHERE status=2;
CREATE INDEX index_registrations_trgm ON directory.index_registrations USING gin(search_document gin_trgm_ops) WHERE status=2;

CREATE TABLE directory.indexed_feed_entries (
  tenant_id uuid NOT NULL,
  indexer_id uuid NOT NULL,
  subject_id text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  entry_hash bytea NOT NULL CHECK (octet_length(entry_hash)=32),
  exact_cbor bytea NOT NULL,
  PRIMARY KEY (tenant_id,indexer_id,subject_id,sequence),
  UNIQUE (tenant_id,indexer_id,entry_hash),
  FOREIGN KEY (tenant_id,indexer_id,subject_id) REFERENCES directory.index_registrations (tenant_id,indexer_id,subject_id)
);

CREATE TABLE directory.index_rate_limits (
  tenant_id uuid NOT NULL,
  indexer_id uuid NOT NULL,
  bucket_start_ms bigint NOT NULL,
  request_count integer NOT NULL CHECK (request_count BETWEEN 1 AND 120),
  PRIMARY KEY (tenant_id,indexer_id,bucket_start_ms)
);

CREATE TRIGGER indexed_feed_entries_append_only BEFORE UPDATE OR DELETE ON directory.indexed_feed_entries FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();

ALTER TABLE directory.index_registrations ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.index_registrations FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.indexed_feed_entries ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.indexed_feed_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.index_rate_limits ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.index_rate_limits FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_tenant_only ON directory.index_registrations USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.indexed_feed_entries USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.index_rate_limits USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));

DO $grant$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NOT NULL THEN
  GRANT SELECT,INSERT,UPDATE ON directory.index_registrations,directory.index_rate_limits TO dtx_public_feed_runtime;
  GRANT SELECT,INSERT ON directory.indexed_feed_entries TO dtx_public_feed_runtime;
END IF; END $grant$;
REVOKE ALL ON directory.index_registrations,directory.indexed_feed_entries,directory.index_rate_limits FROM PUBLIC;
-- PD3b retains every registration attempt while index_registrations remains the accepted subject head.
CREATE TABLE directory.index_registration_attempts (
  tenant_id uuid NOT NULL,
  registration_id uuid NOT NULL,
  indexer_id uuid NOT NULL,
  subject_id text NOT NULL,
  descriptor_sequence bigint NOT NULL CHECK (descriptor_sequence > 0),
  descriptor_hash bytea NOT NULL CHECK (octet_length(descriptor_hash)=32),
  descriptor_exact_cbor bytea NOT NULL,
  status smallint NOT NULL CHECK (status BETWEEN 1 AND 5),
  failure_code text,
  created_at_ms bigint NOT NULL,
  updated_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id,indexer_id,subject_id,descriptor_sequence),
  UNIQUE (tenant_id,indexer_id,descriptor_hash),
  FOREIGN KEY (tenant_id,registration_id) REFERENCES directory.index_registrations (tenant_id,registration_id),
  CHECK (system.is_uuid_v7(registration_id)),
  CHECK (system.is_uuid_v7(indexer_id)),
  CHECK (failure_code IS NULL OR octet_length(failure_code) BETWEEN 1 AND 64)
);

INSERT INTO directory.index_registration_attempts(
  tenant_id,registration_id,indexer_id,subject_id,descriptor_sequence,
  descriptor_hash,descriptor_exact_cbor,status,failure_code,created_at_ms,updated_at_ms
)
SELECT tenant_id,registration_id,indexer_id,subject_id,descriptor_sequence,
       descriptor_hash,descriptor_exact_cbor,status,failure_code,created_at_ms,updated_at_ms
FROM directory.index_registrations;

CREATE TRIGGER index_registration_attempts_append_only
BEFORE DELETE ON directory.index_registration_attempts
FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();

ALTER TABLE directory.index_registration_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE directory.index_registration_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_tenant_only ON directory.index_registration_attempts
USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()))
WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));

DO $grant$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NOT NULL THEN
  GRANT SELECT,INSERT,UPDATE ON directory.index_registration_attempts TO dtx_public_feed_runtime;
END IF; END $grant$;
REVOKE ALL ON directory.index_registration_attempts FROM PUBLIC;
-- IM8c/IM3f: Identity-local contact admission stores only capability hashes and opaque sealed bytes.
CREATE TABLE identity.contact_invites (
  invite_id uuid PRIMARY KEY CHECK ((get_byte(uuid_send(invite_id), 6) >> 4) = 7),
  owner_identity_id text NOT NULL REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
  owner_device_id uuid NOT NULL CHECK ((get_byte(uuid_send(owner_device_id), 6) >> 4) = 7),
  capability_hash bytea NOT NULL UNIQUE CHECK (octet_length(capability_hash)=32),
  invite_binding_digest bytea NOT NULL CHECK (octet_length(invite_binding_digest)=32),
  max_uses smallint NOT NULL CHECK (max_uses BETWEEN 1 AND 8),
  use_count smallint NOT NULL DEFAULT 0 CHECK (use_count BETWEEN 0 AND max_uses),
  issued_at_ms bigint NOT NULL,
  expires_at_ms bigint NOT NULL,
  revoked_at_ms bigint,
  created_at_ms bigint NOT NULL,
  CHECK (expires_at_ms > issued_at_ms AND expires_at_ms-issued_at_ms <= 86400000),
  CHECK (revoked_at_ms IS NULL OR revoked_at_ms >= created_at_ms)
);

CREATE TABLE identity.contact_requests (
  request_id uuid PRIMARY KEY CHECK ((get_byte(uuid_send(request_id), 6) >> 4) = 7),
  invite_id uuid NOT NULL REFERENCES identity.contact_invites(invite_id) ON DELETE RESTRICT,
  target_identity_id text NOT NULL REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
  target_device_id uuid NOT NULL CHECK ((get_byte(uuid_send(target_device_id), 6) >> 4) = 7),
  receipt_capability_hash bytea NOT NULL UNIQUE CHECK (octet_length(receipt_capability_hash)=32),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  sealed_request bytea NOT NULL CHECK (octet_length(sealed_request) BETWEEN 1 AND 131072),
  state smallint NOT NULL DEFAULT 1 CHECK (state BETWEEN 1 AND 6),
  failure_code text,
  created_at_ms bigint NOT NULL,
  expires_at_ms bigint NOT NULL,
  reviewed_at_ms bigint,
  CHECK (expires_at_ms > created_at_ms AND expires_at_ms-created_at_ms <= 86400000),
  CHECK (failure_code IS NULL OR octet_length(failure_code) BETWEEN 1 AND 32),
  CHECK ((state=1 AND reviewed_at_ms IS NULL) OR (state<>1))
);
CREATE INDEX contact_requests_pending_target_idx ON identity.contact_requests(target_identity_id,target_device_id,created_at_ms,request_id) WHERE state=1;

CREATE TABLE identity.contact_delivery_outbox (
  request_id uuid PRIMARY KEY REFERENCES identity.contact_requests(request_id) ON DELETE RESTRICT,
  delivery_digest bytea NOT NULL CHECK (octet_length(delivery_digest)=32),
  sealed_delivery bytea NOT NULL CHECK (octet_length(sealed_delivery) BETWEEN 1 AND 262144),
  created_at_ms bigint NOT NULL
);

CREATE TABLE identity.contact_owner_commands (
  owner_identity_id text NOT NULL REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
  owner_device_id uuid NOT NULL CHECK ((get_byte(uuid_send(owner_device_id), 6) >> 4) = 7),
  idempotency_key_hash bytea NOT NULL CHECK (octet_length(idempotency_key_hash)=32),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  resource_id uuid NOT NULL CHECK ((get_byte(uuid_send(resource_id), 6) >> 4) = 7),
  action smallint NOT NULL CHECK (action BETWEEN 1 AND 3),
  receipt_bytes bytea NOT NULL CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
  created_at_ms bigint NOT NULL,
  PRIMARY KEY(owner_identity_id,owner_device_id,idempotency_key_hash)
);

CREATE TABLE identity.contact_rate_limits (
  owner_identity_id text NOT NULL,
  owner_device_id uuid NOT NULL,
  action smallint NOT NULL CHECK (action BETWEEN 1 AND 3),
  bucket_start_ms bigint NOT NULL,
  request_count integer NOT NULL CHECK (request_count BETWEEN 1 AND 120),
  PRIMARY KEY(owner_identity_id,owner_device_id,action,bucket_start_ms)
);

CREATE TRIGGER contact_delivery_outbox_immutable BEFORE UPDATE OR DELETE ON identity.contact_delivery_outbox FOR EACH ROW EXECUTE FUNCTION identity.reject_immutable_mutation();
CREATE TRIGGER contact_owner_commands_immutable BEFORE UPDATE OR DELETE ON identity.contact_owner_commands FOR EACH ROW EXECUTE FUNCTION identity.reject_immutable_mutation();

ALTER TABLE identity.contact_invites ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.contact_invites FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.contact_requests ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.contact_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.contact_delivery_outbox ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.contact_delivery_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.contact_owner_commands ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.contact_owner_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.contact_rate_limits ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.contact_rate_limits FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.contact_invites USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
CREATE POLICY identity_runtime_only ON identity.contact_requests USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
CREATE POLICY identity_runtime_only ON identity.contact_delivery_outbox USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
CREATE POLICY identity_runtime_only ON identity.contact_owner_commands USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
CREATE POLICY identity_runtime_only ON identity.contact_rate_limits USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

DO $grant$ BEGIN IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
  GRANT SELECT,INSERT,UPDATE ON identity.contact_invites,identity.contact_requests,identity.contact_rate_limits TO dtx_identity_runtime;
  GRANT SELECT,INSERT ON identity.contact_delivery_outbox,identity.contact_owner_commands TO dtx_identity_runtime;
END IF; END $grant$;
REVOKE ALL ON identity.contact_invites,identity.contact_requests,identity.contact_delivery_outbox,identity.contact_owner_commands,identity.contact_rate_limits FROM PUBLIC;
