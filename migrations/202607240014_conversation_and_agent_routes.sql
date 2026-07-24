CREATE TABLE messaging.attachment_objects (
    object_id uuid PRIMARY KEY,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    upload_capability_hash bytea NOT NULL,
    read_capability_hash bytea NOT NULL,
    expected_manifest_digest bytea NOT NULL,
    expected_chunk_count integer NOT NULL,
    expected_ciphertext_bytes bigint NOT NULL,
    uploaded_chunk_count integer NOT NULL DEFAULT 0,
    uploaded_ciphertext_bytes bigint NOT NULL DEFAULT 0,
    manifest_bytes bytea,
    state text NOT NULL DEFAULT 'uploading',
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CHECK (messaging.is_uuid_v7(object_id)),
    CHECK (messaging.is_uuid_v7(owner_device_id)),
    CHECK (octet_length(owner_identity_id) BETWEEN 8 AND 128),
    CHECK (octet_length(upload_capability_hash)=32 AND octet_length(read_capability_hash)=32),
    CHECK (octet_length(expected_manifest_digest)=32),
    CHECK (expected_chunk_count BETWEEN 1 AND 4096),
    CHECK (expected_ciphertext_bytes BETWEEN 1 AND 1073741824),
    CHECK (uploaded_chunk_count BETWEEN 0 AND expected_chunk_count),
    CHECK (uploaded_ciphertext_bytes BETWEEN 0 AND expected_ciphertext_bytes),
    CHECK (manifest_bytes IS NULL OR octet_length(manifest_bytes) BETWEEN 1 AND 1048576),
    CHECK (state IN ('uploading','ready','cancelled','expired')),
    CHECK (expires_at_ms > created_at_ms),
    FOREIGN KEY (owner_identity_id) REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT
);

CREATE TABLE messaging.attachment_chunks (
    object_id uuid NOT NULL REFERENCES messaging.attachment_objects(object_id) ON DELETE CASCADE,
    chunk_index integer NOT NULL,
    ciphertext_digest bytea NOT NULL,
    ciphertext_bytes bytea NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    request_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (object_id, chunk_index),
    UNIQUE (object_id, idempotency_key_hash),
    CHECK (chunk_index BETWEEN 0 AND 4095),
    CHECK (octet_length(ciphertext_digest)=32),
    CHECK (octet_length(ciphertext_bytes) BETWEEN 17 AND 1048576),
    CHECK (octet_length(idempotency_key_hash)=32 AND octet_length(request_digest)=32)
);

CREATE INDEX messaging_attachment_expiry_idx
    ON messaging.attachment_objects(expires_at_ms, object_id)
    WHERE state IN ('uploading','ready','cancelled');

ALTER TABLE messaging.attachment_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.attachment_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY messaging_runtime_only ON messaging.attachment_objects
    USING (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized())
    WITH CHECK (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized());
ALTER TABLE messaging.attachment_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.attachment_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY messaging_runtime_only ON messaging.attachment_chunks
    USING (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized())
    WITH CHECK (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized());

CREATE FUNCTION messaging.expire_attachment_objects(batch_limit integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, messaging
AS $$
DECLARE affected integer;
DECLARE now_ms bigint;
BEGIN
    IF batch_limit < 1 OR batch_limit > 1000 THEN
        RAISE EXCEPTION 'invalid attachment retention batch';
    END IF;
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    WITH victims AS (
        SELECT object_id FROM messaging.attachment_objects
         WHERE state='cancelled' OR expires_at_ms <= now_ms
         ORDER BY expires_at_ms, object_id LIMIT batch_limit FOR UPDATE SKIP LOCKED
    ), removed AS (
        DELETE FROM messaging.attachment_objects object
         USING victims WHERE object.object_id=victims.object_id RETURNING 1
    ) SELECT count(*)::integer INTO affected FROM removed;
    RETURN affected;
END
$$;

DO $grant$
BEGIN
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON messaging.attachment_objects TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON messaging.attachment_chunks TO dtx_mailbox_runtime;
        GRANT EXECUTE ON FUNCTION messaging.expire_attachment_objects(integer) TO dtx_mailbox_runtime;
    END IF;
END
$grant$;

REVOKE ALL ON messaging.attachment_objects, messaging.attachment_chunks FROM PUBLIC;
REVOKE ALL ON FUNCTION messaging.expire_attachment_objects(integer) FROM PUBLIC;
-- V29 adds the candidate's authoritative identity-log origin to the durable
-- membership workflow. Existing rows deliberately remain NULL: discovery
-- fails closed for those rows instead of inventing an origin after the fact.
ALTER TABLE groups.membership_workflows
    ADD COLUMN candidate_identity_origin text;

ALTER TABLE groups.membership_workflows
    ADD CONSTRAINT groups_membership_workflows_candidate_origin_shape
    CHECK (candidate_identity_origin IS NULL OR (
        octet_length(candidate_identity_origin) BETWEEN 10 AND 512
        AND candidate_identity_origin ~ '^https?://[^/[:space:]]+$'
    ));

CREATE UNIQUE INDEX groups_membership_commands_request_workflow_unique
    ON groups.membership_commands (tenant_id, scope_kind, scope_id, workflow_id)
    WHERE kind = 'request_join' AND workflow_id IS NOT NULL;

CREATE INDEX groups_join_records_pending_page_idx
    ON groups.join_records (
        tenant_id,
        scope_kind,
        scope_id,
        requested_at_ms,
        request_id
    )
    WHERE state = 'pending';
-- V30 binds every new membership workflow and MLS admission to one exact
-- candidate KeyPackage. Historical V17/V18 rows remain NULL and are rejected
-- by the V2/V3 production path instead of being guessed after the fact.
ALTER TABLE groups.membership_workflows
    ADD COLUMN candidate_key_package_digest bytea;

ALTER TABLE groups.membership_workflows
    ADD CONSTRAINT groups_membership_workflows_candidate_key_package_digest_size
    CHECK (candidate_key_package_digest IS NULL
           OR octet_length(candidate_key_package_digest) = 32);

-- V22 receipts remain readable. V30/V3 intents carry the durable candidate
-- join and Owner/Admin approval request digests that are covered by the signed
-- receipt. They are populated only for the V3 approved-identity path.
ALTER TABLE groups.mls_commit_intents
    ADD COLUMN protocol_version smallint NOT NULL DEFAULT 2,
    ADD COLUMN join_request_digest bytea,
    ADD COLUMN approval_request_digest bytea;

ALTER TABLE groups.mls_commit_intents
    ADD CONSTRAINT groups_mls_commit_intents_protocol_version_valid
    CHECK (protocol_version IN (2, 3)),
    ADD CONSTRAINT groups_mls_commit_intents_v3_admission_digests_valid
    CHECK ((protocol_version = 2
            AND join_request_digest IS NULL
            AND approval_request_digest IS NULL)
           OR (protocol_version = 3
               AND authorization_kind = 'approved_identity_join'
               AND join_request_digest IS NOT NULL
               AND approval_request_digest IS NOT NULL
               AND octet_length(join_request_digest) = 32
               AND octet_length(approval_request_digest) = 32));
-- V27: narrow Owner authorization for private-conversation Agent grants.
-- The Agent runtime must never receive direct SELECT access to group
-- membership tables merely to check the conversation owner at this boundary.

CREATE FUNCTION groups.private_conversation_owner_authorized(
    requested_tenant_id uuid,
    requested_conversation_id uuid,
    requested_owner_identity_id text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, groups, system
AS $$
BEGIN
    -- The caller's tenant context is still authoritative even though this
    -- function runs with the schema owner's narrowly scoped read authority.
    IF requested_tenant_id IS DISTINCT FROM system.current_tenant_id() THEN
        RETURN false;
    END IF;

    PERFORM 1
      FROM groups.policy_heads
     WHERE tenant_id = requested_tenant_id
       AND scope_kind = 'private_conversation'
       AND scope_id = requested_conversation_id::text
       AND owner_identity_id = requested_owner_identity_id
     FOR SHARE;
    RETURN FOUND;
END
$$;

REVOKE ALL ON FUNCTION groups.private_conversation_owner_authorized(uuid, uuid, text) FROM PUBLIC;

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA groups TO dtx_agent_runtime;
        GRANT EXECUTE ON FUNCTION groups.private_conversation_owner_authorized(uuid, uuid, text)
            TO dtx_agent_runtime;
    END IF;
END
$grant$;

-- Durable receipts keep exact idempotent replay independent of the mutable
-- grant head.  This relation is deliberately agent-local; it does not widen
-- access to any groups relation.
CREATE TABLE agent.conversation_grant_owner_operations (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    action text NOT NULL,
    request_digest bytea NOT NULL,
    grant_id uuid NOT NULL,
    grant_version bigint NOT NULL,
    revoked boolean NOT NULL,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    owner_session_id uuid NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    committed_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT conversation_grant_owner_operations_grant_version_fk
        FOREIGN KEY (tenant_id, conversation_id, installation_id, grant_version, grant_id)
        REFERENCES agent.conversation_grant_versions
            (tenant_id, conversation_id, installation_id, grant_version, grant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_grant_owner_operations_ids_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(operation_id)
        AND system.is_uuid_v7(conversation_id)
        AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(grant_id)
        AND system.is_uuid_v7(owner_device_id)
        AND system.is_uuid_v7(owner_session_id)
        AND agent.is_public_id(owner_identity_id, 'dtxi1')
    ),
    CONSTRAINT conversation_grant_owner_operations_values_valid CHECK (
        action IN ('grant', 'revoke')
        AND octet_length(request_digest) = 32
        AND grant_version BETWEEN 1 AND 9007199254740991
        AND octet_length(receipt_bytes) BETWEEN 1 AND 65536
        AND octet_length(receipt_digest) = 32
        AND committed_at_ms BETWEEN 0 AND 253402300799999
    )
);

CREATE TRIGGER conversation_grant_owner_operations_append_only
BEFORE UPDATE OR DELETE ON agent.conversation_grant_owner_operations
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

ALTER TABLE agent.conversation_grant_owner_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.conversation_grant_owner_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.conversation_grant_owner_operations
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON agent.conversation_grant_owner_operations
            TO dtx_agent_runtime;
    END IF;
END
$grant$;
-- V28: the V27 Owner API writes only the fixed Conversation Grant aggregate.
-- Keep these table rights separate from V27 so databases that already applied
-- its receipt schema receive the new capability without a checksum rewrite.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT INSERT ON agent.conversation_grant_ids,
            agent.conversation_grant_versions,
            agent.conversation_grant_heads,
            agent.conversation_grant_permissions
            TO dtx_agent_runtime;
        GRANT UPDATE ON agent.conversation_grant_heads TO dtx_agent_runtime;
    END IF;
END
$grant$;
-- V29: durable Owner-side ingress receipts for isolated AgentRoute Runs.
--
-- `route_id` is the MLS/data-plane conversation recorded on agent_runs;
-- `source_conversation_id` is retained here only for grant authorization and
-- audit.  No prompt, MLS ciphertext, mailbox descriptor, capability, or
-- Connector credential is stored in this control-plane relation.

CREATE TABLE agent.agent_route_run_operations (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    run_id uuid NOT NULL,
    source_conversation_id uuid NOT NULL,
    route_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    request_event_id uuid NOT NULL,
    grant_version bigint NOT NULL,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    owner_session_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    committed_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT agent_route_run_operations_route_event_unique
        UNIQUE (tenant_id, route_id, request_event_id),
    CONSTRAINT agent_route_run_operations_run_fk
        FOREIGN KEY (tenant_id, run_id)
        REFERENCES agent.agent_runs (tenant_id, run_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_run_operations_grant_version_fk
        FOREIGN KEY (tenant_id, source_conversation_id, installation_id, grant_version)
        REFERENCES agent.conversation_grant_versions
            (tenant_id, conversation_id, installation_id, grant_version)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_run_operations_ids_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(operation_id)
        AND system.is_uuid_v7(run_id)
        AND system.is_uuid_v7(source_conversation_id)
        AND system.is_uuid_v7(route_id)
        AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(request_event_id)
        AND system.is_uuid_v7(owner_device_id)
        AND system.is_uuid_v7(owner_session_id)
        AND agent.is_public_id(owner_identity_id, 'dtxi1')
    ),
    CONSTRAINT agent_route_run_operations_values_valid CHECK (
        source_conversation_id <> route_id
        AND grant_version BETWEEN 1 AND 9007199254740991
        AND octet_length(request_digest) = 32
        AND octet_length(receipt_bytes) BETWEEN 1 AND 65536
        AND octet_length(receipt_digest) = 32
        AND committed_at_ms BETWEEN 0 AND 253402300799999
    )
);

CREATE INDEX agent_route_run_operations_route_idx
    ON agent.agent_route_run_operations (tenant_id, route_id, committed_at_ms, operation_id);

CREATE TRIGGER agent_route_run_operations_append_only
BEFORE UPDATE OR DELETE ON agent.agent_route_run_operations
FOR EACH ROW EXECUTE FUNCTION agent.reject_immutable_mutation();

ALTER TABLE agent.agent_route_run_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_route_run_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_route_run_operations
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        -- Row locks used by exact replay need UPDATE privilege; the append-only
        -- trigger still rejects every actual UPDATE or DELETE.
        GRANT SELECT, INSERT, UPDATE ON agent.agent_route_run_operations TO dtx_agent_runtime;
    END IF;
END
$grant$;
-- V30: durable RouteBootstrapV1 control-plane state.
--
-- Recipient and bootstrap capsules remain opaque bounded bytes.  This schema
-- deliberately does not contain MLS state, mailbox descriptors, prompts, or
-- any decrypted capability material.

ALTER TABLE agent.connector_control_operations
    DROP CONSTRAINT connector_control_operations_kind_valid,
    ADD CONSTRAINT connector_control_operations_kind_valid
        CHECK (operation_kind IN (
            'enrollment', 'apply_config', 'rotate_credential', 'close_stream',
            'deliver_agent_provisioning', 'revoke_agent_provisioning',
            'prepare_agent_route_recipient', 'deliver_agent_route_bootstrap'
        ));
ALTER TABLE agent.connector_control_commands
    DROP CONSTRAINT connector_control_commands_kind_valid,
    ADD CONSTRAINT connector_control_commands_kind_valid
        CHECK (command_kind IN (
            'apply_config', 'rotate_credential', 'close_stream',
            'deliver_agent_provisioning', 'revoke_agent_provisioning',
            'prepare_agent_route_recipient', 'deliver_agent_route_bootstrap'
        ));

CREATE TABLE agent.agent_route_bootstraps (
    tenant_id uuid NOT NULL,
    bootstrap_id uuid NOT NULL,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    agent_control_device_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    -- The route fence is generated by the local MLS import and is absent
    -- until the authenticated Installed receipt is recorded.
    route_fence bytea,
    owner_signed_intent bytea NOT NULL,
    request_digest bytea NOT NULL,
    begin_receipt_bytes bytea NOT NULL,
    begin_receipt_digest bytea NOT NULL,
    recipient_id uuid,
    recipient_capsule_digest bytea,
    opaque_recipient_capsule bytea,
    route_id uuid,
    delivery_id uuid,
    bootstrap_capsule_digest bytea,
    opaque_sealed_bootstrap bytea,
    delivery_request_digest bytea,
    delivery_receipt_bytes bytea,
    delivery_receipt_digest bytea,
    state text NOT NULL,
    rejection_code text,
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, bootstrap_id),
    CONSTRAINT agent_route_bootstraps_delivery_unique UNIQUE (tenant_id, delivery_id),
    CONSTRAINT agent_route_bootstraps_installation_fk
        FOREIGN KEY (tenant_id, installation_id)
        REFERENCES agent.installations (tenant_id, installation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_bootstraps_binding_fk
        FOREIGN KEY (tenant_id, binding_id)
        REFERENCES agent.connector_bindings (tenant_id, binding_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_bootstraps_agent_device_fk
        FOREIGN KEY (tenant_id, installation_id, agent_control_device_id)
        REFERENCES agent.agent_devices (tenant_id, installation_id, agent_device_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_bootstraps_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_bootstraps_ids_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(bootstrap_id)
        AND system.is_uuid_v7(owner_device_id)
        AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(binding_id)
        AND system.is_uuid_v7(agent_control_device_id)
        AND system.is_uuid_v7(connector_id)
        AND (recipient_id IS NULL OR system.is_uuid_v7(recipient_id))
        AND (route_id IS NULL OR system.is_uuid_v7(route_id))
        AND (delivery_id IS NULL OR system.is_uuid_v7(delivery_id))
        AND agent.is_public_id(owner_identity_id, 'dtxi1')
    ),
    CONSTRAINT agent_route_bootstraps_values_valid CHECK (
        (route_fence IS NULL OR octet_length(route_fence) = 32)
        AND octet_length(owner_signed_intent) BETWEEN 1 AND 196608
        AND octet_length(request_digest) = 32
        AND octet_length(begin_receipt_bytes) BETWEEN 1 AND 65536
        AND octet_length(begin_receipt_digest) = 32
        AND expires_at_ms BETWEEN 1 AND 253402300799999
        AND created_at_ms BETWEEN 0 AND expires_at_ms - 1
        AND updated_at_ms BETWEEN created_at_ms AND 253402300799999
        AND state IN (
            'pending_recipient', 'recipient_ready', 'pending_delivery',
            'installed', 'rejected', 'expired', 'revoked'
        )
        AND (
            (state = 'pending_recipient'
             AND route_fence IS NULL
             AND recipient_id IS NULL AND recipient_capsule_digest IS NULL
             AND opaque_recipient_capsule IS NULL AND route_id IS NULL
             AND delivery_id IS NULL AND bootstrap_capsule_digest IS NULL
             AND opaque_sealed_bootstrap IS NULL AND delivery_request_digest IS NULL
             AND delivery_receipt_bytes IS NULL AND delivery_receipt_digest IS NULL
             AND rejection_code IS NULL)
            OR (state = 'recipient_ready'
                AND route_fence IS NULL
                AND recipient_id IS NOT NULL AND octet_length(recipient_capsule_digest) = 32
                AND octet_length(opaque_recipient_capsule) BETWEEN 1 AND 196608
                AND route_id IS NULL AND delivery_id IS NULL
                AND bootstrap_capsule_digest IS NULL AND opaque_sealed_bootstrap IS NULL
                AND delivery_request_digest IS NULL AND delivery_receipt_bytes IS NULL
                AND delivery_receipt_digest IS NULL
                AND rejection_code IS NULL)
            OR (state = 'pending_delivery'
                AND route_fence IS NULL
                AND recipient_id IS NOT NULL AND octet_length(recipient_capsule_digest) = 32
                AND octet_length(opaque_recipient_capsule) BETWEEN 1 AND 196608
                AND route_id IS NOT NULL AND delivery_id IS NOT NULL
                AND octet_length(bootstrap_capsule_digest) = 32
                AND octet_length(opaque_sealed_bootstrap) BETWEEN 1 AND 196608
                AND octet_length(delivery_request_digest) = 32
                AND octet_length(delivery_receipt_bytes) BETWEEN 1 AND 65536
                AND octet_length(delivery_receipt_digest) = 32
                AND rejection_code IS NULL)
            OR (state = 'installed'
                AND octet_length(route_fence) = 32
                AND recipient_id IS NOT NULL AND octet_length(recipient_capsule_digest) = 32
                AND octet_length(opaque_recipient_capsule) BETWEEN 1 AND 196608
                AND route_id IS NOT NULL AND delivery_id IS NOT NULL
                AND octet_length(bootstrap_capsule_digest) = 32
                AND octet_length(opaque_sealed_bootstrap) BETWEEN 1 AND 196608
                AND octet_length(delivery_request_digest) = 32
                AND octet_length(delivery_receipt_bytes) BETWEEN 1 AND 65536
                AND octet_length(delivery_receipt_digest) = 32
                AND rejection_code IS NULL)
            OR (state = 'rejected'
                AND route_fence IS NULL
                AND recipient_id IS NOT NULL AND octet_length(recipient_capsule_digest) = 32
                AND octet_length(opaque_recipient_capsule) BETWEEN 1 AND 196608
                AND route_id IS NOT NULL AND delivery_id IS NOT NULL
                AND octet_length(bootstrap_capsule_digest) = 32
                AND octet_length(opaque_sealed_bootstrap) BETWEEN 1 AND 196608
                AND octet_length(delivery_request_digest) = 32
                AND octet_length(delivery_receipt_bytes) BETWEEN 1 AND 65536
                AND octet_length(delivery_receipt_digest) = 32
                AND rejection_code ~ '^[A-Z][A-Z0-9_]{2,63}$')
            OR (state IN ('expired', 'revoked'))
        )
    )
);

-- One owner/device/binding tuple has at most one live bootstrap.  Installed
-- heads are included so an accidental second Begin cannot replace an active
-- route before it is explicitly expired or revoked.
CREATE UNIQUE INDEX agent_route_bootstraps_live_tuple_unique
    ON agent.agent_route_bootstraps (
        tenant_id, owner_identity_id, owner_device_id, installation_id,
        binding_id, agent_control_device_id
    )
    WHERE state IN ('pending_recipient', 'recipient_ready', 'pending_delivery', 'installed');

CREATE TABLE agent.agent_route_bootstrap_outbox (
    tenant_id uuid NOT NULL,
    outbox_id uuid NOT NULL,
    bootstrap_id uuid NOT NULL,
    delivery_id uuid,
    connector_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    command_sequence bigint NOT NULL,
    command_payload_digest bytea NOT NULL,
    encoded_command_digest bytea NOT NULL,
    command_kind text NOT NULL,
    payload_digest bytea NOT NULL,
    opaque_payload bytea NOT NULL,
    state text NOT NULL,
    result_digest bytea,
    resolved_at_ms bigint,
    rejection_code text,
    created_at_ms bigint NOT NULL,
    dispatched_at_ms bigint,
    PRIMARY KEY (tenant_id, outbox_id),
    CONSTRAINT agent_route_bootstrap_outbox_bootstrap_fk
        FOREIGN KEY (tenant_id, bootstrap_id)
        REFERENCES agent.agent_route_bootstraps (tenant_id, bootstrap_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_bootstrap_outbox_ids_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(outbox_id)
        AND system.is_uuid_v7(bootstrap_id)
        AND (delivery_id IS NULL OR system.is_uuid_v7(delivery_id))
        AND system.is_uuid_v7(connector_id)
        AND system.is_uuid_v7(operation_id)
    ),
    CONSTRAINT agent_route_bootstrap_outbox_values_valid CHECK (
        command_kind IN ('prepare_recipient', 'deliver_bootstrap')
        AND command_sequence BETWEEN 1 AND 9007199254740991
        AND octet_length(command_payload_digest) = 32
        AND octet_length(encoded_command_digest) = 32
        AND octet_length(payload_digest) = 32
        AND octet_length(opaque_payload) BETWEEN 1 AND 196608
        AND state IN ('pending', 'dispatched', 'acknowledged', 'rejected', 'cancelled')
        AND created_at_ms BETWEEN 0 AND 253402300799999
        AND (dispatched_at_ms IS NULL OR dispatched_at_ms BETWEEN created_at_ms AND 253402300799999)
        AND (
            (state IN ('pending', 'dispatched', 'cancelled')
             AND result_digest IS NULL AND resolved_at_ms IS NULL AND rejection_code IS NULL)
            OR (state = 'acknowledged'
                AND octet_length(result_digest) = 32
                AND resolved_at_ms BETWEEN created_at_ms AND 253402300799999
                AND rejection_code IS NULL)
            OR (state = 'rejected'
                AND octet_length(result_digest) = 32
                AND resolved_at_ms BETWEEN created_at_ms AND 253402300799999
                AND rejection_code ~ '^[A-Z][A-Z0-9_]{2,63}$')
        )
        AND ((command_kind = 'prepare_recipient' AND delivery_id IS NULL)
          OR (command_kind = 'deliver_bootstrap' AND delivery_id IS NOT NULL))
    )
);

CREATE UNIQUE INDEX agent_route_bootstrap_outbox_prepare_unique
    ON agent.agent_route_bootstrap_outbox (tenant_id, bootstrap_id, command_kind)
    WHERE command_kind = 'prepare_recipient';
CREATE UNIQUE INDEX agent_route_bootstrap_outbox_delivery_unique
    ON agent.agent_route_bootstrap_outbox (tenant_id, delivery_id, command_kind)
    WHERE command_kind = 'deliver_bootstrap';

CREATE TABLE agent.agent_route_binding_heads (
    tenant_id uuid NOT NULL,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    agent_control_device_id uuid NOT NULL,
    bootstrap_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    route_id uuid NOT NULL,
    route_fence bytea NOT NULL,
    capsule_digest bytea NOT NULL,
    expires_at_ms bigint NOT NULL,
    installed_at_ms bigint NOT NULL,
    PRIMARY KEY (
        tenant_id, owner_identity_id, owner_device_id, installation_id,
        binding_id, agent_control_device_id
    ),
    CONSTRAINT agent_route_binding_heads_bootstrap_fk
        FOREIGN KEY (tenant_id, bootstrap_id)
        REFERENCES agent.agent_route_bootstraps (tenant_id, bootstrap_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_route_binding_heads_ids_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(owner_device_id)
        AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(binding_id)
        AND system.is_uuid_v7(agent_control_device_id)
        AND system.is_uuid_v7(bootstrap_id)
        AND system.is_uuid_v7(delivery_id)
        AND system.is_uuid_v7(route_id)
        AND agent.is_public_id(owner_identity_id, 'dtxi1')
    ),
    CONSTRAINT agent_route_binding_heads_values_valid CHECK (
        octet_length(route_fence) = 32
        AND octet_length(capsule_digest) = 32
        AND installed_at_ms BETWEEN 0 AND expires_at_ms - 1
        AND expires_at_ms BETWEEN 1 AND 253402300799999
    )
);

CREATE UNIQUE INDEX agent_route_binding_heads_route_unique
    ON agent.agent_route_binding_heads (tenant_id, route_id);

ALTER TABLE agent.agent_route_bootstraps ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_route_bootstraps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_route_bootstraps
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_route_bootstrap_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_route_bootstrap_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_route_bootstrap_outbox
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_route_binding_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_route_binding_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_route_binding_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.agent_route_bootstraps, agent.agent_route_bootstrap_outbox,
    agent.agent_route_binding_heads FROM PUBLIC;
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON agent.agent_route_bootstraps,
            agent.agent_route_bootstrap_outbox, agent.agent_route_binding_heads
            TO dtx_agent_runtime;
    END IF;
END
$grant$;
