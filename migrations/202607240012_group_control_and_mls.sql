-- Group membership commands authenticate the caller in the same transaction
-- that reads/writes the durable saga.  The group runtime may therefore read
-- only the immutable identity projection needed by
-- `DeviceSessionRepository::authenticate_in_transaction`; it never receives
-- identity mutation, KeyPackage, or identity-owner capability.
CREATE FUNCTION identity.identity_group_reader_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT COALESCE(
        pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'),
        false
    )
$$;

-- The mailbox reader branch is SELECT-only: `WITH CHECK` deliberately
-- continues to exclude it.
-- All role/owner checks are inlined because PostgreSQL validates RLS helper
-- EXECUTE privileges for every caller covered by a policy. The group branch
-- checks the dedicated reader function's grant without invoking it; the same
-- grant is the explicit ACL proof checked by `GroupPgStore`.
ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_identity_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_mailbox_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname = 'identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname = 'identity'
        )
    );

ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_identity_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_mailbox_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname = 'identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname = 'identity'
        )
    );

ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_identity_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_mailbox_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname = 'identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname = 'identity'
        )
    );

-- Existing deployments can provision application roles before migrations; new
-- local/test environments may provision them later and grant the same narrow
-- matrix as part of their runtime setup.
DO $grant$
BEGIN
    IF to_regrole('dtx_group_runtime') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA identity TO dtx_group_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_group_reader_authorized()
            TO dtx_group_runtime;
        GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
            TO dtx_group_runtime;
    END IF;
END
$grant$;

REVOKE ALL ON FUNCTION identity.identity_group_reader_authorized() FROM PUBLIC;
-- Local group-policy mutations need the same response-loss behavior as
-- membership commands. This append-only receipt table deliberately has no
-- foreign key to policy_heads: an authenticated create attempt rejected before
-- a group exists must still return its original terminal receipt on replay.
CREATE TABLE groups.control_commands (
    tenant_id uuid NOT NULL,
    command_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    actor_identity_id text NOT NULL,
    actor_device_id uuid NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    action text NOT NULL,
    request_digest bytea NOT NULL,
    binding_digest bytea NOT NULL,
    disposition text NOT NULL,
    policy_revision bigint,
    rejection text,
    administrator_count smallint NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, command_id),
    CONSTRAINT groups_control_commands_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT groups_control_commands_scope_kind_valid
        CHECK (scope_kind IN ('private_conversation', 'controlled_public_channel')),
    CONSTRAINT groups_control_commands_scope_id_bounded
        CHECK (octet_length(scope_id) BETWEEN 36 AND 57),
    CONSTRAINT groups_control_commands_actor_shape
        CHECK (octet_length(actor_identity_id) = 57
               AND actor_identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CONSTRAINT groups_control_commands_actor_device_v7
        CHECK (system.is_uuid_v7(actor_device_id)),
    CONSTRAINT groups_control_commands_idempotency_hash_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT groups_control_commands_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT groups_control_commands_binding_digest_size
        CHECK (octet_length(binding_digest) = 32),
    CONSTRAINT groups_control_commands_action_valid
        CHECK (action IN ('create_group', 'grant_admin', 'revoke_admin',
                          'issue_invite', 'revoke_invite')),
    CONSTRAINT groups_control_commands_disposition_valid
        CHECK ((
            (disposition IN ('applied', 'already_applied')
                AND policy_revision BETWEEN 1 AND 9007199254740991
                AND rejection IS NULL)
            OR (disposition = 'rejected'
                AND policy_revision IS NULL
                AND rejection IN ('policy_denied', 'revision_conflict',
                                  'admin_limit_reached', 'invalid_operation',
                                  'group_exists'))
        ) IS TRUE),
    CONSTRAINT groups_control_commands_administrator_count_valid
        CHECK (administrator_count BETWEEN 0 AND 5),
    CONSTRAINT groups_control_commands_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT groups_control_commands_idempotency_unique
        UNIQUE (tenant_id, scope_kind, scope_id, actor_identity_id, idempotency_key_hash)
);

CREATE TRIGGER groups_control_commands_append_only
BEFORE UPDATE OR DELETE ON groups.control_commands
FOR EACH ROW
EXECUTE FUNCTION groups.reject_immutable_mutation();

ALTER TABLE groups.control_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.control_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_runtime_only ON groups.control_commands
    USING (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    )
    WITH CHECK (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    );

DO $grant$
BEGIN
    IF to_regrole('dtx_group_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON groups.control_commands TO dtx_group_runtime;
    END IF;
END
$grant$;
-- AR3: fenced Agent Run checkpoints, output references, and exact terminal claims.

CREATE TABLE agent.agent_run_execution_heads (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    run_lease_id uuid NOT NULL,
    run_lease_epoch bigint NOT NULL,
    connector_id uuid NOT NULL,
    connector_boot_id uuid NOT NULL,
    connector_generation bigint NOT NULL,
    connector_lease_id uuid NOT NULL,
    connector_lease_epoch bigint NOT NULL,
    last_checkpoint_sequence bigint NOT NULL DEFAULT 0,
    last_output_sequence bigint NOT NULL DEFAULT 0,
    terminal_sequence bigint,
    terminal_kind text,
    state text NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    CONSTRAINT agent_run_execution_heads_run_fk FOREIGN KEY (tenant_id, run_id)
        REFERENCES agent.agent_runs (tenant_id, run_id) ON DELETE RESTRICT,
    CONSTRAINT agent_run_execution_heads_lease_fk FOREIGN KEY (tenant_id, run_id, run_lease_id)
        REFERENCES agent.agent_run_leases (tenant_id, run_id, run_lease_id) ON DELETE RESTRICT,
    CONSTRAINT agent_run_execution_heads_ids_v7 CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(run_id)
        AND system.is_uuid_v7(run_lease_id) AND system.is_uuid_v7(connector_id)
        AND system.is_uuid_v7(connector_boot_id) AND system.is_uuid_v7(connector_lease_id)
    ),
    CONSTRAINT agent_run_execution_heads_values CHECK (
        run_lease_epoch BETWEEN 1 AND 9007199254740991
        AND connector_generation BETWEEN 1 AND 9007199254740991
        AND connector_lease_epoch BETWEEN 1 AND 9007199254740991
        AND last_checkpoint_sequence BETWEEN 0 AND 9007199254740991
        AND last_output_sequence BETWEEN 0 AND 9007199254740991
        AND (terminal_sequence IS NULL OR terminal_sequence BETWEEN 1 AND 9007199254740991)
        AND ((state = 'active' AND terminal_sequence IS NULL AND terminal_kind IS NULL)
          OR (state IN ('completed', 'failed') AND terminal_sequence IS NOT NULL
              AND terminal_kind = state))
        AND updated_at_ms >= created_at_ms
    )
);

CREATE TABLE agent.agent_run_checkpoints (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    checkpoint_sequence bigint NOT NULL,
    checkpoint_artifact_id uuid NOT NULL,
    checkpoint_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, run_id, checkpoint_sequence),
    UNIQUE (tenant_id, checkpoint_artifact_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES agent.agent_run_execution_heads (tenant_id, run_id),
    CHECK (checkpoint_sequence BETWEEN 1 AND 9007199254740991),
    CHECK (system.is_uuid_v7(checkpoint_artifact_id)),
    CHECK (octet_length(checkpoint_digest) = 32)
);

CREATE TABLE agent.agent_run_outputs (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    output_sequence bigint NOT NULL,
    output_event_id uuid NOT NULL,
    output_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, run_id, output_sequence),
    UNIQUE (tenant_id, output_event_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES agent.agent_run_execution_heads (tenant_id, run_id),
    CHECK (output_sequence BETWEEN 1 AND 9007199254740991),
    CHECK (system.is_uuid_v7(output_event_id)),
    CHECK (octet_length(output_digest) = 32)
);

CREATE TABLE agent.agent_run_terminals (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    terminal_sequence bigint NOT NULL,
    terminal_kind text NOT NULL,
    result_event_id uuid,
    stable_error_code text,
    evidence_artifact_id uuid,
    evidence_digest bytea,
    terminal_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES agent.agent_run_execution_heads (tenant_id, run_id),
    CHECK (terminal_sequence BETWEEN 1 AND 9007199254740991),
    CHECK (octet_length(terminal_digest) = 32),
    CHECK ((terminal_kind = 'completed' AND system.is_uuid_v7(result_event_id)
            AND stable_error_code IS NULL AND evidence_artifact_id IS NULL
            AND evidence_digest IS NULL)
        OR (terminal_kind = 'failed' AND result_event_id IS NULL
            AND stable_error_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
            AND ((evidence_artifact_id IS NULL AND evidence_digest IS NULL)
              OR (system.is_uuid_v7(evidence_artifact_id) AND octet_length(evidence_digest) = 32))))
);

ALTER TABLE agent.agent_run_execution_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_execution_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_execution_heads
    USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_run_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_checkpoints
    USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_run_outputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_outputs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_outputs
    USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_run_terminals ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_terminals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_terminals
    USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.agent_run_execution_heads FROM PUBLIC;
REVOKE ALL ON agent.agent_run_checkpoints FROM PUBLIC;
REVOKE ALL ON agent.agent_run_outputs FROM PUBLIC;
REVOKE ALL ON agent.agent_run_terminals FROM PUBLIC;
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
-- Single-writer MLS Commit Sequencer state. The server treats MLS Commit and
-- Welcome artifacts as opaque bytes/digests and never attempts to decode MLS
-- application data.
CREATE TABLE groups.mls_heads (
    tenant_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    epoch bigint NOT NULL,
    head_digest bytea NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, scope_kind, scope_id),
    FOREIGN KEY (tenant_id, scope_kind, scope_id)
        REFERENCES groups.policy_heads (tenant_id, scope_kind, scope_id)
        ON DELETE RESTRICT,
    CHECK (system.is_uuid_v7(tenant_id)),
    CHECK (scope_kind IN ('private_conversation', 'controlled_public_channel')),
    CHECK (octet_length(scope_id) BETWEEN 36 AND 57),
    CHECK (epoch BETWEEN 0 AND 9007199254740991),
    CHECK (octet_length(head_digest) = 32),
    CHECK (updated_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TABLE groups.mls_commit_intents (
    tenant_id uuid NOT NULL,
    submission_id uuid NOT NULL,
    membership_command_id uuid,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    authorization_kind text NOT NULL,
    actor_identity_id text NOT NULL,
    actor_device_id uuid NOT NULL,
    candidate_identity_id text NOT NULL,
    candidate_device_id uuid NOT NULL,
    candidate_key_package_digest bytea NOT NULL,
    candidate_proof_digest bytea NOT NULL,
    controller_device_id uuid,
    controller_consent_digest bytea,
    idempotency_key_hash bytea NOT NULL,
    request_digest bytea NOT NULL,
    authorization_digest bytea,
    parent_epoch bigint NOT NULL,
    parent_head_digest bytea NOT NULL,
    admitted_epoch bigint NOT NULL,
    result_head_digest bytea NOT NULL,
    commit_bytes bytea NOT NULL,
    commit_digest bytea NOT NULL,
    welcome_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, submission_id),
    FOREIGN KEY (tenant_id, scope_kind, scope_id)
        REFERENCES groups.policy_heads (tenant_id, scope_kind, scope_id)
        ON DELETE RESTRICT,
    CHECK (system.is_uuid_v7(tenant_id)),
    CHECK (system.is_uuid_v7(submission_id)),
    CHECK (membership_command_id IS NULL OR system.is_uuid_v7(membership_command_id)),
    CHECK (scope_kind IN ('private_conversation', 'controlled_public_channel')),
    CHECK (octet_length(scope_id) BETWEEN 36 AND 57),
    CHECK (authorization_kind IN ('owner_bootstrap', 'approved_identity_join', 'existing_member_device_add')),
    CHECK ((authorization_kind = 'owner_bootstrap'
            AND membership_command_id IS NULL
            AND authorization_digest IS NULL
            AND controller_device_id IS NULL
            AND controller_consent_digest IS NULL)
           OR (authorization_kind = 'approved_identity_join'
            AND membership_command_id IS NOT NULL
            AND octet_length(authorization_digest) = 32
            AND controller_device_id IS NULL
            AND controller_consent_digest IS NULL)
           OR (authorization_kind = 'existing_member_device_add'
               AND membership_command_id IS NULL
               AND authorization_digest IS NULL
               AND controller_device_id IS NOT NULL
               AND octet_length(controller_consent_digest) = 32)),
    CHECK (octet_length(actor_identity_id) = 57 AND actor_identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CHECK (system.is_uuid_v7(actor_device_id)),
    CHECK (octet_length(candidate_identity_id) = 57 AND candidate_identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CHECK (system.is_uuid_v7(candidate_device_id)),
    CHECK (octet_length(candidate_key_package_digest) = 32),
    CHECK (octet_length(candidate_proof_digest) = 32),
    CHECK (controller_device_id IS NULL OR system.is_uuid_v7(controller_device_id)),
    CHECK (octet_length(idempotency_key_hash) = 32),
    CHECK (octet_length(request_digest) = 32),
    CHECK (parent_epoch BETWEEN 0 AND 9007199254740991),
    CHECK (admitted_epoch = parent_epoch + 1 AND admitted_epoch BETWEEN 1 AND 9007199254740991),
    CHECK (octet_length(parent_head_digest) = 32),
    CHECK (octet_length(result_head_digest) = 32),
    CHECK (octet_length(commit_bytes) BETWEEN 1 AND 1048576),
    CHECK (octet_length(commit_digest) = 32),
    CHECK (octet_length(welcome_digest) = 32),
    CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    UNIQUE (tenant_id, scope_kind, scope_id, actor_identity_id, idempotency_key_hash),
    UNIQUE (tenant_id, scope_kind, scope_id, admitted_epoch),
    UNIQUE (tenant_id, scope_kind, scope_id, commit_digest)
);

CREATE TABLE groups.mls_commit_receipts (
    tenant_id uuid NOT NULL,
    submission_id uuid NOT NULL,
    receipt_cbor bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    signing_public_key bytea NOT NULL,
    signature bytea NOT NULL,
    PRIMARY KEY (tenant_id, submission_id),
    FOREIGN KEY (tenant_id, submission_id)
        REFERENCES groups.mls_commit_intents (tenant_id, submission_id)
        ON DELETE RESTRICT,
    CHECK (octet_length(receipt_cbor) BETWEEN 1 AND 16384),
    CHECK (octet_length(receipt_digest) = 32),
    CHECK (octet_length(signing_public_key) = 32),
    CHECK (octet_length(signature) = 64)
);

CREATE UNIQUE INDEX groups_mls_commit_intents_membership_command_unique
    ON groups.mls_commit_intents (tenant_id, scope_kind, scope_id, membership_command_id)
    WHERE membership_command_id IS NOT NULL;

CREATE TABLE groups.mls_sequencer_outbox (
    tenant_id uuid NOT NULL,
    submission_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    event_kind text NOT NULL,
    payload_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, submission_id),
    FOREIGN KEY (tenant_id, submission_id)
        REFERENCES groups.mls_commit_intents (tenant_id, submission_id)
        ON DELETE RESTRICT,
    CHECK (event_kind = 'mls_commit_accepted'),
    CHECK (octet_length(payload_digest) = 32),
    CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TABLE groups.mls_device_members (
    tenant_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    identity_id text NOT NULL,
    device_id uuid NOT NULL,
    admitted_epoch bigint NOT NULL,
    commit_digest bytea NOT NULL,
    state text NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, scope_kind, scope_id, identity_id, device_id),
    FOREIGN KEY (tenant_id, scope_kind, scope_id)
        REFERENCES groups.policy_heads (tenant_id, scope_kind, scope_id)
        ON DELETE RESTRICT,
    CHECK (system.is_uuid_v7(tenant_id)),
    CHECK (scope_kind IN ('private_conversation', 'controlled_public_channel')),
    CHECK (octet_length(scope_id) BETWEEN 36 AND 57),
    CHECK (octet_length(identity_id) = 57 AND identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CHECK (system.is_uuid_v7(device_id)),
    CHECK (admitted_epoch BETWEEN 1 AND 9007199254740991),
    CHECK (octet_length(commit_digest) = 32),
    CHECK (state IN ('pending_confirmation', 'active', 'removed')),
    CHECK (updated_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TABLE groups.mls_join_confirmations (
    tenant_id uuid NOT NULL,
    submission_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    identity_id text NOT NULL,
    device_id uuid NOT NULL,
    receipt_digest bytea NOT NULL,
    head_digest bytea NOT NULL,
    signature bytea NOT NULL,
    confirmed_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, submission_id),
    FOREIGN KEY (tenant_id, submission_id)
        REFERENCES groups.mls_commit_intents (tenant_id, submission_id)
        ON DELETE RESTRICT,
    CHECK (octet_length(identity_id) = 57 AND identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CHECK (system.is_uuid_v7(device_id)),
    CHECK (octet_length(receipt_digest) = 32),
    CHECK (octet_length(head_digest) = 32),
    CHECK (octet_length(signature) = 64),
    CHECK (confirmed_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TRIGGER groups_mls_commit_intents_append_only
BEFORE UPDATE OR DELETE ON groups.mls_commit_intents
FOR EACH ROW EXECUTE FUNCTION groups.reject_immutable_mutation();
CREATE TRIGGER groups_mls_commit_receipts_append_only
BEFORE UPDATE OR DELETE ON groups.mls_commit_receipts
FOR EACH ROW EXECUTE FUNCTION groups.reject_immutable_mutation();
CREATE TRIGGER groups_mls_sequencer_outbox_append_only
BEFORE UPDATE OR DELETE ON groups.mls_sequencer_outbox
FOR EACH ROW EXECUTE FUNCTION groups.reject_immutable_mutation();
CREATE TRIGGER groups_mls_join_confirmations_append_only
BEFORE UPDATE OR DELETE ON groups.mls_join_confirmations
FOR EACH ROW EXECUTE FUNCTION groups.reject_immutable_mutation();

ALTER TABLE groups.mls_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.mls_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE groups.mls_commit_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.mls_commit_intents FORCE ROW LEVEL SECURITY;
ALTER TABLE groups.mls_commit_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.mls_commit_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE groups.mls_sequencer_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.mls_sequencer_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE groups.mls_device_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.mls_device_members FORCE ROW LEVEL SECURITY;
ALTER TABLE groups.mls_join_confirmations ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.mls_join_confirmations FORCE ROW LEVEL SECURITY;

CREATE POLICY groups_runtime_only ON groups.mls_heads
    USING ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
           AND tenant_id = system.current_tenant_id())
    WITH CHECK ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
                AND tenant_id = system.current_tenant_id());
CREATE POLICY groups_runtime_only ON groups.mls_commit_intents
    USING ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
           AND tenant_id = system.current_tenant_id())
    WITH CHECK ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
                AND tenant_id = system.current_tenant_id());
CREATE POLICY groups_runtime_only ON groups.mls_commit_receipts
    USING ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
           AND tenant_id = system.current_tenant_id())
    WITH CHECK ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
                AND tenant_id = system.current_tenant_id());
CREATE POLICY groups_runtime_only ON groups.mls_sequencer_outbox
    USING ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
           AND tenant_id = system.current_tenant_id())
    WITH CHECK ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
                AND tenant_id = system.current_tenant_id());
CREATE POLICY groups_runtime_only ON groups.mls_device_members
    USING ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
           AND tenant_id = system.current_tenant_id())
    WITH CHECK ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
                AND tenant_id = system.current_tenant_id());
CREATE POLICY groups_runtime_only ON groups.mls_join_confirmations
    USING ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
           AND tenant_id = system.current_tenant_id())
    WITH CHECK ((groups.group_runtime_authorized() OR groups.group_owner_authorized())
                AND tenant_id = system.current_tenant_id());

DO $grant$
BEGIN
    IF to_regrole('dtx_group_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON groups.mls_heads TO dtx_group_runtime;
        GRANT SELECT, INSERT ON groups.mls_commit_intents TO dtx_group_runtime;
        GRANT SELECT, INSERT ON groups.mls_commit_receipts TO dtx_group_runtime;
        GRANT SELECT, INSERT ON groups.mls_sequencer_outbox TO dtx_group_runtime;
        GRANT SELECT, INSERT, UPDATE ON groups.mls_device_members TO dtx_group_runtime;
        GRANT SELECT, INSERT ON groups.mls_join_confirmations TO dtx_group_runtime;
    END IF;
END
$grant$;
