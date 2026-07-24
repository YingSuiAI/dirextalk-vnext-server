-- Group membership is tenant-scoped owner data. A membership reservation must
-- survive a remote Sequencer response loss, so this schema owns a normalized
-- saga state machine and its own non-owner writer role boundary. Database
-- operators provision `dtx_group_runtime`; migrations never create application
-- runtime principals.
CREATE SCHEMA groups;

CREATE FUNCTION groups.group_runtime_authorized()
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

CREATE FUNCTION groups.group_owner_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT current_user = pg_get_userbyid(nspowner)
      FROM pg_namespace
     WHERE nspname = 'groups'
$$;

CREATE FUNCTION groups.reject_immutable_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'group membership immutable relation cannot be rewritten'
        USING ERRCODE = '23514';
END
$$;

CREATE TABLE groups.policy_heads (
    tenant_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    owner_identity_id text NOT NULL,
    policy_revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, scope_kind, scope_id),
    CONSTRAINT groups_policy_heads_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT groups_policy_heads_scope_kind_valid
        CHECK (scope_kind IN ('private_conversation', 'controlled_public_channel')),
    CONSTRAINT groups_policy_heads_scope_id_bounded
        CHECK (octet_length(scope_id) BETWEEN 36 AND 57),
    CONSTRAINT groups_policy_heads_owner_shape
        CHECK (octet_length(owner_identity_id) = 57 AND owner_identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CONSTRAINT groups_policy_heads_revision_safe
        CHECK (policy_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT groups_policy_heads_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT groups_policy_heads_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE TABLE groups.admin_terms (
    tenant_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    identity_id text NOT NULL,
    authorization_generation bigint NOT NULL,
    active boolean NOT NULL,
    PRIMARY KEY (tenant_id, scope_kind, scope_id, identity_id),
    CONSTRAINT groups_admin_terms_head_fk
        FOREIGN KEY (tenant_id, scope_kind, scope_id)
        REFERENCES groups.policy_heads (tenant_id, scope_kind, scope_id)
        ON DELETE RESTRICT,
    CONSTRAINT groups_admin_terms_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT groups_admin_terms_identity_shape
        CHECK (octet_length(identity_id) = 57 AND identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CONSTRAINT groups_admin_terms_generation_safe
        CHECK (authorization_generation BETWEEN 1 AND 9007199254740991)
);

CREATE TABLE groups.members (
    tenant_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    identity_id text NOT NULL,
    admitted_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, scope_kind, scope_id, identity_id),
    CONSTRAINT groups_members_head_fk
        FOREIGN KEY (tenant_id, scope_kind, scope_id)
        REFERENCES groups.policy_heads (tenant_id, scope_kind, scope_id)
        ON DELETE RESTRICT,
    CONSTRAINT groups_members_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT groups_members_identity_shape
        CHECK (octet_length(identity_id) = 57 AND identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CONSTRAINT groups_members_admitted_at_valid
        CHECK (admitted_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TABLE groups.invites (
    tenant_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    invite_id uuid NOT NULL,
    issuer_identity_id text NOT NULL,
    target_identity_id text,
    max_uses integer NOT NULL,
    use_count integer NOT NULL,
    reserved_use_count integer NOT NULL,
    expires_at_ms bigint NOT NULL,
    revoked boolean NOT NULL,
    policy_revision bigint NOT NULL,
    issuer_authority text NOT NULL,
    issuer_authorization_generation bigint,
    PRIMARY KEY (tenant_id, scope_kind, scope_id, invite_id),
    CONSTRAINT groups_invites_head_fk
        FOREIGN KEY (tenant_id, scope_kind, scope_id)
        REFERENCES groups.policy_heads (tenant_id, scope_kind, scope_id)
        ON DELETE RESTRICT,
    CONSTRAINT groups_invites_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT groups_invites_issuer_shape
        CHECK (octet_length(issuer_identity_id) = 57 AND issuer_identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CONSTRAINT groups_invites_target_shape
        CHECK (target_identity_id IS NULL
               OR (octet_length(target_identity_id) = 57 AND target_identity_id ~ '^dtxi1[a-z2-7]{52}$')),
    CONSTRAINT groups_invites_use_counts_valid
        CHECK (max_uses > 0 AND use_count >= 0 AND reserved_use_count >= 0
               AND use_count + reserved_use_count <= max_uses),
    CONSTRAINT groups_invites_expiry_valid
        CHECK (expires_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT groups_invites_revision_safe
        CHECK (policy_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT groups_invites_authority_valid
        CHECK ((
            (issuer_authority = 'owner' AND issuer_authorization_generation IS NULL)
            OR (issuer_authority = 'admin'
                AND issuer_authorization_generation BETWEEN 1 AND 9007199254740991)
        ) IS TRUE)
);

CREATE TABLE groups.join_records (
    tenant_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    request_id uuid NOT NULL,
    candidate_identity_id text NOT NULL,
    invite_id uuid NOT NULL,
    state text NOT NULL,
    requested_at_ms bigint NOT NULL,
    reserved_by_identity_id text,
    reserved_authority text,
    reserved_authorization_generation bigint,
    reserved_at_ms bigint,
    reservation_policy_revision bigint,
    approved_by_identity_id text,
    approved_at_ms bigint,
    approval_policy_revision bigint,
    PRIMARY KEY (tenant_id, scope_kind, scope_id, request_id),
    CONSTRAINT groups_join_records_head_fk
        FOREIGN KEY (tenant_id, scope_kind, scope_id)
        REFERENCES groups.policy_heads (tenant_id, scope_kind, scope_id)
        ON DELETE RESTRICT,
    CONSTRAINT groups_join_records_invite_fk
        FOREIGN KEY (tenant_id, scope_kind, scope_id, invite_id)
        REFERENCES groups.invites (tenant_id, scope_kind, scope_id, invite_id)
        ON DELETE RESTRICT,
    CONSTRAINT groups_join_records_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT groups_join_records_candidate_shape
        CHECK (octet_length(candidate_identity_id) = 57 AND candidate_identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CONSTRAINT groups_join_records_requested_at_valid
        CHECK (requested_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT groups_join_records_state_valid
        CHECK ((
            (state = 'pending'
                AND reserved_by_identity_id IS NULL
                AND reserved_authority IS NULL
                AND reserved_authorization_generation IS NULL
                AND reserved_at_ms IS NULL
                AND reservation_policy_revision IS NULL
                AND approved_by_identity_id IS NULL
                AND approved_at_ms IS NULL
                AND approval_policy_revision IS NULL)
            OR (state = 'reserved'
                AND octet_length(reserved_by_identity_id) = 57
                AND reserved_by_identity_id ~ '^dtxi1[a-z2-7]{52}$'
                AND reserved_authority IN ('owner', 'admin')
                AND ((reserved_authority = 'owner' AND reserved_authorization_generation IS NULL)
                     OR (reserved_authority = 'admin'
                         AND reserved_authorization_generation BETWEEN 1 AND 9007199254740991))
                AND reserved_at_ms BETWEEN -62135596800000 AND 253402300799999
                AND reservation_policy_revision BETWEEN 1 AND 9007199254740991
                AND approved_by_identity_id IS NULL
                AND approved_at_ms IS NULL
                AND approval_policy_revision IS NULL)
            OR (state = 'approved'
                AND octet_length(approved_by_identity_id) = 57
                AND approved_by_identity_id ~ '^dtxi1[a-z2-7]{52}$'
                AND approved_at_ms BETWEEN -62135596800000 AND 253402300799999
                AND approval_policy_revision BETWEEN 1 AND 9007199254740991)
        ) IS TRUE)
);

CREATE UNIQUE INDEX groups_join_records_one_active_candidate_idx
    ON groups.join_records (tenant_id, scope_kind, scope_id, candidate_identity_id)
    WHERE state IN ('pending', 'reserved');

CREATE TABLE groups.membership_commands (
    tenant_id uuid NOT NULL,
    command_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    actor_identity_id text NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    kind text NOT NULL,
    request_digest bytea NOT NULL,
    workflow_id uuid,
    terminal_phase text,
    terminal_admission text,
    terminal_commit_scope_kind text,
    terminal_commit_scope_id text,
    terminal_commit_command_id uuid,
    terminal_commit_request_digest bytea,
    terminal_committed_digest bytea,
    terminal_rejection text,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, command_id),
    CONSTRAINT groups_membership_commands_head_fk
        FOREIGN KEY (tenant_id, scope_kind, scope_id)
        REFERENCES groups.policy_heads (tenant_id, scope_kind, scope_id)
        ON DELETE RESTRICT,
    CONSTRAINT groups_membership_commands_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT groups_membership_commands_actor_shape
        CHECK (octet_length(actor_identity_id) = 57 AND actor_identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CONSTRAINT groups_membership_commands_key_hash_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT groups_membership_commands_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT groups_membership_commands_kind_valid
        CHECK (kind IN ('request_join', 'approve_join')),
    CONSTRAINT groups_membership_commands_terminal_valid
        CHECK ((
            (workflow_id IS NOT NULL
                AND terminal_phase IS NULL
                AND terminal_admission IS NULL
                AND terminal_commit_scope_kind IS NULL
                AND terminal_commit_scope_id IS NULL
                AND terminal_commit_command_id IS NULL
                AND terminal_commit_request_digest IS NULL
                AND terminal_committed_digest IS NULL
                AND terminal_rejection IS NULL)
            OR (workflow_id IS NULL
                AND ((terminal_phase = 'committed'
                      AND terminal_admission IN ('applied', 'already_member')
                      AND terminal_commit_scope_kind IN ('private_conversation', 'controlled_public_channel')
                      AND octet_length(terminal_commit_scope_id) BETWEEN 36 AND 57
                      AND terminal_commit_command_id IS NOT NULL
                      AND octet_length(terminal_commit_request_digest) = 32
                      AND octet_length(terminal_committed_digest) = 32
                      AND terminal_rejection IS NULL)
                     OR (terminal_phase = 'rejected'
                         AND terminal_admission IS NULL
                         AND terminal_commit_scope_kind IS NULL
                         AND terminal_commit_scope_id IS NULL
                         AND terminal_commit_command_id IS NULL
                         AND terminal_commit_request_digest IS NULL
                         AND terminal_committed_digest IS NULL
                         AND terminal_rejection IN ('policy_denied', 'stale_fence', 'admission_denied')))
            )
        ) IS TRUE),
    CONSTRAINT groups_membership_commands_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT groups_membership_commands_idempotency_unique
        UNIQUE (tenant_id, scope_kind, scope_id, actor_identity_id, idempotency_key_hash)
);

CREATE TABLE groups.membership_workflows (
    tenant_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    request_id uuid NOT NULL,
    request_actor_identity_id text NOT NULL,
    request_actor_device_id uuid NOT NULL,
    request_idempotency_key_hash bytea NOT NULL,
    request_policy_revision bigint NOT NULL,
    request_sequencer_head bytea NOT NULL,
    candidate_identity_id text NOT NULL,
    candidate_device_id uuid NOT NULL,
    invite_id uuid NOT NULL,
    state text NOT NULL,
    approval_command_id uuid,
    approval_actor_identity_id text,
    approval_actor_device_id uuid,
    approval_idempotency_key_hash bytea,
    approval_policy_revision bigint,
    approval_sequencer_head bytea,
    authorization_digest bytea,
    admission text,
    commit_scope_kind text,
    commit_scope_id text,
    commit_command_id uuid,
    commit_request_digest bytea,
    committed_digest bytea,
    rejection text,
    PRIMARY KEY (tenant_id, scope_kind, scope_id, request_id),
    CONSTRAINT groups_membership_workflows_head_fk
        FOREIGN KEY (tenant_id, scope_kind, scope_id)
        REFERENCES groups.policy_heads (tenant_id, scope_kind, scope_id)
        ON DELETE RESTRICT,
    CONSTRAINT groups_membership_workflows_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT groups_membership_workflows_request_actor_shape
        CHECK (octet_length(request_actor_identity_id) = 57
               AND request_actor_identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CONSTRAINT groups_membership_workflows_candidate_shape
        CHECK (octet_length(candidate_identity_id) = 57
               AND candidate_identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CONSTRAINT groups_membership_workflows_request_hash_sizes
        CHECK (octet_length(request_idempotency_key_hash) = 32
               AND octet_length(request_sequencer_head) = 32),
    CONSTRAINT groups_membership_workflows_request_revision_safe
        CHECK (request_policy_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT groups_membership_workflows_state_valid
        CHECK ((
            (state = 'pending_approval'
                AND approval_command_id IS NULL
                AND approval_actor_identity_id IS NULL
                AND approval_actor_device_id IS NULL
                AND approval_idempotency_key_hash IS NULL
                AND approval_policy_revision IS NULL
                AND approval_sequencer_head IS NULL
                AND authorization_digest IS NULL
                AND admission IS NULL
                AND commit_scope_kind IS NULL
                AND commit_scope_id IS NULL
                AND commit_command_id IS NULL
                AND commit_request_digest IS NULL
                AND committed_digest IS NULL
                AND rejection IS NULL)
            OR (state IN ('pending_commit', 'reconciling')
                AND approval_command_id IS NOT NULL
                AND octet_length(approval_actor_identity_id) = 57
                AND approval_actor_identity_id ~ '^dtxi1[a-z2-7]{52}$'
                AND approval_actor_device_id IS NOT NULL
                AND octet_length(approval_idempotency_key_hash) = 32
                AND approval_policy_revision BETWEEN 1 AND 9007199254740991
                AND octet_length(approval_sequencer_head) = 32
                AND octet_length(authorization_digest) = 32
                AND admission IS NULL
                AND commit_scope_kind IS NULL
                AND commit_scope_id IS NULL
                AND commit_command_id IS NULL
                AND commit_request_digest IS NULL
                AND committed_digest IS NULL
                AND rejection IS NULL)
            OR (state = 'committed'
                AND admission IN ('applied', 'already_member')
                AND commit_scope_kind IN ('private_conversation', 'controlled_public_channel')
                AND octet_length(commit_scope_id) BETWEEN 36 AND 57
                AND commit_command_id IS NOT NULL
                AND octet_length(commit_request_digest) = 32
                AND octet_length(committed_digest) = 32
                AND rejection IS NULL)
            OR (state = 'rejected'
                AND admission IS NULL
                AND commit_scope_kind IS NULL
                AND commit_scope_id IS NULL
                AND commit_command_id IS NULL
                AND commit_request_digest IS NULL
                AND committed_digest IS NULL
                AND rejection IN ('policy_denied', 'stale_fence', 'admission_denied'))
        ) IS TRUE)
);

CREATE TABLE groups.sequencer_outbox (
    tenant_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    command_id uuid NOT NULL,
    request_id uuid NOT NULL,
    action text NOT NULL,
    state text NOT NULL,
    available_at_ms bigint NOT NULL,
    attempt_count bigint NOT NULL DEFAULT 0,
    leased_action text,
    lease_token uuid,
    lease_expires_at_ms bigint,
    completed_at_ms bigint,
    PRIMARY KEY (tenant_id, scope_kind, scope_id, command_id),
    CONSTRAINT groups_sequencer_outbox_head_fk
        FOREIGN KEY (tenant_id, scope_kind, scope_id)
        REFERENCES groups.policy_heads (tenant_id, scope_kind, scope_id)
        ON DELETE RESTRICT,
    CONSTRAINT groups_sequencer_outbox_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT groups_sequencer_outbox_action_valid
        CHECK (action IN ('submit', 'query')),
    CONSTRAINT groups_sequencer_outbox_state_valid
        CHECK ((
            (state = 'active' AND completed_at_ms IS NULL
                AND ((leased_action IS NULL AND lease_token IS NULL AND lease_expires_at_ms IS NULL)
                     OR (leased_action IN ('submit', 'query')
                          AND lease_token IS NOT NULL AND lease_expires_at_ms IS NOT NULL)))
            OR (state = 'completed' AND completed_at_ms IS NOT NULL
                AND leased_action IS NULL AND lease_token IS NULL AND lease_expires_at_ms IS NULL)
        ) IS TRUE),
    CONSTRAINT groups_sequencer_outbox_time_valid
        CHECK (available_at_ms BETWEEN -62135596800000 AND 253402300799999
               AND (lease_expires_at_ms IS NULL
                    OR lease_expires_at_ms BETWEEN available_at_ms AND 253402300799999)
               AND (completed_at_ms IS NULL
                    OR completed_at_ms BETWEEN available_at_ms AND 253402300799999)),
    CONSTRAINT groups_sequencer_outbox_attempt_safe
        CHECK (attempt_count BETWEEN 0 AND 9007199254740991)
);

CREATE INDEX groups_sequencer_outbox_dispatch_idx
    ON groups.sequencer_outbox (tenant_id, available_at_ms, scope_kind, scope_id, command_id)
    WHERE state = 'active';

CREATE TRIGGER groups_members_append_only
BEFORE UPDATE OR DELETE ON groups.members
FOR EACH ROW
EXECUTE FUNCTION groups.reject_immutable_mutation();

CREATE TRIGGER groups_membership_commands_append_only
BEFORE UPDATE OR DELETE ON groups.membership_commands
FOR EACH ROW
EXECUTE FUNCTION groups.reject_immutable_mutation();

ALTER TABLE groups.policy_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.policy_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_runtime_only ON groups.policy_heads
    USING (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    )
    WITH CHECK (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    );

ALTER TABLE groups.admin_terms ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.admin_terms FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_runtime_only ON groups.admin_terms
    USING (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    )
    WITH CHECK (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    );

ALTER TABLE groups.members ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.members FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_runtime_only ON groups.members
    USING (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    )
    WITH CHECK (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    );

ALTER TABLE groups.invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.invites FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_runtime_only ON groups.invites
    USING (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    )
    WITH CHECK (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    );

ALTER TABLE groups.join_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.join_records FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_runtime_only ON groups.join_records
    USING (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    )
    WITH CHECK (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    );

ALTER TABLE groups.membership_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.membership_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_runtime_only ON groups.membership_commands
    USING (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    )
    WITH CHECK (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    );

ALTER TABLE groups.membership_workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.membership_workflows FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_runtime_only ON groups.membership_workflows
    USING (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    )
    WITH CHECK (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    );

ALTER TABLE groups.sequencer_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups.sequencer_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_runtime_only ON groups.sequencer_outbox
    USING (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    )
    WITH CHECK (
        (groups.group_runtime_authorized() OR groups.group_owner_authorized())
        AND tenant_id = system.current_tenant_id()
    );

REVOKE ALL ON SCHEMA groups FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA groups FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA groups FROM PUBLIC;
-- Bootstrap idempotency is global only within the dedicated HTTP bootstrap
-- namespace. Keeping its claim separate from identity.command_receipts
-- preserves the established per-identity append contract for all other
-- identity-log commands while preserving the per-identity receipt contract.
--
-- The deferred FK means a claim, its initial log head, command receipt, and
-- outbox row commit or roll back together. A response loss can therefore
-- replay one durable result, while a different identity or body using the
-- same bootstrap key is rejected before it can create another identity.
CREATE TABLE identity.bootstrap_idempotency_claims (
    idempotency_key_hash bytea PRIMARY KEY,
    identity_id text NOT NULL,
    request_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT identity_bootstrap_idempotency_claims_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_bootstrap_idempotency_claims_key_hash_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT identity_bootstrap_idempotency_claims_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT identity_bootstrap_idempotency_claims_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TRIGGER identity_bootstrap_idempotency_claims_immutable
BEFORE UPDATE OR DELETE ON identity.bootstrap_idempotency_claims
FOR EACH ROW
EXECUTE FUNCTION identity.reject_immutable_mutation();

ALTER TABLE identity.bootstrap_idempotency_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.bootstrap_idempotency_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.bootstrap_idempotency_claims
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

-- Grant only the immutable claim capabilities when the dedicated runtime role
-- exists; role bootstrap and schema installation are deliberately separate.
DO $grant$
BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON identity.bootstrap_idempotency_claims
            TO dtx_identity_runtime;
    END IF;
END
$grant$;
