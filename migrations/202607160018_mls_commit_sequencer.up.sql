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
