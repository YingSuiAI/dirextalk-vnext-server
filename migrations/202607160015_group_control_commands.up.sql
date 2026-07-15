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
