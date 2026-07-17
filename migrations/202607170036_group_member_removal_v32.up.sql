-- V32 / MLS V4 adds an Owner-only, response-loss-safe member-removal effect.
-- The accepted opaque MLS Commit, product policy revision, member deletion,
-- removed-leaf tombstone, group head, outbox, and signed receipt are committed
-- by one Group runtime transaction.
ALTER TABLE groups.mls_commit_intents
    ADD COLUMN expected_policy_revision bigint,
    ADD COLUMN result_policy_revision bigint;

ALTER TABLE groups.mls_device_members
    ADD COLUMN removed_epoch bigint;

-- Preserve any pre-V32 defensive tombstones without granting them access to a
-- later commit. New V4 removals always record the exact removal epoch.
UPDATE groups.mls_device_members
   SET removed_epoch = admitted_epoch
 WHERE state = 'removed' AND removed_epoch IS NULL;

ALTER TABLE groups.mls_device_members
    ADD CONSTRAINT groups_mls_device_members_removed_epoch_valid
    CHECK (((state = 'removed') = (removed_epoch IS NOT NULL))
           AND (removed_epoch IS NULL
                OR removed_epoch BETWEEN admitted_epoch AND 9007199254740991));

ALTER TABLE groups.mls_commit_intents
    DROP CONSTRAINT groups_mls_commit_intents_v3_admission_digests_valid,
    DROP CONSTRAINT groups_mls_commit_intents_protocol_version_valid;

-- The original V21 checks were unnamed. Locate only the two authorization
-- checks by their reviewed defining fields, then replace them with stable names.
DO $migration$
DECLARE
    constraint_name name;
BEGIN
    FOR constraint_name IN
        SELECT conname
          FROM pg_constraint
         WHERE conrelid = 'groups.mls_commit_intents'::regclass
           AND contype = 'c'
           AND position('authorization_kind' IN pg_get_constraintdef(oid)) > 0
    LOOP
        EXECUTE format(
            'ALTER TABLE groups.mls_commit_intents DROP CONSTRAINT %I',
            constraint_name
        );
    END LOOP;
END
$migration$;

ALTER TABLE groups.mls_commit_intents
    ADD CONSTRAINT groups_mls_commit_intents_authorization_kind_valid
    CHECK (authorization_kind IN ('owner_bootstrap', 'approved_identity_join',
                                  'existing_member_device_add', 'member_removal')),
    ADD CONSTRAINT groups_mls_commit_intents_authorization_shape_valid
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
               AND octet_length(controller_consent_digest) = 32)
           OR (authorization_kind = 'member_removal'
               AND membership_command_id IS NULL
               AND authorization_digest IS NULL
               AND controller_device_id IS NULL
               AND controller_consent_digest IS NULL)),
    ADD CONSTRAINT groups_mls_commit_intents_protocol_version_valid
    CHECK (protocol_version IN (2, 3, 4)),
    ADD CONSTRAINT groups_mls_commit_intents_versioned_bindings_valid
    CHECK ((protocol_version = 2
            AND join_request_digest IS NULL
            AND approval_request_digest IS NULL
            AND expected_policy_revision IS NULL
            AND result_policy_revision IS NULL)
           OR (protocol_version = 3
               AND authorization_kind = 'approved_identity_join'
               AND octet_length(join_request_digest) = 32
               AND octet_length(approval_request_digest) = 32
               AND expected_policy_revision IS NULL
               AND result_policy_revision IS NULL)
           OR (protocol_version = 4
               AND authorization_kind = 'member_removal'
               AND join_request_digest IS NULL
               AND approval_request_digest IS NULL
               AND expected_policy_revision BETWEEN 1 AND 9007199254740990
               AND result_policy_revision = expected_policy_revision + 1));

-- `groups.members` was append-only before removal existed. Keep that guard for
-- every mutation except the exact member DELETE covered by a V4 intent, the
-- newly persisted product-policy head, and the still-current parent MLS head.
-- Because all three facts are in the same transaction, a crash cannot leave a
-- product deletion without the corresponding durable sequencer intent.
DROP TRIGGER groups_members_append_only ON groups.members;

CREATE FUNCTION groups.enforce_member_removal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'DELETE' OR NOT EXISTS (
        SELECT 1
          FROM groups.mls_commit_intents AS intent
          JOIN groups.policy_heads AS policy
            ON policy.tenant_id = intent.tenant_id
           AND policy.scope_kind = intent.scope_kind
           AND policy.scope_id = intent.scope_id
          JOIN groups.mls_heads AS mls
            ON mls.tenant_id = intent.tenant_id
           AND mls.scope_kind = intent.scope_kind
           AND mls.scope_id = intent.scope_id
         WHERE intent.tenant_id = OLD.tenant_id
           AND intent.scope_kind = OLD.scope_kind
           AND intent.scope_id = OLD.scope_id
           AND intent.candidate_identity_id = OLD.identity_id
           AND intent.protocol_version = 4
           AND intent.authorization_kind = 'member_removal'
           AND policy.policy_revision = intent.result_policy_revision
           AND mls.epoch = intent.parent_epoch
           AND mls.head_digest = intent.parent_head_digest
    ) THEN
        RAISE EXCEPTION 'group membership immutable relation cannot be rewritten'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER groups_members_remove_only
BEFORE UPDATE OR DELETE ON groups.members
FOR EACH ROW
EXECUTE FUNCTION groups.enforce_member_removal();

REVOKE ALL ON FUNCTION groups.enforce_member_removal() FROM PUBLIC;

DO $grant$
BEGIN
    IF to_regrole('dtx_group_runtime') IS NOT NULL THEN
        GRANT DELETE ON groups.members TO dtx_group_runtime;
    END IF;
END
$grant$;
