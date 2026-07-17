DO $revoke$
BEGIN
    IF to_regrole('dtx_group_runtime') IS NOT NULL THEN
        REVOKE DELETE ON groups.members FROM dtx_group_runtime;
    END IF;
END
$revoke$;

DROP TRIGGER groups_members_remove_only ON groups.members;
DROP FUNCTION groups.enforce_member_removal();

CREATE TRIGGER groups_members_append_only
BEFORE UPDATE OR DELETE ON groups.members
FOR EACH ROW
EXECUTE FUNCTION groups.reject_immutable_mutation();

ALTER TABLE groups.mls_commit_intents
    DROP CONSTRAINT groups_mls_commit_intents_versioned_bindings_valid,
    DROP CONSTRAINT groups_mls_commit_intents_protocol_version_valid,
    DROP CONSTRAINT groups_mls_commit_intents_authorization_shape_valid,
    DROP CONSTRAINT groups_mls_commit_intents_authorization_kind_valid;

ALTER TABLE groups.mls_commit_intents
    ADD CONSTRAINT groups_mls_commit_intents_authorization_kind_valid
    CHECK (authorization_kind IN ('owner_bootstrap', 'approved_identity_join',
                                  'existing_member_device_add')),
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
               AND octet_length(controller_consent_digest) = 32)),
    ADD CONSTRAINT groups_mls_commit_intents_protocol_version_valid
    CHECK (protocol_version IN (2, 3)),
    ADD CONSTRAINT groups_mls_commit_intents_v3_admission_digests_valid
    CHECK ((protocol_version = 2
            AND join_request_digest IS NULL
            AND approval_request_digest IS NULL)
           OR (protocol_version = 3
               AND authorization_kind = 'approved_identity_join'
               AND octet_length(join_request_digest) = 32
               AND octet_length(approval_request_digest) = 32));

ALTER TABLE groups.mls_commit_intents
    DROP COLUMN result_policy_revision,
    DROP COLUMN expected_policy_revision;

ALTER TABLE groups.mls_device_members
    DROP CONSTRAINT groups_mls_device_members_removed_epoch_valid,
    DROP COLUMN removed_epoch;
