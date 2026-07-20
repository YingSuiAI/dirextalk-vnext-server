DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM groups.mls_commit_intents WHERE protocol_version=5)
       OR EXISTS(SELECT 1 FROM messaging.history_recovery_offers)
       OR EXISTS(SELECT 1 FROM identity.key_packages WHERE purpose='history_recovery')
       OR EXISTS(SELECT 1 FROM identity.device_enrollment_challenges WHERE protocol_version=2) THEN
        RAISE EXCEPTION 'cannot downgrade history recovery V1 while V40 facts exist'
            USING ERRCODE='55000';
    END IF;
END $$;

-- Restore the V39 policy installed by migration 045.  The populated-data
-- refusal above remains the first statement so a rejected downgrade performs
-- no policy or schema mutation.
ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_realtime_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_realtime_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_realtime_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

REVOKE ALL ON FUNCTION identity.scoped_key_package_claim_authorized(text,uuid,bytea,bytea,bytea,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.history_recovery_request_authorized(text,uuid,bytea,uuid,bigint) FROM PUBLIC;
DROP FUNCTION identity.scoped_key_package_claim_authorized(text,uuid,bytea,bytea,bytea,uuid);
DROP FUNCTION identity.history_recovery_request_authorized(text,uuid,bytea,uuid,bigint);
DROP TABLE messaging.history_recovery_offers;

ALTER TABLE groups.mls_commit_intents
    DROP CONSTRAINT groups_mls_commit_intents_versioned_bindings_valid,
    DROP CONSTRAINT groups_mls_commit_intents_protocol_version_valid,
    DROP CONSTRAINT groups_mls_commit_intents_authorization_shape_valid,
    DROP CONSTRAINT groups_mls_commit_intents_authorization_kind_valid;
ALTER TABLE groups.mls_commit_intents
    ADD CONSTRAINT groups_mls_commit_intents_authorization_kind_valid CHECK (authorization_kind IN ('owner_bootstrap','approved_identity_join','existing_member_device_add','member_removal')),
    ADD CONSTRAINT groups_mls_commit_intents_authorization_shape_valid CHECK (
        (authorization_kind='owner_bootstrap' AND membership_command_id IS NULL AND authorization_digest IS NULL AND controller_device_id IS NULL AND controller_consent_digest IS NULL)
        OR (authorization_kind='approved_identity_join' AND membership_command_id IS NOT NULL AND octet_length(authorization_digest)=32 AND controller_device_id IS NULL AND controller_consent_digest IS NULL)
        OR (authorization_kind='existing_member_device_add' AND membership_command_id IS NULL AND authorization_digest IS NULL AND controller_device_id IS NOT NULL AND octet_length(controller_consent_digest)=32)
        OR (authorization_kind='member_removal' AND membership_command_id IS NULL AND authorization_digest IS NULL AND controller_device_id IS NULL AND controller_consent_digest IS NULL)),
    ADD CONSTRAINT groups_mls_commit_intents_protocol_version_valid CHECK (protocol_version IN (2,3,4)),
    ADD CONSTRAINT groups_mls_commit_intents_versioned_bindings_valid CHECK (
        (protocol_version=2 AND join_request_digest IS NULL AND approval_request_digest IS NULL AND expected_policy_revision IS NULL AND result_policy_revision IS NULL)
        OR (protocol_version=3 AND authorization_kind='approved_identity_join' AND octet_length(join_request_digest)=32 AND octet_length(approval_request_digest)=32 AND expected_policy_revision IS NULL AND result_policy_revision IS NULL)
        OR (protocol_version=4 AND authorization_kind='member_removal' AND join_request_digest IS NULL AND approval_request_digest IS NULL AND expected_policy_revision BETWEEN 1 AND 9007199254740990 AND result_policy_revision=expected_policy_revision+1));
ALTER TABLE groups.mls_commit_intents DROP COLUMN identity_revoke_head_digest, DROP COLUMN recovery_scope_digest, DROP COLUMN recovery_request_digest, DROP COLUMN history_recovery_request_id;

DROP TRIGGER identity_key_package_scope_immutable ON identity.key_packages;
DROP FUNCTION identity.enforce_key_package_scope_immutable();
ALTER TABLE identity.key_package_claims DROP CONSTRAINT identity_key_package_claims_scope_valid, DROP COLUMN recovery_scope_digest, DROP COLUMN recovery_request_digest, DROP COLUMN purpose;
ALTER TABLE identity.key_packages DROP CONSTRAINT identity_key_packages_scope_valid, DROP COLUMN recovery_scope_digest, DROP COLUMN recovery_request_digest, DROP COLUMN purpose;

DROP TRIGGER identity_history_recovery_request_immutable ON identity.device_enrollment_challenges;
DROP FUNCTION identity.enforce_history_recovery_request_immutable();
ALTER TABLE identity.device_enrollment_challenges DROP CONSTRAINT identity_device_enrollment_history_request_valid,
    DROP COLUMN candidate_request_signature, DROP COLUMN recipient_encryption_key,
    DROP COLUMN request_issued_at_ms, DROP COLUMN recovery_mode,
    DROP COLUMN observed_head_hash, DROP COLUMN observed_head_sequence,
    DROP COLUMN recovery_request_digest, DROP COLUMN recovery_request_bytes,
    DROP COLUMN protocol_version;
