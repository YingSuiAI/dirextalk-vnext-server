-- V40: candidate-authorized, opaque history recovery and MLS device recovery.
-- Existing protocol rows remain valid and every cross-runtime read is exposed
-- through a narrow SECURITY DEFINER predicate rather than table grants.

ALTER TABLE identity.device_enrollment_challenges
    ADD COLUMN protocol_version smallint NOT NULL DEFAULT 1,
    ADD COLUMN recovery_request_bytes bytea,
    ADD COLUMN recovery_request_digest bytea,
    ADD COLUMN observed_head_sequence bigint,
    ADD COLUMN observed_head_hash bytea,
    ADD COLUMN recovery_mode text,
    ADD COLUMN request_issued_at_ms bigint,
    ADD COLUMN recipient_encryption_key bytea,
    ADD COLUMN candidate_request_signature bytea,
    ADD CONSTRAINT identity_device_enrollment_history_request_valid CHECK (
        (protocol_version = 1
         AND recovery_request_bytes IS NULL AND recovery_request_digest IS NULL
         AND observed_head_sequence IS NULL AND observed_head_hash IS NULL
         AND recovery_mode IS NULL AND request_issued_at_ms IS NULL
         AND recipient_encryption_key IS NULL AND candidate_request_signature IS NULL)
        OR
        (protocol_version = 2
         AND octet_length(recovery_request_bytes) BETWEEN 1 AND 16384
         AND octet_length(recovery_request_digest) = 32
         AND observed_head_sequence BETWEEN 1 AND 9007199254740991
         AND octet_length(observed_head_hash) = 32
         AND recovery_mode = 'all_current_memberships'
         AND request_issued_at_ms BETWEEN -62135596800000 AND 253402300799999
         AND octet_length(recipient_encryption_key) = 32
         AND octet_length(candidate_request_signature) = 64)
    );

CREATE FUNCTION identity.enforce_history_recovery_request_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.protocol_version IS DISTINCT FROM NEW.protocol_version
       OR OLD.recovery_request_bytes IS DISTINCT FROM NEW.recovery_request_bytes
       OR OLD.recovery_request_digest IS DISTINCT FROM NEW.recovery_request_digest
       OR OLD.observed_head_sequence IS DISTINCT FROM NEW.observed_head_sequence
       OR OLD.observed_head_hash IS DISTINCT FROM NEW.observed_head_hash
       OR OLD.recovery_mode IS DISTINCT FROM NEW.recovery_mode
       OR OLD.request_issued_at_ms IS DISTINCT FROM NEW.request_issued_at_ms
       OR OLD.recipient_encryption_key IS DISTINCT FROM NEW.recipient_encryption_key
       OR OLD.candidate_request_signature IS DISTINCT FROM NEW.candidate_request_signature THEN
        RAISE EXCEPTION 'history recovery request is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER identity_history_recovery_request_immutable
BEFORE UPDATE ON identity.device_enrollment_challenges
FOR EACH ROW EXECUTE FUNCTION identity.enforce_history_recovery_request_immutable();

ALTER TABLE identity.key_packages
    ADD COLUMN purpose text NOT NULL DEFAULT 'general',
    ADD COLUMN recovery_request_digest bytea,
    ADD COLUMN recovery_scope_digest bytea,
    ADD CONSTRAINT identity_key_packages_scope_valid CHECK (
        (purpose='general' AND recovery_request_digest IS NULL AND recovery_scope_digest IS NULL)
        OR (purpose='history_recovery' AND octet_length(recovery_request_digest)=32
            AND octet_length(recovery_scope_digest)=32)
    );
ALTER TABLE identity.key_package_claims
    ADD COLUMN purpose text NOT NULL DEFAULT 'general',
    ADD COLUMN recovery_request_digest bytea,
    ADD COLUMN recovery_scope_digest bytea,
    ADD CONSTRAINT identity_key_package_claims_scope_valid CHECK (
        (purpose='general' AND recovery_request_digest IS NULL AND recovery_scope_digest IS NULL)
        OR (purpose='history_recovery' AND octet_length(recovery_request_digest)=32
            AND octet_length(recovery_scope_digest)=32)
    );

CREATE FUNCTION identity.enforce_key_package_scope_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.purpose IS DISTINCT FROM NEW.purpose
       OR OLD.recovery_request_digest IS DISTINCT FROM NEW.recovery_request_digest
       OR OLD.recovery_scope_digest IS DISTINCT FROM NEW.recovery_scope_digest THEN
        RAISE EXCEPTION 'key package recovery scope is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER identity_key_package_scope_immutable
BEFORE UPDATE ON identity.key_packages
FOR EACH ROW EXECUTE FUNCTION identity.enforce_key_package_scope_immutable();

CREATE TABLE messaging.history_recovery_offers (
    identity_id text NOT NULL,
    request_id uuid NOT NULL CHECK (messaging.is_uuid_v7(request_id)),
    recovery_request_digest bytea NOT NULL CHECK (octet_length(recovery_request_digest)=32),
    approved_head_hash bytea NOT NULL CHECK (octet_length(approved_head_hash)=32),
    candidate_device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(candidate_device_id)),
    provider_device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(provider_device_id)),
    authority_kind text NOT NULL CHECK (authority_kind IN ('active_device','root','recovery')),
    authority_id text NOT NULL CHECK (octet_length(authority_id) BETWEEN 8 AND 128),
    mailbox_id uuid NOT NULL,
    envelope_id uuid NOT NULL CHECK (messaging.is_uuid_v7(envelope_id)),
    provider_highwater bigint NOT NULL CHECK (provider_highwater BETWEEN 0 AND 9007199254740990),
    earliest_sequence bigint NOT NULL CHECK (earliest_sequence=provider_highwater+1),
    recipient_package_digest bytea NOT NULL CHECK (octet_length(recipient_package_digest)=32),
    attachment_digest bytea NOT NULL CHECK (octet_length(attachment_digest)=32),
    offer_digest bytea NOT NULL CHECK (octet_length(offer_digest)=32),
    exact_grant bytea NOT NULL CHECK (octet_length(exact_grant) BETWEEN 1 AND 1048576),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    idempotency_key_hash bytea NOT NULL CHECK (octet_length(idempotency_key_hash)=32),
    provider_signature bytea NOT NULL CHECK (octet_length(provider_signature)=64),
    authority_signature bytea NOT NULL CHECK (octet_length(authority_signature)=64),
    granted_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL CHECK (expires_at_ms>granted_at_ms),
    receipt_bytes bytea NOT NULL CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    receipt_hash bytea NOT NULL CHECK (octet_length(receipt_hash)=32),
    PRIMARY KEY(identity_id,request_id),
    UNIQUE(identity_id,provider_device_id,idempotency_key_hash),
    UNIQUE(mailbox_id,envelope_id),
    FOREIGN KEY(mailbox_id,envelope_id) REFERENCES messaging.mailbox_envelopes(mailbox_id,envelope_id) ON DELETE CASCADE
);
ALTER TABLE messaging.history_recovery_offers ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.history_recovery_offers FORCE ROW LEVEL SECURITY;
CREATE POLICY messaging_runtime_only ON messaging.history_recovery_offers
    USING (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized())
    WITH CHECK (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized());

ALTER TABLE groups.mls_commit_intents
    ADD COLUMN history_recovery_request_id uuid,
    ADD COLUMN recovery_request_digest bytea,
    ADD COLUMN recovery_scope_digest bytea,
    ADD COLUMN identity_revoke_head_digest bytea;
ALTER TABLE groups.mls_commit_intents
    DROP CONSTRAINT groups_mls_commit_intents_authorization_kind_valid,
    DROP CONSTRAINT groups_mls_commit_intents_authorization_shape_valid,
    DROP CONSTRAINT groups_mls_commit_intents_protocol_version_valid,
    DROP CONSTRAINT groups_mls_commit_intents_versioned_bindings_valid;
ALTER TABLE groups.mls_commit_intents
    ADD CONSTRAINT groups_mls_commit_intents_authorization_kind_valid CHECK (
        authorization_kind IN ('owner_bootstrap','approved_identity_join',
          'existing_member_device_add','member_removal','existing_member_device_remove')),
    ADD CONSTRAINT groups_mls_commit_intents_authorization_shape_valid CHECK (
        (authorization_kind='owner_bootstrap' AND membership_command_id IS NULL AND authorization_digest IS NULL AND controller_device_id IS NULL AND controller_consent_digest IS NULL)
        OR (authorization_kind='approved_identity_join' AND membership_command_id IS NOT NULL AND octet_length(authorization_digest)=32 AND controller_device_id IS NULL AND controller_consent_digest IS NULL)
        OR (authorization_kind='existing_member_device_add' AND membership_command_id IS NULL AND authorization_digest IS NULL AND controller_device_id IS NOT NULL AND octet_length(controller_consent_digest)=32)
        OR (authorization_kind IN ('member_removal','existing_member_device_remove') AND membership_command_id IS NULL AND authorization_digest IS NULL AND controller_device_id IS NULL AND controller_consent_digest IS NULL)),
    ADD CONSTRAINT groups_mls_commit_intents_protocol_version_valid CHECK (protocol_version IN (2,3,4,5)),
    ADD CONSTRAINT groups_mls_commit_intents_versioned_bindings_valid CHECK (
        (protocol_version=2 AND join_request_digest IS NULL AND approval_request_digest IS NULL AND expected_policy_revision IS NULL AND result_policy_revision IS NULL AND history_recovery_request_id IS NULL AND recovery_request_digest IS NULL AND recovery_scope_digest IS NULL AND identity_revoke_head_digest IS NULL)
        OR (protocol_version=3 AND authorization_kind='approved_identity_join' AND octet_length(join_request_digest)=32 AND octet_length(approval_request_digest)=32 AND expected_policy_revision IS NULL AND result_policy_revision IS NULL AND history_recovery_request_id IS NULL AND recovery_request_digest IS NULL AND recovery_scope_digest IS NULL AND identity_revoke_head_digest IS NULL)
        OR (protocol_version=4 AND authorization_kind='member_removal' AND join_request_digest IS NULL AND approval_request_digest IS NULL AND expected_policy_revision BETWEEN 1 AND 9007199254740990 AND result_policy_revision=expected_policy_revision+1 AND history_recovery_request_id IS NULL AND recovery_request_digest IS NULL AND recovery_scope_digest IS NULL AND identity_revoke_head_digest IS NULL)
        OR (protocol_version=5 AND authorization_kind='existing_member_device_add' AND history_recovery_request_id IS NOT NULL AND octet_length(recovery_request_digest)=32 AND octet_length(recovery_scope_digest)=32 AND identity_revoke_head_digest IS NULL AND expected_policy_revision IS NULL AND result_policy_revision IS NULL)
        OR (protocol_version=5 AND authorization_kind='existing_member_device_remove' AND history_recovery_request_id IS NULL AND recovery_request_digest IS NULL AND recovery_scope_digest IS NULL AND octet_length(identity_revoke_head_digest)=32 AND expected_policy_revision IS NULL AND result_policy_revision IS NULL)
    );

CREATE FUNCTION identity.history_recovery_request_authorized(
    requested_identity_id text, requested_request_id uuid,
    requested_request_digest bytea, requested_device_id uuid,
    at_ms bigint
) RETURNS TABLE(
    approved_head_hash bytea,
    recipient_encryption_key bytea,
    request_expires_at_ms bigint
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
    SELECT challenge.approved_head_hash,challenge.recipient_encryption_key,
           challenge.expires_at_ms
      FROM identity.device_enrollment_challenges AS challenge
      JOIN identity.log_heads AS head
        ON head.identity_id=challenge.identity_id
       AND head.state='active'
       AND head.head_hash=challenge.approved_head_hash
     WHERE (COALESCE(pg_has_role(session_user,to_regrole('dtx_identity_runtime'),'MEMBER'),false)
            OR COALESCE(pg_has_role(session_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),false)
            OR COALESCE(pg_has_role(session_user,to_regrole('dtx_group_runtime'),'MEMBER'),false))
       AND challenge.identity_id=requested_identity_id
       AND challenge.challenge_id=requested_request_id
       AND challenge.protocol_version=2 AND challenge.state='approved'
       AND challenge.recovery_request_digest=requested_request_digest
       AND challenge.target_device_id=requested_device_id
       AND challenge.expires_at_ms>at_ms
$$;

CREATE FUNCTION identity.scoped_key_package_claim_authorized(
    requested_identity_id text, requested_device_id uuid,
    requested_package_digest bytea, requested_request_digest bytea,
    requested_scope_digest bytea, requested_controller_device_id uuid
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
    SELECT (COALESCE(pg_has_role(session_user,to_regrole('dtx_group_runtime'),'MEMBER'),false)
            OR COALESCE(pg_has_role(session_user,to_regrole('dtx_identity_runtime'),'MEMBER'),false))
       AND EXISTS(
        SELECT 1 FROM identity.key_packages AS package
        JOIN identity.key_package_claim_receipts AS receipt USING(package_id)
        JOIN identity.key_package_claims AS claim
          ON claim.claimant_identity_id=receipt.claimant_identity_id
         AND claim.claimant_device_id=receipt.claimant_device_id
         AND claim.idempotency_key_hash=receipt.idempotency_key_hash
       WHERE package.owner_identity_id=requested_identity_id
         AND package.owner_device_id=requested_device_id
         AND package.package_digest=requested_package_digest
         AND package.purpose='history_recovery'
         AND package.recovery_request_digest=requested_request_digest
         AND package.recovery_scope_digest=requested_scope_digest
         AND claim.purpose='history_recovery'
         AND claim.recovery_request_digest=requested_request_digest
         AND claim.recovery_scope_digest=requested_scope_digest
         AND claim.claimant_identity_id=requested_identity_id
	       AND claim.claimant_device_id=requested_controller_device_id)
$$;

-- Migration 045 added the realtime reader by replacing these policies with a
-- flat OR expression.  That accidentally removed migration 019's narrow group
-- reader branch: PostgreSQL tried to invoke the identity-writer helper while a
-- group transaction revalidated its controller session.  Restore only the
-- SELECT branch.  WITH CHECK remains identity-writer/owner-only, and the group
-- runtime still proves its dedicated helper grant without receiving EXECUTE on
-- any broader identity authorization helper.
ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_group_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_realtime_sync_runtime'),'MEMBER'),
                    false
                )
              OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname='identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname='identity'
        )
    );
ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_group_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_realtime_sync_runtime'),'MEMBER'),
                    false
                )
              OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname='identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname='identity'
        )
    );
ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_group_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_realtime_sync_runtime'),'MEMBER'),
                    false
                )
              OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname='identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname='identity'
        )
    );

REVOKE ALL ON messaging.history_recovery_offers FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.enforce_history_recovery_request_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.enforce_key_package_scope_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.history_recovery_request_authorized(text,uuid,bytea,uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.scoped_key_package_claim_authorized(text,uuid,bytea,bytea,bytea,uuid) FROM PUBLIC;
DO $grants$ BEGIN
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        GRANT SELECT,INSERT ON messaging.history_recovery_offers TO dtx_mailbox_runtime;
        GRANT EXECUTE ON FUNCTION identity.history_recovery_request_authorized(text,uuid,bytea,uuid,bigint) TO dtx_mailbox_runtime;
    END IF;
    IF to_regrole('dtx_group_runtime') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION identity.history_recovery_request_authorized(text,uuid,bytea,uuid,bigint) TO dtx_group_runtime;
        GRANT EXECUTE ON FUNCTION identity.scoped_key_package_claim_authorized(text,uuid,bytea,bytea,bytea,uuid) TO dtx_group_runtime;
    END IF;
END $grants$;
