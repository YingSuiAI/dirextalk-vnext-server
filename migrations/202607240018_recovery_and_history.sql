ALTER TABLE realtime.encrypted_account_read_cursors
    ADD COLUMN identity_head bytea,
    ADD COLUMN ciphertext_digest bytea,
    ADD CONSTRAINT account_read_cursor_identity_head_size
        CHECK (identity_head IS NULL OR octet_length(identity_head)=32),
    ADD CONSTRAINT account_read_cursor_ciphertext_digest_size
        CHECK (ciphertext_digest IS NULL OR octet_length(ciphertext_digest)=32),
    ADD CONSTRAINT account_read_cursor_metadata_pair
        CHECK ((identity_head IS NULL) = (ciphertext_digest IS NULL));

UPDATE realtime.encrypted_account_read_cursors AS cursor_state
   SET identity_head=identity_head.head_hash,
       ciphertext_digest=sha256(
           convert_to('dirextalk.account-read-cursor-ciphertext.v1','UTF8')
           || decode('00','hex') || cursor_state.encrypted_cursor
       )
  FROM identity.log_heads AS identity_head
 WHERE identity_head.identity_id=cursor_state.identity_id;
ALTER TABLE realtime.encrypted_account_read_cursors
    ALTER COLUMN identity_head SET NOT NULL,
    ALTER COLUMN ciphertext_digest SET NOT NULL;

CREATE TABLE realtime.account_read_cursor_claims (
    identity_id text NOT NULL,
    device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(device_id)),
    idempotency_key_hash bytea NOT NULL CHECK (octet_length(idempotency_key_hash)=32),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    conversation_digest bytea NOT NULL CHECK (octet_length(conversation_digest)=32),
    committed_revision bigint NOT NULL CHECK (committed_revision BETWEEN 1 AND 9007199254740991),
    receipt_bytes bytea NOT NULL CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    receipt_hash bytea NOT NULL CHECK (octet_length(receipt_hash)=32),
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, device_id, idempotency_key_hash),
    FOREIGN KEY (identity_id) REFERENCES realtime.identity_heads(identity_id) ON DELETE RESTRICT
);

ALTER TABLE realtime.outbox
    ADD COLUMN claim_id uuid,
    ADD COLUMN claimed_by uuid,
    ADD COLUMN claim_expires_at_ms bigint,
    ADD CONSTRAINT realtime_outbox_claim_id_v7
        CHECK (claim_id IS NULL OR messaging.is_uuid_v7(claim_id)),
    ADD CONSTRAINT realtime_outbox_claimed_by_v7
        CHECK (claimed_by IS NULL OR messaging.is_uuid_v7(claimed_by)),
    ADD CONSTRAINT realtime_outbox_claim_tuple
        CHECK ((claim_id IS NULL) = (claimed_by IS NULL)
           AND (claim_id IS NULL) = (claim_expires_at_ms IS NULL));

CREATE INDEX realtime_outbox_pending_claim_idx
    ON realtime.outbox (claim_expires_at_ms, identity_id, cursor)
    WHERE published_at_ms IS NULL;

CREATE FUNCTION realtime.claim_outbox(
    requested_claim_id uuid,
    worker_id uuid,
    now_ms bigint,
    claim_ttl_ms bigint,
    maximum_rows integer
)
RETURNS TABLE(identity_id text, cursor bigint, event_kind text, subject_digest bytea)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, realtime
AS $$
DECLARE database_now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    IF NOT realtime.runtime_authorized()
       OR NOT messaging.is_uuid_v7(requested_claim_id)
       OR NOT messaging.is_uuid_v7(worker_id)
       OR now_ms NOT BETWEEN database_now_ms-60000 AND database_now_ms+60000
       OR claim_ttl_ms NOT BETWEEN 1000 AND 45000
       OR maximum_rows NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'realtime outbox claim rejected' USING ERRCODE='42501';
    END IF;
    RETURN QUERY
    WITH candidates AS (
        SELECT pending.identity_id, pending.cursor
          FROM realtime.outbox AS pending
          JOIN realtime.journal AS event
            ON event.identity_id=pending.identity_id AND event.cursor=pending.cursor
         WHERE pending.published_at_ms IS NULL
           AND (pending.claim_expires_at_ms IS NULL OR pending.claim_expires_at_ms <= now_ms)
           AND event.expires_at_ms > now_ms
         ORDER BY pending.identity_id, pending.cursor
         LIMIT maximum_rows
         FOR UPDATE OF pending SKIP LOCKED
    ), claimed AS (
        UPDATE realtime.outbox AS pending
           SET claim_id=requested_claim_id,
               claimed_by=worker_id,
               claim_expires_at_ms=now_ms+claim_ttl_ms,
               attempts=LEAST(pending.attempts+1,1000)
          FROM candidates
         WHERE pending.identity_id=candidates.identity_id
           AND pending.cursor=candidates.cursor
        RETURNING pending.identity_id, pending.cursor
    )
    SELECT claimed.identity_id, claimed.cursor, event.event_kind, event.subject_digest
      FROM claimed
      JOIN realtime.journal AS event
        ON event.identity_id=claimed.identity_id AND event.cursor=claimed.cursor
     ORDER BY claimed.identity_id, claimed.cursor;
END
$$;

CREATE FUNCTION realtime.mark_outbox_published(
    requested_claim_id uuid,
    worker_id uuid,
    now_ms bigint
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, realtime
AS $$
DECLARE changed integer;
DECLARE database_now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    IF NOT realtime.runtime_authorized()
       OR NOT messaging.is_uuid_v7(requested_claim_id)
       OR NOT messaging.is_uuid_v7(worker_id)
       OR now_ms NOT BETWEEN database_now_ms-60000 AND database_now_ms+60000 THEN
        RAISE EXCEPTION 'realtime outbox publish rejected' USING ERRCODE='42501';
    END IF;
    UPDATE realtime.outbox
       SET published_at_ms=COALESCE(published_at_ms, now_ms)
     WHERE claim_id=requested_claim_id AND claimed_by=worker_id;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed;
END
$$;

CREATE FUNCTION realtime.compact_expired(now_ms bigint, maximum_rows integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, realtime
AS $$
DECLARE changed integer;
DECLARE affected_identities text[];
DECLARE database_now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    IF NOT realtime.runtime_authorized()
       OR now_ms NOT BETWEEN database_now_ms-60000 AND database_now_ms+60000
       OR maximum_rows NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'realtime compaction rejected' USING ERRCODE='42501';
    END IF;
    WITH candidates AS (
        SELECT event.identity_id, event.cursor
          FROM realtime.journal AS event
         WHERE event.expires_at_ms <= now_ms
         ORDER BY event.identity_id, event.cursor
         LIMIT maximum_rows
         FOR UPDATE SKIP LOCKED
    ), removed_outbox AS (
        DELETE FROM realtime.outbox AS pending
         USING candidates
         WHERE pending.identity_id=candidates.identity_id
           AND pending.cursor=candidates.cursor
    ), removed_journal AS (
        DELETE FROM realtime.journal AS event
         USING candidates
         WHERE event.identity_id=candidates.identity_id
           AND event.cursor=candidates.cursor
        RETURNING event.identity_id
    )
    SELECT COALESCE(array_agg(DISTINCT identity_id),ARRAY[]::text[]), count(*)::integer
      INTO affected_identities, changed
      FROM removed_journal;
    UPDATE realtime.identity_heads AS head
       SET journal_floor=COALESCE(
           (SELECT min(event.cursor) FROM realtime.journal AS event
             WHERE event.identity_id=head.identity_id),
           LEAST(head.next_cursor+1,9007199254740991)
       )
     WHERE head.identity_id=ANY(affected_identities);
    RETURN changed;
END
$$;

REVOKE ALL ON realtime.account_read_cursor_claims FROM PUBLIC;
REVOKE ALL ON FUNCTION realtime.claim_outbox(uuid,uuid,bigint,bigint,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION realtime.mark_outbox_published(uuid,uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION realtime.compact_expired(bigint,integer) FROM PUBLIC;

DO $grants$
BEGIN
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON realtime.encrypted_account_read_cursors TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON realtime.account_read_cursor_claims TO dtx_mailbox_runtime;
    END IF;
    IF to_regrole('dtx_realtime_sync_runtime') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION realtime.claim_outbox(uuid,uuid,bigint,bigint,integer)
            TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION realtime.mark_outbox_published(uuid,uuid,bigint)
            TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION realtime.compact_expired(bigint,integer)
            TO dtx_realtime_sync_runtime;
    END IF;
END
$grants$;
ALTER TABLE realtime.journal
    DROP CONSTRAINT journal_event_kind_check,
    ADD CONSTRAINT journal_event_kind_check CHECK (event_kind IN (
        'mailbox_delivery', 'conversation_read', 'durable_invalidation',
        'identity_head_changed', 'device_revoked', 'key_authorization_changed'
    ));

CREATE FUNCTION realtime.append_identity_invalidation(
    requested_identity_id text,
    requested_event_kind text,
    requested_subject_digest bytea
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, realtime
AS $$
DECLARE database_now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
DECLARE next_value bigint;
BEGIN
    IF NOT identity.identity_runtime_authorized()
       OR requested_event_kind NOT IN (
           'identity_head_changed', 'device_revoked', 'key_authorization_changed'
       )
       OR octet_length(requested_subject_digest) <> 32 THEN
        RAISE EXCEPTION 'identity realtime invalidation rejected' USING ERRCODE='42501';
    END IF;
    INSERT INTO realtime.identity_heads(identity_id,next_cursor,journal_floor)
        VALUES(requested_identity_id,0,1)
        ON CONFLICT(identity_id) DO NOTHING;
    UPDATE realtime.identity_heads
       SET next_cursor=next_cursor+1
     WHERE identity_id=requested_identity_id
       AND next_cursor<9007199254740991
    RETURNING next_cursor INTO next_value;
    IF next_value IS NULL THEN
        RAISE EXCEPTION 'identity realtime cursor exhausted' USING ERRCODE='22003';
    END IF;
    INSERT INTO realtime.journal(
        identity_id,cursor,event_kind,subject_digest,created_at_ms,expires_at_ms
    ) VALUES(
        requested_identity_id,next_value,requested_event_kind,
        requested_subject_digest,database_now_ms,database_now_ms+604800000
    );
    INSERT INTO realtime.outbox(identity_id,cursor)
        VALUES(requested_identity_id,next_value);
    RETURN next_value;
END
$$;

CREATE OR REPLACE FUNCTION realtime.compact_expired(now_ms bigint, maximum_rows integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, realtime
AS $$
DECLARE changed integer;
DECLARE affected_identities text[];
DECLARE database_now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    IF NOT realtime.runtime_authorized()
       OR now_ms NOT BETWEEN database_now_ms-60000 AND database_now_ms+60000
       OR maximum_rows NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'realtime compaction rejected' USING ERRCODE='42501';
    END IF;
    WITH ordered AS (
        SELECT event.identity_id,event.cursor,event.expires_at_ms,head.journal_floor,
               row_number() OVER (
                   PARTITION BY event.identity_id ORDER BY event.cursor
               ) AS ordinal,
               min(event.cursor) FILTER (WHERE event.expires_at_ms>now_ms) OVER (
                   PARTITION BY event.identity_id
               ) AS first_live_cursor
          FROM realtime.journal AS event
          JOIN realtime.identity_heads AS head USING(identity_id)
         WHERE event.cursor>=head.journal_floor
    ), candidates AS (
        SELECT identity_id,cursor
          FROM ordered
         WHERE expires_at_ms<=now_ms
           AND cursor=journal_floor+ordinal-1
           AND (first_live_cursor IS NULL OR cursor<first_live_cursor)
         ORDER BY identity_id,cursor
         LIMIT maximum_rows
    ), removed_outbox AS (
        DELETE FROM realtime.outbox AS pending
         USING candidates
         WHERE pending.identity_id=candidates.identity_id
           AND pending.cursor=candidates.cursor
    ), removed_journal AS (
        DELETE FROM realtime.journal AS event
         USING candidates
         WHERE event.identity_id=candidates.identity_id
           AND event.cursor=candidates.cursor
        RETURNING event.identity_id
    )
    SELECT COALESCE(array_agg(DISTINCT identity_id),ARRAY[]::text[]), count(*)::integer
      INTO affected_identities, changed
      FROM removed_journal;
    UPDATE realtime.identity_heads AS head
       SET journal_floor=COALESCE(
           (SELECT min(event.cursor) FROM realtime.journal AS event
             WHERE event.identity_id=head.identity_id),
           LEAST(head.next_cursor+1,9007199254740991)
       )
     WHERE head.identity_id=ANY(affected_identities);
    RETURN changed;
END
$$;

REVOKE ALL ON FUNCTION realtime.append_identity_invalidation(text,text,bytea)
    FROM PUBLIC;

DO $grants$
BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA realtime TO dtx_identity_runtime;
        GRANT EXECUTE ON FUNCTION realtime.append_identity_invalidation(text,text,bytea)
            TO dtx_identity_runtime;
    END IF;
END
$grants$;
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

-- The final read policy keeps the narrow group reader branch separate from
-- identity writes. `WITH CHECK` remains identity-writer/owner-only, and the
-- group runtime proves its dedicated helper grant without receiving EXECUTE on
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
