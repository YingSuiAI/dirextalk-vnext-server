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
