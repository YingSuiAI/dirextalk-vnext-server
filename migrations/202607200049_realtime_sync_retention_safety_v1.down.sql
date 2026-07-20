-- V47 cannot represent an irreversibly tombstoned payload or a deleted
-- account-delivery prefix. Refuse before any DDL so the resumable floor and
-- current reader remain intact.
DO $preflight$
DECLARE compacted_heads bigint;
DECLARE tombstoned_payloads bigint;
BEGIN
    SELECT count(*) INTO compacted_heads
      FROM messaging.identity_delivery_heads WHERE compacted_through>0;
    SELECT count(*) INTO tombstoned_payloads
      FROM messaging.mailbox_envelopes WHERE opaque_ciphertext IS NULL;
    IF compacted_heads<>0 OR tombstoned_payloads<>0 THEN
        RAISE EXCEPTION 'cannot downgrade realtime retention safety after compaction'
            USING ERRCODE='55000',
                  DETAIL=format(
                      'compacted identity heads=%s tombstoned payloads=%s',
                      compacted_heads,tombstoned_payloads
                  ),
                  HINT='Keep schema version 49 or later and use the retained delivery floor.';
    END IF;
END
$preflight$;

CREATE OR REPLACE FUNCTION messaging.enforce_envelope_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.mailbox_id IS DISTINCT FROM NEW.mailbox_id
       OR OLD.envelope_id IS DISTINCT FROM NEW.envelope_id
       OR OLD.delivery_sequence IS DISTINCT FROM NEW.delivery_sequence
       OR OLD.opaque_ciphertext IS DISTINCT FROM NEW.opaque_ciphertext
       OR OLD.request_digest IS DISTINCT FROM NEW.request_digest
       OR OLD.receipt_bytes IS DISTINCT FROM NEW.receipt_bytes
       OR OLD.receipt_hash IS DISTINCT FROM NEW.receipt_hash
       OR OLD.expires_at_ms IS DISTINCT FROM NEW.expires_at_ms
       OR OLD.created_at_ms IS DISTINCT FROM NEW.created_at_ms
       OR OLD.state <> 'available'
       OR NEW.state NOT IN ('acked','expired') THEN
        RAISE EXCEPTION 'mailbox envelope transition is not authorized' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END
$$;

ALTER TABLE messaging.mailbox_envelopes
    DROP CONSTRAINT messaging_envelopes_ciphertext_bounded,
    ADD CONSTRAINT messaging_envelopes_ciphertext_bounded CHECK (
        octet_length(opaque_ciphertext) BETWEEN 1 AND 262144
    ),
    ALTER COLUMN opaque_ciphertext SET NOT NULL;
ALTER TABLE messaging.identity_delivery_heads
    DROP CONSTRAINT identity_delivery_compaction_not_ahead,
    DROP COLUMN compacted_through;

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
               row_number() OVER(PARTITION BY event.identity_id ORDER BY event.cursor) AS ordinal,
               min(event.cursor) FILTER(WHERE event.expires_at_ms>now_ms)
                   OVER(PARTITION BY event.identity_id) AS first_live_cursor
          FROM realtime.journal AS event JOIN realtime.identity_heads AS head USING(identity_id)
         WHERE event.cursor>=head.journal_floor
    ), candidates AS (
        SELECT identity_id,cursor FROM ordered
         WHERE expires_at_ms<=now_ms AND cursor=journal_floor+ordinal-1
           AND (first_live_cursor IS NULL OR cursor<first_live_cursor)
         ORDER BY identity_id,cursor LIMIT maximum_rows
    ), removed_outbox AS (
        DELETE FROM realtime.outbox AS pending USING candidates
         WHERE pending.identity_id=candidates.identity_id AND pending.cursor=candidates.cursor
    ), removed_journal AS (
        DELETE FROM realtime.journal AS event USING candidates
         WHERE event.identity_id=candidates.identity_id AND event.cursor=candidates.cursor
        RETURNING event.identity_id
    )
    SELECT COALESCE(array_agg(DISTINCT identity_id),ARRAY[]::text[]),count(*)::integer
      INTO affected_identities,changed FROM removed_journal;
    UPDATE realtime.identity_heads AS head SET journal_floor=COALESCE(
        (SELECT min(cursor) FROM realtime.journal WHERE identity_id=head.identity_id),
        LEAST(head.next_cursor+1,9007199254740991))
     WHERE head.identity_id=ANY(affected_identities);
    RETURN changed;
END
$$;

DROP FUNCTION messaging.compact_expired_identity_deliveries(bigint,integer);
