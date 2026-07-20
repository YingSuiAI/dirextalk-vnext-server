DO $revoke$
BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION realtime.append_identity_invalidation(text,text,bytea)
            FROM dtx_identity_runtime;
        REVOKE USAGE ON SCHEMA realtime FROM dtx_identity_runtime;
    END IF;
END
$revoke$;

DROP FUNCTION realtime.append_identity_invalidation(text,text,bytea);

UPDATE realtime.journal
   SET event_kind='durable_invalidation'
 WHERE event_kind IN (
    'identity_head_changed','device_revoked','key_authorization_changed'
 );
ALTER TABLE realtime.journal
    DROP CONSTRAINT journal_event_kind_check,
    ADD CONSTRAINT journal_event_kind_check CHECK (event_kind IN (
        'mailbox_delivery','conversation_read','durable_invalidation'
    ));

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
