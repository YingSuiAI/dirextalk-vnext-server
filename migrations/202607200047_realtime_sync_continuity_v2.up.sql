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
