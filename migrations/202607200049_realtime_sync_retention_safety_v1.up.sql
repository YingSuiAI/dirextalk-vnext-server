ALTER TABLE messaging.identity_delivery_heads
    ADD COLUMN compacted_through bigint NOT NULL DEFAULT 0
        CHECK (compacted_through BETWEEN 0 AND 9007199254740991),
    ADD CONSTRAINT identity_delivery_compaction_not_ahead
        CHECK (compacted_through <= next_sequence);

ALTER TABLE messaging.mailbox_envelopes
    ALTER COLUMN opaque_ciphertext DROP NOT NULL,
    DROP CONSTRAINT messaging_envelopes_ciphertext_bounded,
    ADD CONSTRAINT messaging_envelopes_ciphertext_bounded CHECK (
        (state IN ('available','acked') AND octet_length(opaque_ciphertext) BETWEEN 1 AND 262144)
        OR (state='expired' AND opaque_ciphertext IS NULL)
    );

CREATE OR REPLACE FUNCTION messaging.enforce_envelope_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.mailbox_id IS DISTINCT FROM NEW.mailbox_id
       OR OLD.envelope_id IS DISTINCT FROM NEW.envelope_id
       OR OLD.delivery_sequence IS DISTINCT FROM NEW.delivery_sequence
       OR OLD.request_digest IS DISTINCT FROM NEW.request_digest
       OR OLD.receipt_bytes IS DISTINCT FROM NEW.receipt_bytes
       OR OLD.receipt_hash IS DISTINCT FROM NEW.receipt_hash
       OR OLD.expires_at_ms IS DISTINCT FROM NEW.expires_at_ms
       OR OLD.created_at_ms IS DISTINCT FROM NEW.created_at_ms
       OR NOT (
           (OLD.state='available' AND NEW.state='acked'
                AND OLD.opaque_ciphertext IS NOT DISTINCT FROM NEW.opaque_ciphertext)
           OR (OLD.state IN ('available','acked') AND NEW.state='expired'
                AND NEW.opaque_ciphertext IS NULL)
       ) THEN
        RAISE EXCEPTION 'mailbox envelope transition is not authorized'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION messaging.compact_expired_identity_deliveries(now_ms bigint, maximum_rows integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, messaging
AS $$
DECLARE database_now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
DECLARE selected_identity text;
DECLARE current_floor bigint;
DECLARE compact_to bigint;
DECLARE removed integer;
DECLARE changed integer := 0;
BEGIN
    IF NOT realtime.runtime_authorized()
       OR now_ms NOT BETWEEN database_now_ms-60000 AND database_now_ms+60000
       OR maximum_rows NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'identity delivery compaction rejected' USING ERRCODE='42501';
    END IF;
    WHILE changed < maximum_rows LOOP
        SELECT head.identity_id INTO selected_identity
          FROM messaging.identity_delivery_heads AS head
          JOIN messaging.identity_delivery_journal AS first_event
            ON first_event.identity_id=head.identity_id
           AND first_event.delivery_sequence=head.compacted_through+1
         WHERE first_event.expires_at_ms<=now_ms
         ORDER BY head.identity_id LIMIT 1;
        EXIT WHEN selected_identity IS NULL;

        PERFORM pg_advisory_xact_lock(hashtextextended(
            'mailbox-identity:' || selected_identity, 0));
        SELECT compacted_through INTO current_floor
          FROM messaging.identity_delivery_heads
         WHERE identity_id=selected_identity FOR UPDATE;
        SELECT max(delivery_sequence) INTO compact_to
          FROM (
            SELECT delivery_sequence
              FROM messaging.identity_delivery_journal
             WHERE identity_id=selected_identity
               AND delivery_sequence>current_floor
               AND expires_at_ms<=now_ms
               AND delivery_sequence < COALESCE((
                    SELECT min(delivery_sequence)
                      FROM messaging.identity_delivery_journal
                     WHERE identity_id=selected_identity
                       AND delivery_sequence>current_floor
                       AND expires_at_ms>now_ms
               ),9007199254740992)
             ORDER BY delivery_sequence
             LIMIT maximum_rows-changed
          ) AS expired_prefix;
        IF compact_to IS NULL THEN
            selected_identity := NULL;
            CONTINUE;
        END IF;

        WITH payload AS MATERIALIZED (
            SELECT envelope.mailbox_id,envelope.envelope_id,envelope.state,
                   octet_length(envelope.opaque_ciphertext)::bigint AS ciphertext_bytes
              FROM messaging.identity_delivery_journal AS journal
              JOIN messaging.mailbox_envelopes AS envelope
                ON envelope.mailbox_id=journal.mailbox_id
               AND envelope.envelope_id=journal.envelope_id
             WHERE journal.identity_id=selected_identity
               AND journal.delivery_sequence>current_floor
               AND journal.delivery_sequence<=compact_to
        ), tombstoned AS (
            UPDATE messaging.mailbox_envelopes AS envelope
               SET state='expired',opaque_ciphertext=NULL
              FROM payload
             WHERE envelope.mailbox_id=payload.mailbox_id
               AND envelope.envelope_id=payload.envelope_id
               AND envelope.state IN ('available','acked')
            RETURNING envelope.mailbox_id,envelope.envelope_id
        ), released AS (
            SELECT payload.mailbox_id,
                   count(*) FILTER (WHERE payload.state='available')::integer AS envelope_count,
                   COALESCE(sum(payload.ciphertext_bytes)
                       FILTER (WHERE payload.state='available'),0)::bigint AS envelope_bytes
              FROM payload JOIN tombstoned USING(mailbox_id,envelope_id)
             GROUP BY payload.mailbox_id
        )
        UPDATE messaging.mailboxes AS mailbox
           SET active_envelope_count=mailbox.active_envelope_count-released.envelope_count,
               active_envelope_bytes=mailbox.active_envelope_bytes-released.envelope_bytes
          FROM released WHERE mailbox.mailbox_id=released.mailbox_id;

        DELETE FROM messaging.identity_delivery_journal
         WHERE identity_id=selected_identity
           AND delivery_sequence>current_floor
           AND delivery_sequence<=compact_to;
        GET DIAGNOSTICS removed = ROW_COUNT;
        IF removed <> compact_to-current_floor THEN
            RAISE EXCEPTION 'identity delivery prefix is not contiguous' USING ERRCODE='23514';
        END IF;
        UPDATE messaging.identity_delivery_heads
           SET compacted_through=compact_to
         WHERE identity_id=selected_identity;
        changed := changed+removed;
        selected_identity := NULL;
    END LOOP;
    RETURN changed;
END
$$;

CREATE OR REPLACE FUNCTION realtime.compact_expired(now_ms bigint, maximum_rows integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, realtime
AS $$
DECLARE database_now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
DECLARE selected_identity text;
DECLARE current_floor bigint;
DECLARE compact_to bigint;
DECLARE removed integer;
DECLARE changed integer := 0;
BEGIN
    IF NOT realtime.runtime_authorized()
       OR now_ms NOT BETWEEN database_now_ms-60000 AND database_now_ms+60000
       OR maximum_rows NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'realtime compaction rejected' USING ERRCODE='42501';
    END IF;
    WHILE changed < maximum_rows LOOP
        SELECT head.identity_id INTO selected_identity
          FROM realtime.identity_heads AS head
          JOIN realtime.journal AS first_event
            ON first_event.identity_id=head.identity_id
           AND first_event.cursor=head.journal_floor
         WHERE first_event.expires_at_ms<=now_ms
         ORDER BY head.identity_id LIMIT 1;
        EXIT WHEN selected_identity IS NULL;
        SELECT journal_floor INTO current_floor
          FROM realtime.identity_heads
         WHERE identity_id=selected_identity FOR UPDATE;
        SELECT max(cursor) INTO compact_to FROM (
            SELECT cursor FROM realtime.journal
             WHERE identity_id=selected_identity
               AND cursor>=current_floor
               AND expires_at_ms<=now_ms
               AND cursor < COALESCE((
                    SELECT min(cursor) FROM realtime.journal
                     WHERE identity_id=selected_identity
                       AND cursor>=current_floor AND expires_at_ms>now_ms
               ),9007199254740992)
             ORDER BY cursor LIMIT maximum_rows-changed
        ) AS expired_prefix;
        IF compact_to IS NULL THEN
            selected_identity := NULL;
            CONTINUE;
        END IF;
        DELETE FROM realtime.outbox
         WHERE identity_id=selected_identity AND cursor BETWEEN current_floor AND compact_to;
        DELETE FROM realtime.journal
         WHERE identity_id=selected_identity AND cursor BETWEEN current_floor AND compact_to;
        GET DIAGNOSTICS removed = ROW_COUNT;
        IF removed <> compact_to-current_floor+1 THEN
            RAISE EXCEPTION 'realtime journal prefix is not contiguous' USING ERRCODE='23514';
        END IF;
        UPDATE realtime.identity_heads
           SET journal_floor=LEAST(compact_to+1,9007199254740991)
         WHERE identity_id=selected_identity;
        changed := changed+removed;
        selected_identity := NULL;
    END LOOP;
    IF changed < maximum_rows THEN
        changed := changed + messaging.compact_expired_identity_deliveries(
            now_ms,maximum_rows-changed);
    END IF;
    RETURN changed;
END
$$;

REVOKE ALL ON FUNCTION messaging.compact_expired_identity_deliveries(bigint,integer) FROM PUBLIC;
