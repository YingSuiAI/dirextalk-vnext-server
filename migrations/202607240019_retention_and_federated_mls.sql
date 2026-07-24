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
    -- Serialize every compactor phase before taking any per-identity lock. A
    -- writer never needs this global lock and always takes its one identity
    -- advisory lock before either journal head.
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'dirextalk-retention-compactor-v1',0));
    WHILE changed < maximum_rows LOOP
        SELECT head.identity_id INTO selected_identity
          FROM messaging.identity_delivery_heads AS head
          JOIN messaging.identity_delivery_journal AS first_event
            ON first_event.identity_id=head.identity_id
           AND first_event.delivery_sequence=head.compacted_through+1
         WHERE first_event.expires_at_ms<=database_now_ms
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
               AND expires_at_ms<=database_now_ms
               AND delivery_sequence < COALESCE((
                    SELECT min(delivery_sequence)
                      FROM messaging.identity_delivery_journal
                     WHERE identity_id=selected_identity
                       AND delivery_sequence>current_floor
                       AND expires_at_ms>database_now_ms
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
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'dirextalk-retention-compactor-v1',0));
    WHILE changed < maximum_rows LOOP
        SELECT head.identity_id INTO selected_identity
          FROM realtime.identity_heads AS head
          JOIN realtime.journal AS first_event
            ON first_event.identity_id=head.identity_id
           AND first_event.cursor=head.journal_floor
         WHERE first_event.expires_at_ms<=database_now_ms
         ORDER BY head.identity_id LIMIT 1;
        EXIT WHEN selected_identity IS NULL;
        PERFORM pg_advisory_xact_lock(hashtextextended(
            'mailbox-identity:' || selected_identity, 0));
        SELECT journal_floor INTO current_floor
          FROM realtime.identity_heads
         WHERE identity_id=selected_identity FOR UPDATE;
        SELECT max(cursor) INTO compact_to FROM (
            SELECT cursor FROM realtime.journal
             WHERE identity_id=selected_identity
               AND cursor>=current_floor
               AND expires_at_ms<=database_now_ms
               AND cursor < COALESCE((
                    SELECT min(cursor) FROM realtime.journal
                     WHERE identity_id=selected_identity
                       AND cursor>=current_floor AND expires_at_ms>database_now_ms
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
    RETURN changed;
END
$$;

REVOKE ALL ON FUNCTION messaging.compact_expired_identity_deliveries(bigint,integer) FROM PUBLIC;

DO $grants$
BEGIN
    IF to_regrole('dtx_realtime_sync_runtime') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION messaging.compact_expired_identity_deliveries(bigint,integer)
            TO dtx_realtime_sync_runtime;
    END IF;
END
$grants$;
-- Freeze one explicit replay horizon for opaque enqueue and acknowledgement
-- receipts. Ciphertext remains quota-charged until durable expiry tombstones
-- it; replay metadata remains exact for 15 further minutes, then bounded GC is
-- permitted. All retention decisions use one captured database clock.

CREATE OR REPLACE FUNCTION messaging.enforce_envelope_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE database_now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    IF TG_OP='DELETE' THEN
        IF OLD.state<>'expired'
           OR OLD.opaque_ciphertext IS NOT NULL
           OR OLD.expires_at_ms>database_now_ms-900000 THEN
            RAISE EXCEPTION 'mailbox envelope retention delete is not authorized'
                USING ERRCODE='23514';
        END IF;
        RETURN OLD;
    END IF;
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
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION messaging.enforce_enqueue_claim_retention()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE database_now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    IF TG_OP<>'DELETE' OR NOT EXISTS (
        SELECT 1 FROM messaging.mailbox_envelopes AS envelope
         WHERE envelope.mailbox_id=OLD.mailbox_id
           AND envelope.envelope_id=OLD.envelope_id
           AND envelope.state='expired'
           AND envelope.opaque_ciphertext IS NULL
           AND envelope.expires_at_ms<=database_now_ms-900000
    ) THEN
        RAISE EXCEPTION 'mailbox enqueue claim is immutable inside replay retention'
            USING ERRCODE='23514';
    END IF;
    RETURN OLD;
END
$$;

CREATE FUNCTION messaging.enforce_replay_claim_retention()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE database_now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    IF TG_OP<>'DELETE' OR OLD.created_at_ms>database_now_ms-900000 THEN
        RAISE EXCEPTION 'mailbox acknowledgement claim is immutable inside replay retention'
            USING ERRCODE='23514';
    END IF;
    RETURN OLD;
END
$$;

DROP TRIGGER messaging_enqueue_claims_append_only ON messaging.mailbox_enqueue_claims;
CREATE TRIGGER messaging_enqueue_claims_append_only
BEFORE UPDATE OR DELETE ON messaging.mailbox_enqueue_claims
FOR EACH ROW
EXECUTE FUNCTION messaging.enforce_enqueue_claim_retention();

DROP TRIGGER messaging_ack_claims_append_only ON messaging.mailbox_ack_claims;
CREATE TRIGGER messaging_ack_claims_append_only
BEFORE UPDATE OR DELETE ON messaging.mailbox_ack_claims
FOR EACH ROW
EXECUTE FUNCTION messaging.enforce_replay_claim_retention();

CREATE TRIGGER messaging_device_delivery_ack_claims_retention
BEFORE UPDATE OR DELETE ON messaging.device_delivery_ack_claims
FOR EACH ROW
EXECUTE FUNCTION messaging.enforce_replay_claim_retention();

CREATE INDEX messaging_identity_delivery_expiry_gc_idx
    ON messaging.identity_delivery_journal(expires_at_ms,identity_id,delivery_sequence);
CREATE INDEX messaging_mailbox_retained_quota_idx
    ON messaging.mailbox_envelopes(mailbox_id)
    WHERE opaque_ciphertext IS NOT NULL;
CREATE INDEX messaging_envelope_tombstone_gc_idx
    ON messaging.mailbox_envelopes(expires_at_ms,mailbox_id,delivery_sequence)
    WHERE state='expired' AND opaque_ciphertext IS NULL;
CREATE INDEX messaging_mailbox_ack_replay_gc_idx
    ON messaging.mailbox_ack_claims(created_at_ms,mailbox_id);
CREATE INDEX messaging_device_ack_replay_gc_idx
    ON messaging.device_delivery_ack_claims(created_at_ms,identity_id,device_id);

CREATE OR REPLACE FUNCTION messaging.compact_expired_identity_deliveries(
    now_ms bigint,
    maximum_rows integer
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, messaging
AS $$
DECLARE database_now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
DECLARE retention_cutoff_ms bigint;
DECLARE selected_identity text;
DECLARE current_floor bigint;
DECLARE compact_to bigint;
DECLARE processed integer;
DECLARE changed integer := 0;
DECLARE stage_changed integer;
DECLARE base_budget integer;
DECLARE remainder_budget integer;
DECLARE rotating_stage integer;
DECLARE tombstone_budget integer;
DECLARE prefix_budget integer;
DECLARE orphan_budget integer;
DECLARE mailbox_ack_budget integer;
DECLARE device_ack_budget integer;
BEGIN
    IF NOT realtime.runtime_authorized()
       OR now_ms NOT BETWEEN database_now_ms-60000 AND database_now_ms+60000
       OR maximum_rows NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'identity delivery compaction rejected' USING ERRCODE='42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'dirextalk-retention-compactor-v1',0));
    retention_cutoff_ms := database_now_ms-900000;

    -- Reserve progress for all five relations. For batches smaller than five,
    -- rotate the remainder by the trusted database clock so no phase can be
    -- permanently starved across calls.
    base_budget := maximum_rows/5;
    remainder_budget := maximum_rows%5;
    rotating_stage := mod(database_now_ms/30000,5)::integer;
    tombstone_budget := base_budget
        + CASE WHEN mod(0-rotating_stage+5,5)<remainder_budget THEN 1 ELSE 0 END;
    prefix_budget := base_budget
        + CASE WHEN mod(1-rotating_stage+5,5)<remainder_budget THEN 1 ELSE 0 END;
    orphan_budget := base_budget
        + CASE WHEN mod(2-rotating_stage+5,5)<remainder_budget THEN 1 ELSE 0 END;
    mailbox_ack_budget := base_budget
        + CASE WHEN mod(3-rotating_stage+5,5)<remainder_budget THEN 1 ELSE 0 END;
    device_ack_budget := base_budget
        + CASE WHEN mod(4-rotating_stage+5,5)<remainder_budget THEN 1 ELSE 0 END;

    -- Durable expiry tombstones ciphertext and releases only active
    -- counters. ACK never releases retained quota by itself.
    stage_changed := 0;
    WHILE stage_changed<tombstone_budget LOOP
        SELECT journal.identity_id INTO selected_identity
          FROM messaging.identity_delivery_journal AS journal
          JOIN messaging.mailbox_envelopes AS envelope
            ON envelope.mailbox_id=journal.mailbox_id
           AND envelope.envelope_id=journal.envelope_id
         WHERE journal.expires_at_ms<=database_now_ms
           AND envelope.opaque_ciphertext IS NOT NULL
         ORDER BY journal.expires_at_ms,journal.identity_id,journal.delivery_sequence
         LIMIT 1;
        EXIT WHEN selected_identity IS NULL;

        PERFORM pg_advisory_xact_lock(hashtextextended(
            'mailbox-identity:' || selected_identity,0));
        PERFORM compacted_through FROM messaging.identity_delivery_heads
         WHERE identity_id=selected_identity FOR UPDATE;
        WITH payload AS MATERIALIZED (
            SELECT envelope.mailbox_id,envelope.envelope_id,envelope.state,
                   octet_length(envelope.opaque_ciphertext)::bigint AS ciphertext_bytes
              FROM messaging.identity_delivery_journal AS journal
              JOIN messaging.mailbox_envelopes AS envelope
                ON envelope.mailbox_id=journal.mailbox_id
               AND envelope.envelope_id=journal.envelope_id
             WHERE journal.identity_id=selected_identity
               AND journal.expires_at_ms<=database_now_ms
               AND envelope.opaque_ciphertext IS NOT NULL
             ORDER BY journal.delivery_sequence
             LIMIT tombstone_budget-stage_changed
             FOR UPDATE OF envelope
        ), tombstoned AS (
            UPDATE messaging.mailbox_envelopes AS envelope
               SET state='expired',opaque_ciphertext=NULL
              FROM payload
             WHERE envelope.mailbox_id=payload.mailbox_id
               AND envelope.envelope_id=payload.envelope_id
            RETURNING envelope.mailbox_id,envelope.envelope_id
        ), released AS (
            SELECT payload.mailbox_id,
                   count(*) FILTER(WHERE payload.state='available')::integer AS envelope_count,
                   COALESCE(sum(payload.ciphertext_bytes)
                       FILTER(WHERE payload.state='available'),0)::bigint AS envelope_bytes
              FROM payload JOIN tombstoned USING(mailbox_id,envelope_id)
             GROUP BY payload.mailbox_id
        ), updated_mailboxes AS (
            UPDATE messaging.mailboxes AS mailbox
               SET active_envelope_count=mailbox.active_envelope_count-released.envelope_count,
                   active_envelope_bytes=mailbox.active_envelope_bytes-released.envelope_bytes
              FROM released WHERE mailbox.mailbox_id=released.mailbox_id
            RETURNING mailbox.mailbox_id
        )
        SELECT count(*)::integer INTO processed FROM tombstoned;
        IF processed=0 THEN
            RAISE EXCEPTION 'expired identity delivery could not be tombstoned'
                USING ERRCODE='23514';
        END IF;
        stage_changed := stage_changed+processed;
        changed := changed+processed;
        selected_identity := NULL;
    END LOOP;

    -- Collapse only an old, contiguous, fully tombstoned delivery prefix.
    stage_changed := 0;
    WHILE stage_changed<prefix_budget LOOP
        SELECT head.identity_id INTO selected_identity
          FROM messaging.identity_delivery_heads AS head
          JOIN messaging.identity_delivery_journal AS journal
            ON journal.identity_id=head.identity_id
           AND journal.delivery_sequence=head.compacted_through+1
          JOIN messaging.mailbox_envelopes AS envelope
            ON envelope.mailbox_id=journal.mailbox_id
           AND envelope.envelope_id=journal.envelope_id
         WHERE journal.expires_at_ms<=retention_cutoff_ms
           AND envelope.state='expired'
           AND envelope.opaque_ciphertext IS NULL
         ORDER BY journal.expires_at_ms,head.identity_id LIMIT 1;
        EXIT WHEN selected_identity IS NULL;

        PERFORM pg_advisory_xact_lock(hashtextextended(
            'mailbox-identity:' || selected_identity,0));
        SELECT compacted_through INTO current_floor
          FROM messaging.identity_delivery_heads
         WHERE identity_id=selected_identity FOR UPDATE;
        SELECT max(delivery_sequence) INTO compact_to
          FROM (
            SELECT journal.delivery_sequence
              FROM messaging.identity_delivery_journal AS journal
              JOIN messaging.mailbox_envelopes AS envelope
                ON envelope.mailbox_id=journal.mailbox_id
               AND envelope.envelope_id=journal.envelope_id
             WHERE journal.identity_id=selected_identity
               AND journal.delivery_sequence>current_floor
               AND journal.delivery_sequence<COALESCE((
                    SELECT min(blocked.delivery_sequence)
                      FROM messaging.identity_delivery_journal AS blocked
                      JOIN messaging.mailbox_envelopes AS blocked_envelope
                        ON blocked_envelope.mailbox_id=blocked.mailbox_id
                       AND blocked_envelope.envelope_id=blocked.envelope_id
                     WHERE blocked.identity_id=selected_identity
                       AND blocked.delivery_sequence>current_floor
                       AND NOT (
                           blocked.expires_at_ms<=retention_cutoff_ms
                           AND blocked_envelope.state='expired'
                           AND blocked_envelope.opaque_ciphertext IS NULL
                       )
               ),9007199254740992)
             ORDER BY journal.delivery_sequence
             LIMIT prefix_budget-stage_changed
          ) AS retained_prefix;
        IF compact_to IS NULL THEN
            selected_identity := NULL;
            CONTINUE;
        END IF;

        DELETE FROM messaging.mailbox_enqueue_claims AS claim
         USING messaging.identity_delivery_journal AS journal
         WHERE journal.identity_id=selected_identity
           AND journal.delivery_sequence>current_floor
           AND journal.delivery_sequence<=compact_to
           AND claim.mailbox_id=journal.mailbox_id
           AND claim.envelope_id=journal.envelope_id;
        WITH deleted_journal AS (
            DELETE FROM messaging.identity_delivery_journal
             WHERE identity_id=selected_identity
               AND delivery_sequence>current_floor
               AND delivery_sequence<=compact_to
            RETURNING mailbox_id,envelope_id
        ), deleted_envelopes AS (
            DELETE FROM messaging.mailbox_envelopes AS envelope
             USING deleted_journal
             WHERE envelope.mailbox_id=deleted_journal.mailbox_id
               AND envelope.envelope_id=deleted_journal.envelope_id
            RETURNING envelope.mailbox_id
        )
        SELECT count(*)::integer INTO processed FROM deleted_journal;
        IF processed<>compact_to-current_floor THEN
            RAISE EXCEPTION 'identity delivery retention prefix is not contiguous'
                USING ERRCODE='23514';
        END IF;
        UPDATE messaging.identity_delivery_heads
           SET compacted_through=compact_to
         WHERE identity_id=selected_identity;
        stage_changed := stage_changed+processed;
        changed := changed+processed;
        selected_identity := NULL;
    END LOOP;

    -- Collect expired envelopes whose durable journal is already absent.
    stage_changed := 0;
    WHILE stage_changed<orphan_budget LOOP
        SELECT mailbox.owner_identity_id INTO selected_identity
          FROM messaging.mailbox_envelopes AS envelope
          JOIN messaging.mailboxes AS mailbox USING(mailbox_id)
         WHERE envelope.state='expired'
           AND envelope.opaque_ciphertext IS NULL
           AND envelope.expires_at_ms<=retention_cutoff_ms
           AND NOT EXISTS (
               SELECT 1 FROM messaging.identity_delivery_journal AS journal
                WHERE journal.mailbox_id=envelope.mailbox_id
                  AND journal.envelope_id=envelope.envelope_id
           )
         ORDER BY envelope.expires_at_ms,mailbox.owner_identity_id,
                  envelope.mailbox_id,envelope.delivery_sequence
         LIMIT 1;
        EXIT WHEN selected_identity IS NULL;
        PERFORM pg_advisory_xact_lock(hashtextextended(
            'mailbox-identity:' || selected_identity,0));
        WITH candidates AS MATERIALIZED (
            SELECT envelope.mailbox_id,envelope.envelope_id
              FROM messaging.mailbox_envelopes AS envelope
              JOIN messaging.mailboxes AS mailbox USING(mailbox_id)
             WHERE mailbox.owner_identity_id=selected_identity
               AND envelope.state='expired'
               AND envelope.opaque_ciphertext IS NULL
               AND envelope.expires_at_ms<=retention_cutoff_ms
               AND NOT EXISTS (
                   SELECT 1 FROM messaging.identity_delivery_journal AS journal
                    WHERE journal.mailbox_id=envelope.mailbox_id
                      AND journal.envelope_id=envelope.envelope_id
               )
             ORDER BY envelope.expires_at_ms,envelope.mailbox_id,envelope.delivery_sequence
             LIMIT orphan_budget-stage_changed
             FOR UPDATE OF envelope
        ), deleted_claims AS (
            DELETE FROM messaging.mailbox_enqueue_claims AS claim
             USING candidates
             WHERE claim.mailbox_id=candidates.mailbox_id
               AND claim.envelope_id=candidates.envelope_id
            RETURNING claim.mailbox_id
        ), deleted_envelopes AS (
            DELETE FROM messaging.mailbox_envelopes AS envelope
             USING candidates
             WHERE envelope.mailbox_id=candidates.mailbox_id
               AND envelope.envelope_id=candidates.envelope_id
               AND (SELECT count(*) FROM deleted_claims)>=0
            RETURNING envelope.mailbox_id
        )
        SELECT count(*)::integer INTO processed FROM deleted_envelopes;
        IF processed=0 THEN
            RAISE EXCEPTION 'orphan envelope retention could not advance'
                USING ERRCODE='23514';
        END IF;
        stage_changed := stage_changed+processed;
        changed := changed+processed;
        selected_identity := NULL;
    END LOOP;

    -- No-op ACKs under fresh idempotency keys are bounded by the same replay
    -- horizon; their durable delivery cursors remain untouched.
    stage_changed := 0;
    WHILE stage_changed<mailbox_ack_budget LOOP
        SELECT mailbox.owner_identity_id INTO selected_identity
          FROM messaging.mailbox_ack_claims AS claim
          JOIN messaging.mailboxes AS mailbox USING(mailbox_id)
         WHERE claim.created_at_ms<=retention_cutoff_ms
         ORDER BY claim.created_at_ms,mailbox.owner_identity_id LIMIT 1;
        EXIT WHEN selected_identity IS NULL;
        PERFORM pg_advisory_xact_lock(hashtextextended(
            'mailbox-identity:' || selected_identity,0));
        WITH deleted AS (
            DELETE FROM messaging.mailbox_ack_claims AS claim
             USING messaging.mailboxes AS mailbox
             WHERE claim.mailbox_id=mailbox.mailbox_id
               AND mailbox.owner_identity_id=selected_identity
               AND claim.created_at_ms<=retention_cutoff_ms
               AND (claim.mailbox_id,claim.owner_identity_id,claim.owner_device_id,
                    claim.idempotency_key_hash) IN (
                   SELECT candidate.mailbox_id,candidate.owner_identity_id,
                          candidate.owner_device_id,candidate.idempotency_key_hash
                     FROM messaging.mailbox_ack_claims AS candidate
                     JOIN messaging.mailboxes AS candidate_mailbox USING(mailbox_id)
                    WHERE candidate_mailbox.owner_identity_id=selected_identity
                      AND candidate.created_at_ms<=retention_cutoff_ms
                    ORDER BY candidate.created_at_ms,candidate.mailbox_id,
                             candidate.owner_device_id,candidate.idempotency_key_hash
                    LIMIT mailbox_ack_budget-stage_changed
               )
            RETURNING claim.mailbox_id
        )
        SELECT count(*)::integer INTO processed FROM deleted;
        IF processed=0 THEN
            RAISE EXCEPTION 'mailbox acknowledgement retention could not advance'
                USING ERRCODE='23514';
        END IF;
        stage_changed := stage_changed+processed;
        changed := changed+processed;
        selected_identity := NULL;
    END LOOP;

    stage_changed := 0;
    WHILE stage_changed<device_ack_budget LOOP
        SELECT identity_id INTO selected_identity
          FROM messaging.device_delivery_ack_claims
         WHERE created_at_ms<=retention_cutoff_ms
         ORDER BY created_at_ms,identity_id,device_id LIMIT 1;
        EXIT WHEN selected_identity IS NULL;
        PERFORM pg_advisory_xact_lock(hashtextextended(
            'mailbox-identity:' || selected_identity,0));
        WITH deleted AS (
            DELETE FROM messaging.device_delivery_ack_claims AS claim
             WHERE claim.identity_id=selected_identity
               AND claim.created_at_ms<=retention_cutoff_ms
               AND (claim.identity_id,claim.device_id,claim.idempotency_key_hash) IN (
                   SELECT candidate.identity_id,candidate.device_id,
                          candidate.idempotency_key_hash
                     FROM messaging.device_delivery_ack_claims AS candidate
                    WHERE candidate.identity_id=selected_identity
                      AND candidate.created_at_ms<=retention_cutoff_ms
                    ORDER BY candidate.created_at_ms,candidate.device_id,
                             candidate.idempotency_key_hash
                    LIMIT device_ack_budget-stage_changed
               )
            RETURNING claim.identity_id
        )
        SELECT count(*)::integer INTO processed FROM deleted;
        IF processed=0 THEN
            RAISE EXCEPTION 'device acknowledgement retention could not advance'
                USING ERRCODE='23514';
        END IF;
        stage_changed := stage_changed+processed;
        changed := changed+processed;
        selected_identity := NULL;
    END LOOP;

    RETURN changed;
END
$$;

REVOKE ALL ON FUNCTION messaging.enforce_envelope_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION messaging.enforce_enqueue_claim_retention() FROM PUBLIC;
REVOKE ALL ON FUNCTION messaging.enforce_replay_claim_retention() FROM PUBLIC;
REVOKE ALL ON FUNCTION messaging.compact_expired_identity_deliveries(bigint,integer) FROM PUBLIC;
-- V40: narrow identity-origin projection for federated MLS V5 recovery.
-- The group runtime receives no identity or messaging table privileges. Only
-- the identity runtime may ask this SECURITY DEFINER function for redacted
-- current facts that its public HTTPS origin validates again against the
-- reduced identity log before returning canonical CBOR.

CREATE FUNCTION identity.mls_v5_recovery_authorization_projection(
    requested_identity_id text,
    requested_request_id uuid,
    requested_candidate_device_id uuid,
    requested_controller_device_id uuid,
    requested_head_digest bytea,
    requested_package_digest bytea,
    requested_request_digest bytea,
    requested_scope_digest bytea,
    at_ms bigint
) RETURNS TABLE(
    provider_device_id uuid,
    authority_kind text,
    authority_id text,
    history_grant_digest bytea,
    attachment_digest bytea,
    claim_receipt_digest bytea,
    authorization_expires_at_ms bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity, messaging
AS $$
    SELECT offer.provider_device_id,
           offer.authority_kind,
           offer.authority_id,
           offer.request_digest,
           offer.attachment_digest,
           receipt.receipt_digest,
           LEAST(
               challenge.expires_at_ms,
               package.expires_at_ms,
               offer.expires_at_ms,
               attachment.expires_at_ms
           )
      FROM identity.device_enrollment_challenges AS challenge
      JOIN identity.log_heads AS head
        ON head.identity_id = challenge.identity_id
       AND head.state = 'active'
       AND head.head_hash = requested_head_digest
       AND head.head_hash = challenge.approved_head_hash
      JOIN identity.key_packages AS package
        ON package.owner_identity_id = challenge.identity_id
       AND package.owner_device_id = challenge.target_device_id
       AND package.package_digest = requested_package_digest
       AND package.published_head_sequence = head.head_sequence
       AND package.published_head_hash = head.head_hash
       AND package.purpose = 'history_recovery'
       AND package.recovery_request_digest = requested_request_digest
       AND package.recovery_scope_digest = requested_scope_digest
       AND package.state = 'claimed'
       AND package.expires_at_ms > at_ms
      JOIN identity.key_package_claim_receipts AS receipt
        ON receipt.package_id = package.package_id
       AND receipt.claimant_identity_id = requested_identity_id
       AND receipt.claimant_device_id = requested_controller_device_id
       AND receipt.claimed_at_ms <= at_ms
      JOIN identity.key_package_claims AS claim
        ON claim.claimant_identity_id = receipt.claimant_identity_id
       AND claim.claimant_device_id = receipt.claimant_device_id
       AND claim.idempotency_key_hash = receipt.idempotency_key_hash
       AND claim.target_identity_id = requested_identity_id
       AND claim.target_device_id = requested_candidate_device_id
       AND claim.purpose = 'history_recovery'
       AND claim.recovery_request_digest = requested_request_digest
       AND claim.recovery_scope_digest = requested_scope_digest
      JOIN messaging.history_recovery_offers AS offer
        ON offer.identity_id = challenge.identity_id
       AND offer.request_id = challenge.challenge_id
       AND offer.recovery_request_digest = requested_request_digest
       AND offer.approved_head_hash = requested_head_digest
       AND offer.candidate_device_id = requested_candidate_device_id
       AND offer.expires_at_ms > at_ms
      JOIN LATERAL (
          SELECT max(candidate.expires_at_ms) AS expires_at_ms
            FROM messaging.attachment_objects AS candidate
           WHERE candidate.owner_identity_id = offer.identity_id
             AND candidate.expected_manifest_digest = offer.attachment_digest
             AND candidate.state = 'ready'
             AND candidate.expires_at_ms >= offer.expires_at_ms
             AND candidate.expires_at_ms > at_ms
      ) AS attachment ON attachment.expires_at_ms IS NOT NULL
     WHERE COALESCE(
               pg_has_role(
                   session_user,
                   to_regrole('dtx_identity_runtime'),
                   'MEMBER'
               ),
               false
           )
       AND challenge.identity_id = requested_identity_id
       AND challenge.challenge_id = requested_request_id
       AND challenge.target_device_id = requested_candidate_device_id
       AND challenge.protocol_version = 2
       AND challenge.state = 'approved'
       AND challenge.approved_at_ms IS NOT NULL
       AND challenge.approver_device_id IS NOT NULL
       AND challenge.recovery_request_digest = requested_request_digest
       AND challenge.expires_at_ms > at_ms
     LIMIT 1
$$;

REVOKE ALL ON FUNCTION identity.mls_v5_recovery_authorization_projection(
    text,uuid,uuid,uuid,bytea,bytea,bytea,bytea,bigint
) FROM PUBLIC;

DO $grants$ BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION identity.mls_v5_recovery_authorization_projection(
            text,uuid,uuid,uuid,bytea,bytea,bytea,bytea,bigint
        ) TO dtx_identity_runtime;
    END IF;
END $grants$;
