-- V46: immutable UUID coordinates for History Recovery delivery facts.  Legacy
-- realtime rows remain readable with NULL IDs; the Grant V4 path always writes
-- both UUIDv7 values and binds them into its delivery-fact receipt.
ALTER TABLE realtime.journal
    ADD COLUMN event_id uuid
        CHECK (event_id IS NULL OR messaging.is_uuid_v7(event_id));
ALTER TABLE realtime.outbox
    ADD COLUMN record_id uuid
        CHECK (record_id IS NULL OR messaging.is_uuid_v7(record_id));
CREATE UNIQUE INDEX realtime_journal_event_id_unique
    ON realtime.journal(event_id) WHERE event_id IS NOT NULL;
CREATE UNIQUE INDEX realtime_outbox_record_id_unique
    ON realtime.outbox(record_id) WHERE record_id IS NOT NULL;

DO $grants$
BEGIN
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON realtime.journal, realtime.outbox TO dtx_mailbox_runtime;
    END IF;
END
$grants$;
