DO $revoke$
BEGIN
    IF to_regrole('dtx_realtime_sync_runtime') IS NOT NULL THEN
        REVOKE ALL ON SCHEMA realtime, identity, messaging FROM dtx_realtime_sync_runtime;
        REVOKE ALL ON ALL TABLES IN SCHEMA realtime FROM dtx_realtime_sync_runtime;
        REVOKE ALL ON FUNCTION realtime.runtime_authorized() FROM dtx_realtime_sync_runtime;
        REVOKE ALL ON FUNCTION messaging.is_uuid_v7(uuid) FROM dtx_realtime_sync_runtime;
        REVOKE ALL ON FUNCTION identity.identity_runtime_authorized() FROM dtx_realtime_sync_runtime;
        REVOKE ALL ON FUNCTION identity.identity_owner_authorized() FROM dtx_realtime_sync_runtime;
        REVOKE ALL ON FUNCTION identity.identity_realtime_reader_authorized() FROM dtx_realtime_sync_runtime;
        REVOKE ALL ON FUNCTION identity.identity_mailbox_reader_authorized() FROM dtx_realtime_sync_runtime;
        REVOKE ALL ON identity.device_sessions, identity.log_heads, identity.log_entries FROM dtx_realtime_sync_runtime;
    END IF;
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION identity.identity_realtime_reader_authorized() FROM dtx_mailbox_runtime;
        REVOKE ALL ON messaging.identity_delivery_heads, messaging.identity_delivery_journal,
            messaging.device_delivery_state, messaging.device_delivery_ack_claims,
            messaging.device_history_grants FROM dtx_mailbox_runtime;
        REVOKE ALL ON SCHEMA realtime FROM dtx_mailbox_runtime;
        REVOKE ALL ON ALL TABLES IN SCHEMA realtime FROM dtx_mailbox_runtime;
    END IF;
END
$revoke$;

ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
DROP FUNCTION identity.identity_realtime_reader_authorized();

DROP TABLE realtime.encrypted_account_read_cursors;
DROP TABLE realtime.device_leases;
DROP TABLE realtime.device_sync_acks;
DROP TABLE realtime.outbox;
DROP TABLE realtime.journal;
DROP TABLE realtime.identity_heads;
DROP FUNCTION realtime.runtime_authorized();
DROP SCHEMA realtime;
DROP TABLE messaging.device_history_grants;
DROP TABLE messaging.device_delivery_ack_claims;
DROP TABLE messaging.device_delivery_state;
DROP TABLE messaging.identity_delivery_journal;
DROP TABLE messaging.identity_delivery_heads;
