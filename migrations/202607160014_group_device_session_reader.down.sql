-- Restore the migration-013 identity reader policy exactly: mailbox reads
-- remain available while the group-only device-session reader is removed.
ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (
        identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_owner_authorized()
    )
    WITH CHECK (
        identity.identity_runtime_authorized()
        OR identity.identity_owner_authorized()
    );

ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (
        identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_owner_authorized()
    )
    WITH CHECK (
        identity.identity_runtime_authorized()
        OR identity.identity_owner_authorized()
    );

ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (
        identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_owner_authorized()
    )
    WITH CHECK (
        identity.identity_runtime_authorized()
        OR identity.identity_owner_authorized()
    );

DO $revoke$
BEGIN
    IF to_regrole('dtx_group_runtime') IS NOT NULL THEN
        REVOKE EXECUTE ON FUNCTION identity.identity_group_reader_authorized()
            FROM dtx_group_runtime;
        REVOKE SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
            FROM dtx_group_runtime;
        REVOKE USAGE ON SCHEMA identity FROM dtx_group_runtime;
    END IF;
END
$revoke$;

DROP FUNCTION identity.identity_group_reader_authorized();
