DO $revoke$
BEGIN
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION identity.identity_mailbox_reader_authorized()
            FROM dtx_mailbox_runtime;
        REVOKE ALL ON FUNCTION identity.identity_runtime_authorized()
            FROM dtx_mailbox_runtime;
        REVOKE ALL ON FUNCTION identity.identity_owner_authorized()
            FROM dtx_mailbox_runtime;
        REVOKE ALL ON identity.device_sessions, identity.log_heads, identity.log_entries
            FROM dtx_mailbox_runtime;
        REVOKE ALL ON SCHEMA identity FROM dtx_mailbox_runtime;
    END IF;
END
$revoke$;

ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

DROP FUNCTION identity.identity_mailbox_reader_authorized();

DROP TRIGGER messaging_ack_claims_append_only ON messaging.mailbox_ack_claims;
DROP TRIGGER messaging_enqueue_claims_append_only ON messaging.mailbox_enqueue_claims;
DROP TRIGGER messaging_registration_claims_append_only ON messaging.mailbox_registration_claims;
DROP TRIGGER messaging_envelopes_transition ON messaging.mailbox_envelopes;
DROP TRIGGER messaging_mailboxes_transition ON messaging.mailboxes;
DROP FUNCTION messaging.reject_immutable_mutation();
DROP FUNCTION messaging.enforce_envelope_transition();
DROP FUNCTION messaging.enforce_mailbox_transition();
DROP TABLE messaging.mailbox_ack_claims;
DROP TABLE messaging.mailbox_enqueue_claims;
DROP TABLE messaging.mailbox_envelopes;
DROP TABLE messaging.mailbox_registration_claims;
DROP TABLE messaging.mailboxes;
DROP FUNCTION messaging.is_uuid_v7(uuid);
DROP FUNCTION messaging.mailbox_owner_authorized();
DROP FUNCTION messaging.mailbox_runtime_authorized();
DROP SCHEMA messaging;
