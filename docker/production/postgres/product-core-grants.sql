-- Product Core production least-privilege matrix. Agent/Public roles are
-- intentionally absent; their frozen schemas and source remain profile-only.

GRANT USAGE ON SCHEMA system TO dtx_identity_runtime, dtx_group_runtime,
    dtx_mailbox_runtime, dtx_realtime_sync_runtime;
GRANT SELECT ON system.schema_epoch TO dtx_identity_runtime, dtx_group_runtime,
    dtx_mailbox_runtime, dtx_realtime_sync_runtime;

GRANT USAGE ON SCHEMA identity TO dtx_identity_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA identity TO dtx_identity_runtime;
GRANT SELECT, INSERT, UPDATE ON identity.log_heads TO dtx_identity_runtime;
GRANT SELECT, INSERT ON identity.log_entries TO dtx_identity_runtime;
GRANT SELECT, INSERT, UPDATE ON identity.command_receipts TO dtx_identity_runtime;
GRANT SELECT, INSERT ON identity.bootstrap_idempotency_claims TO dtx_identity_runtime;
GRANT SELECT, INSERT, UPDATE ON identity.device_session_challenges TO dtx_identity_runtime;
GRANT SELECT, INSERT ON identity.device_sessions TO dtx_identity_runtime;
GRANT SELECT, INSERT ON identity.device_session_idempotency_claims TO dtx_identity_runtime;
GRANT SELECT, INSERT ON identity.device_session_receipts TO dtx_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.prune_expired_device_sessions(bigint, integer)
    TO dtx_identity_runtime;
GRANT SELECT, INSERT, UPDATE ON identity.device_enrollment_challenges
    TO dtx_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.prune_expired_device_enrollment_challenges(bigint, integer)
    TO dtx_identity_runtime;
GRANT SELECT, INSERT, UPDATE ON identity.key_packages TO dtx_identity_runtime;
GRANT SELECT, INSERT ON identity.key_package_publish_claims TO dtx_identity_runtime;
GRANT SELECT, INSERT ON identity.key_package_claims TO dtx_identity_runtime;
GRANT SELECT, INSERT ON identity.key_package_claim_receipts TO dtx_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.prune_expired_key_packages(bigint, integer)
    TO dtx_identity_runtime;
GRANT USAGE ON SCHEMA realtime TO dtx_identity_runtime;
GRANT EXECUTE ON FUNCTION realtime.append_identity_invalidation(text,text,bytea)
    TO dtx_identity_runtime;
GRANT SELECT, INSERT ON identity.fork_evidence TO dtx_identity_runtime;
GRANT SELECT, INSERT ON identity.log_outbox TO dtx_identity_runtime;

GRANT USAGE ON SCHEMA system TO dtx_group_runtime;
GRANT EXECUTE ON FUNCTION system.current_tenant_id() TO dtx_group_runtime;
GRANT EXECUTE ON FUNCTION system.is_uuid_v7(uuid) TO dtx_group_runtime;
GRANT USAGE ON SCHEMA groups TO dtx_group_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA groups TO dtx_group_runtime;
GRANT USAGE ON SCHEMA identity TO dtx_group_runtime;
GRANT EXECUTE ON FUNCTION identity.identity_group_reader_authorized()
    TO dtx_group_runtime;
GRANT EXECUTE ON FUNCTION identity.history_recovery_request_authorized(text,uuid,bytea,uuid,bigint)
    TO dtx_group_runtime;
GRANT EXECUTE ON FUNCTION identity.scoped_key_package_claim_authorized(text,uuid,bytea,bytea,bytea,uuid)
    TO dtx_group_runtime;
GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
    TO dtx_group_runtime;
GRANT SELECT, INSERT, UPDATE ON groups.policy_heads TO dtx_group_runtime;
GRANT SELECT, INSERT, UPDATE ON groups.admin_terms TO dtx_group_runtime;
GRANT SELECT, INSERT ON groups.members TO dtx_group_runtime;
GRANT SELECT, INSERT, UPDATE ON groups.invites TO dtx_group_runtime;
GRANT SELECT, INSERT, UPDATE ON groups.join_records TO dtx_group_runtime;
GRANT SELECT, INSERT ON groups.membership_commands TO dtx_group_runtime;
GRANT SELECT, INSERT ON groups.control_commands TO dtx_group_runtime;
GRANT SELECT, INSERT, UPDATE ON groups.membership_workflows TO dtx_group_runtime;
GRANT SELECT, INSERT, UPDATE ON groups.sequencer_outbox TO dtx_group_runtime;

GRANT USAGE ON SCHEMA messaging, identity TO dtx_mailbox_runtime;
GRANT EXECUTE ON FUNCTION messaging.mailbox_runtime_authorized() TO dtx_mailbox_runtime;
GRANT EXECUTE ON FUNCTION messaging.mailbox_owner_authorized() TO dtx_mailbox_runtime;
GRANT EXECUTE ON FUNCTION messaging.is_uuid_v7(uuid) TO dtx_mailbox_runtime;
GRANT EXECUTE ON FUNCTION identity.identity_runtime_authorized() TO dtx_mailbox_runtime;
GRANT EXECUTE ON FUNCTION identity.identity_owner_authorized() TO dtx_mailbox_runtime;
GRANT EXECUTE ON FUNCTION identity.identity_mailbox_reader_authorized()
    TO dtx_mailbox_runtime;
GRANT EXECUTE ON FUNCTION identity.identity_realtime_reader_authorized()
    TO dtx_mailbox_runtime;
GRANT EXECUTE ON FUNCTION identity.history_recovery_request_authorized(text,uuid,bytea,uuid,bigint)
    TO dtx_mailbox_runtime;
GRANT EXECUTE ON FUNCTION messaging.enqueue_opaque_push_intent(uuid, uuid, uuid)
    TO dtx_mailbox_runtime;
GRANT SELECT, INSERT, UPDATE ON messaging.mailboxes TO dtx_mailbox_runtime;
GRANT SELECT, INSERT ON messaging.mailbox_registration_claims TO dtx_mailbox_runtime;
GRANT SELECT, INSERT, UPDATE ON messaging.mailbox_envelopes TO dtx_mailbox_runtime;
GRANT SELECT, INSERT ON messaging.mailbox_enqueue_claims TO dtx_mailbox_runtime;
GRANT SELECT, INSERT ON messaging.mailbox_ack_claims TO dtx_mailbox_runtime;
GRANT SELECT, INSERT, UPDATE ON messaging.identity_delivery_heads,
    messaging.device_delivery_state, messaging.device_history_grants TO dtx_mailbox_runtime;
GRANT SELECT, INSERT ON messaging.identity_delivery_journal,
    messaging.device_delivery_ack_claims TO dtx_mailbox_runtime;
GRANT SELECT, INSERT ON messaging.history_recovery_offers TO dtx_mailbox_runtime;
GRANT USAGE ON SCHEMA realtime TO dtx_mailbox_runtime;
GRANT SELECT, INSERT, UPDATE ON realtime.identity_heads TO dtx_mailbox_runtime;
GRANT SELECT, INSERT ON realtime.journal, realtime.outbox TO dtx_mailbox_runtime;
GRANT SELECT, INSERT, UPDATE ON realtime.encrypted_account_read_cursors TO dtx_mailbox_runtime;
GRANT SELECT, INSERT ON realtime.account_read_cursor_claims TO dtx_mailbox_runtime;
GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
    TO dtx_mailbox_runtime;

GRANT USAGE ON SCHEMA realtime, identity, messaging TO dtx_realtime_sync_runtime;
GRANT EXECUTE ON FUNCTION realtime.runtime_authorized() TO dtx_realtime_sync_runtime;
GRANT EXECUTE ON FUNCTION messaging.is_uuid_v7(uuid) TO dtx_realtime_sync_runtime;
GRANT EXECUTE ON FUNCTION identity.identity_runtime_authorized() TO dtx_realtime_sync_runtime;
GRANT EXECUTE ON FUNCTION identity.identity_owner_authorized() TO dtx_realtime_sync_runtime;
GRANT EXECUTE ON FUNCTION identity.identity_realtime_reader_authorized()
    TO dtx_realtime_sync_runtime;
GRANT EXECUTE ON FUNCTION identity.identity_mailbox_reader_authorized()
    TO dtx_realtime_sync_runtime;
GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
    TO dtx_realtime_sync_runtime;
GRANT SELECT ON realtime.identity_heads, realtime.journal TO dtx_realtime_sync_runtime;
GRANT SELECT, INSERT, UPDATE ON realtime.device_sync_acks, realtime.device_leases
    TO dtx_realtime_sync_runtime;
GRANT EXECUTE ON FUNCTION realtime.claim_outbox(uuid,uuid,bigint,bigint,integer)
    TO dtx_realtime_sync_runtime;
GRANT EXECUTE ON FUNCTION realtime.mark_outbox_published(uuid,uuid,bigint)
    TO dtx_realtime_sync_runtime;
GRANT EXECUTE ON FUNCTION realtime.compact_expired(bigint,integer)
    TO dtx_realtime_sync_runtime;
GRANT EXECUTE ON FUNCTION messaging.compact_expired_identity_deliveries(bigint,integer)
    TO dtx_realtime_sync_runtime;

GRANT USAGE ON SCHEMA messaging TO dtx_push_registration_runtime;
GRANT EXECUTE ON FUNCTION messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid),
    messaging.opaque_push_commit_put(uuid,bytea,uuid,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea,bytea,bytea,bytea,text,bytea),
    messaging.opaque_push_commit_delete(uuid,bytea,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea)
    TO dtx_push_registration_runtime;

GRANT USAGE ON SCHEMA identity TO dtx_push_identity_auth_runtime;
GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
    TO dtx_push_identity_auth_runtime;

GRANT USAGE ON SCHEMA messaging TO dtx_push_broker_runtime;
GRANT EXECUTE ON FUNCTION messaging.claim_opaque_push_deliveries(uuid,integer),
    messaging.prune_opaque_push_terminal(integer),
    messaging.authorize_opaque_push_send(uuid,uuid),
    messaging.finish_opaque_push_accepted(uuid,uuid),
    messaging.finish_opaque_push_permanent_failure(uuid,uuid,text),
    messaging.finish_opaque_push_transient(uuid,uuid,integer,text),
    messaging.finish_opaque_push_invalid_token(uuid,uuid,bigint)
    TO dtx_push_broker_runtime;
