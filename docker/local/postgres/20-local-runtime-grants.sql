-- Local Compose only. This is the same least-privilege matrix used by the
-- PostgreSQL integration harness, applied after the migrations have created
-- their schemas. Keep it explicit: if a new runtime requirement is added, the
-- local cluster must fail closed until this matrix is updated deliberately.

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
GRANT SELECT, INSERT, UPDATE ON messaging.mailboxes TO dtx_mailbox_runtime;
GRANT SELECT, INSERT ON messaging.mailbox_registration_claims TO dtx_mailbox_runtime;
GRANT SELECT, INSERT, UPDATE ON messaging.mailbox_envelopes TO dtx_mailbox_runtime;
GRANT SELECT, INSERT ON messaging.mailbox_enqueue_claims TO dtx_mailbox_runtime;
GRANT SELECT, INSERT ON messaging.mailbox_ack_claims TO dtx_mailbox_runtime;
GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
    TO dtx_mailbox_runtime;

-- These login roles deliberately use direct grants with NOINHERIT. Membership
-- in dtx_public_feed_runtime is only the RLS authorization marker and does not
-- let either service reach the other one's mutable tables.
GRANT USAGE ON SCHEMA directory TO dtx_public_feed_node, dtx_indexer_node;
GRANT EXECUTE ON FUNCTION directory.public_feed_runtime_authorized()
    TO dtx_public_feed_node, dtx_indexer_node;
GRANT EXECUTE ON FUNCTION directory.public_feed_owner_authorized()
    TO dtx_public_feed_node, dtx_indexer_node;
GRANT EXECUTE ON FUNCTION directory.current_tenant_id()
    TO dtx_public_feed_node, dtx_indexer_node;
GRANT SELECT, INSERT, UPDATE ON directory.public_subjects TO dtx_public_feed_node;
GRANT SELECT, INSERT ON directory.descriptor_versions, directory.feed_entries,
    directory.moderation_labels TO dtx_public_feed_node;
GRANT SELECT, INSERT, UPDATE ON directory.index_registrations,
    directory.index_rate_limits, directory.index_registration_attempts
    TO dtx_indexer_node;
GRANT SELECT, INSERT ON directory.indexed_feed_entries TO dtx_indexer_node;
