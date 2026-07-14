DROP TABLE identity.log_outbox;
DROP TABLE identity.fork_evidence;
DROP TABLE identity.command_receipts;
DROP TABLE identity.log_entries;
DROP TABLE identity.log_heads;

DROP FUNCTION identity.enforce_completed_command_receipt();
DROP FUNCTION identity.enforce_command_receipt_transition();
DROP FUNCTION identity.enforce_log_entry_chain();
DROP FUNCTION identity.enforce_log_head_chain();
DROP FUNCTION identity.assert_log_chain(text);
DROP FUNCTION identity.enforce_log_head_transition();
DROP FUNCTION identity.reject_immutable_mutation();
DROP FUNCTION identity.identity_owner_authorized();
DROP FUNCTION identity.identity_runtime_authorized();

DROP SCHEMA identity;
