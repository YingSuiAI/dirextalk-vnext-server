DO $revoke$
BEGIN
    IF to_regrole('dtx_group_runtime') IS NOT NULL THEN
        REVOKE ALL ON groups.mls_join_confirmations FROM dtx_group_runtime;
        REVOKE ALL ON groups.mls_device_members FROM dtx_group_runtime;
        REVOKE ALL ON groups.mls_sequencer_outbox FROM dtx_group_runtime;
        REVOKE ALL ON groups.mls_commit_receipts FROM dtx_group_runtime;
        REVOKE ALL ON groups.mls_commit_intents FROM dtx_group_runtime;
        REVOKE ALL ON groups.mls_heads FROM dtx_group_runtime;
    END IF;
END
$revoke$;

DROP TABLE groups.mls_join_confirmations;
DROP TABLE groups.mls_device_members;
DROP TABLE groups.mls_sequencer_outbox;
DROP TABLE groups.mls_commit_receipts;
DROP TABLE groups.mls_commit_intents;
DROP TABLE groups.mls_heads;
