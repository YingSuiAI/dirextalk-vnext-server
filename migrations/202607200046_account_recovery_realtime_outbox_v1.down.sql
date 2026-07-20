DO $revoke$
BEGIN
    IF to_regrole('dtx_realtime_sync_runtime') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION realtime.claim_outbox(uuid,uuid,bigint,bigint,integer)
            FROM dtx_realtime_sync_runtime;
        REVOKE ALL ON FUNCTION realtime.mark_outbox_published(uuid,uuid,bigint)
            FROM dtx_realtime_sync_runtime;
        REVOKE ALL ON FUNCTION realtime.compact_expired(bigint,integer)
            FROM dtx_realtime_sync_runtime;
    END IF;
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        REVOKE ALL ON realtime.account_read_cursor_claims FROM dtx_mailbox_runtime;
        REVOKE ALL ON realtime.encrypted_account_read_cursors FROM dtx_mailbox_runtime;
    END IF;
END
$revoke$;

DROP FUNCTION realtime.compact_expired(bigint,integer);
DROP FUNCTION realtime.mark_outbox_published(uuid,uuid,bigint);
DROP FUNCTION realtime.claim_outbox(uuid,uuid,bigint,bigint,integer);
DROP INDEX realtime.realtime_outbox_pending_claim_idx;
ALTER TABLE realtime.outbox
    DROP CONSTRAINT realtime_outbox_claim_tuple,
    DROP CONSTRAINT realtime_outbox_claimed_by_v7,
    DROP CONSTRAINT realtime_outbox_claim_id_v7,
    DROP COLUMN claim_expires_at_ms,
    DROP COLUMN claimed_by,
    DROP COLUMN claim_id;
DROP TABLE realtime.account_read_cursor_claims;
ALTER TABLE realtime.encrypted_account_read_cursors
    DROP CONSTRAINT account_read_cursor_metadata_pair,
    DROP CONSTRAINT account_read_cursor_ciphertext_digest_size,
    DROP CONSTRAINT account_read_cursor_identity_head_size,
    DROP COLUMN ciphertext_digest,
    DROP COLUMN identity_head;
