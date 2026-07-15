DO $revoke$
BEGIN
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION messaging.expire_attachment_objects(integer) FROM dtx_mailbox_runtime;
        REVOKE ALL ON messaging.attachment_chunks, messaging.attachment_objects FROM dtx_mailbox_runtime;
    END IF;
END
$revoke$;
DROP FUNCTION messaging.expire_attachment_objects(integer);
DROP TABLE messaging.attachment_chunks;
DROP TABLE messaging.attachment_objects;
