CREATE TABLE messaging.attachment_objects (
    object_id uuid PRIMARY KEY,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    upload_capability_hash bytea NOT NULL,
    read_capability_hash bytea NOT NULL,
    expected_manifest_digest bytea NOT NULL,
    expected_chunk_count integer NOT NULL,
    expected_ciphertext_bytes bigint NOT NULL,
    uploaded_chunk_count integer NOT NULL DEFAULT 0,
    uploaded_ciphertext_bytes bigint NOT NULL DEFAULT 0,
    manifest_bytes bytea,
    state text NOT NULL DEFAULT 'uploading',
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CHECK (messaging.is_uuid_v7(object_id)),
    CHECK (messaging.is_uuid_v7(owner_device_id)),
    CHECK (octet_length(owner_identity_id) BETWEEN 8 AND 128),
    CHECK (octet_length(upload_capability_hash)=32 AND octet_length(read_capability_hash)=32),
    CHECK (octet_length(expected_manifest_digest)=32),
    CHECK (expected_chunk_count BETWEEN 1 AND 4096),
    CHECK (expected_ciphertext_bytes BETWEEN 1 AND 1073741824),
    CHECK (uploaded_chunk_count BETWEEN 0 AND expected_chunk_count),
    CHECK (uploaded_ciphertext_bytes BETWEEN 0 AND expected_ciphertext_bytes),
    CHECK (manifest_bytes IS NULL OR octet_length(manifest_bytes) BETWEEN 1 AND 1048576),
    CHECK (state IN ('uploading','ready','cancelled','expired')),
    CHECK (expires_at_ms > created_at_ms),
    FOREIGN KEY (owner_identity_id) REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT
);

CREATE TABLE messaging.attachment_chunks (
    object_id uuid NOT NULL REFERENCES messaging.attachment_objects(object_id) ON DELETE CASCADE,
    chunk_index integer NOT NULL,
    ciphertext_digest bytea NOT NULL,
    ciphertext_bytes bytea NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    request_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (object_id, chunk_index),
    UNIQUE (object_id, idempotency_key_hash),
    CHECK (chunk_index BETWEEN 0 AND 4095),
    CHECK (octet_length(ciphertext_digest)=32),
    CHECK (octet_length(ciphertext_bytes) BETWEEN 17 AND 1048576),
    CHECK (octet_length(idempotency_key_hash)=32 AND octet_length(request_digest)=32)
);

CREATE INDEX messaging_attachment_expiry_idx
    ON messaging.attachment_objects(expires_at_ms, object_id)
    WHERE state IN ('uploading','ready','cancelled');

ALTER TABLE messaging.attachment_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.attachment_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY messaging_runtime_only ON messaging.attachment_objects
    USING (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized())
    WITH CHECK (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized());
ALTER TABLE messaging.attachment_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE messaging.attachment_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY messaging_runtime_only ON messaging.attachment_chunks
    USING (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized())
    WITH CHECK (messaging.mailbox_runtime_authorized() OR messaging.mailbox_owner_authorized());

CREATE FUNCTION messaging.expire_attachment_objects(batch_limit integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, messaging
AS $$
DECLARE affected integer;
DECLARE now_ms bigint;
BEGIN
    IF batch_limit < 1 OR batch_limit > 1000 THEN
        RAISE EXCEPTION 'invalid attachment retention batch';
    END IF;
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    WITH victims AS (
        SELECT object_id FROM messaging.attachment_objects
         WHERE state='cancelled' OR expires_at_ms <= now_ms
         ORDER BY expires_at_ms, object_id LIMIT batch_limit FOR UPDATE SKIP LOCKED
    ), removed AS (
        DELETE FROM messaging.attachment_objects object
         USING victims WHERE object.object_id=victims.object_id RETURNING 1
    ) SELECT count(*)::integer INTO affected FROM removed;
    RETURN affected;
END
$$;

DO $grant$
BEGIN
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON messaging.attachment_objects TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON messaging.attachment_chunks TO dtx_mailbox_runtime;
        GRANT EXECUTE ON FUNCTION messaging.expire_attachment_objects(integer) TO dtx_mailbox_runtime;
    END IF;
END
$grant$;

REVOKE ALL ON messaging.attachment_objects, messaging.attachment_chunks FROM PUBLIC;
REVOKE ALL ON FUNCTION messaging.expire_attachment_objects(integer) FROM PUBLIC;
