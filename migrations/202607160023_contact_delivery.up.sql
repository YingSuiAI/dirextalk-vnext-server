-- IM8c/IM3f: Identity-local contact admission stores only capability hashes and opaque sealed bytes.
CREATE TABLE identity.contact_invites (
  invite_id uuid PRIMARY KEY CHECK ((get_byte(uuid_send(invite_id), 6) >> 4) = 7),
  owner_identity_id text NOT NULL REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
  owner_device_id uuid NOT NULL CHECK ((get_byte(uuid_send(owner_device_id), 6) >> 4) = 7),
  capability_hash bytea NOT NULL UNIQUE CHECK (octet_length(capability_hash)=32),
  invite_binding_digest bytea NOT NULL CHECK (octet_length(invite_binding_digest)=32),
  max_uses smallint NOT NULL CHECK (max_uses BETWEEN 1 AND 8),
  use_count smallint NOT NULL DEFAULT 0 CHECK (use_count BETWEEN 0 AND max_uses),
  issued_at_ms bigint NOT NULL,
  expires_at_ms bigint NOT NULL,
  revoked_at_ms bigint,
  created_at_ms bigint NOT NULL,
  CHECK (expires_at_ms > issued_at_ms AND expires_at_ms-issued_at_ms <= 86400000),
  CHECK (revoked_at_ms IS NULL OR revoked_at_ms >= created_at_ms)
);

CREATE TABLE identity.contact_requests (
  request_id uuid PRIMARY KEY CHECK ((get_byte(uuid_send(request_id), 6) >> 4) = 7),
  invite_id uuid NOT NULL REFERENCES identity.contact_invites(invite_id) ON DELETE RESTRICT,
  target_identity_id text NOT NULL REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
  target_device_id uuid NOT NULL CHECK ((get_byte(uuid_send(target_device_id), 6) >> 4) = 7),
  receipt_capability_hash bytea NOT NULL UNIQUE CHECK (octet_length(receipt_capability_hash)=32),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  sealed_request bytea NOT NULL CHECK (octet_length(sealed_request) BETWEEN 1 AND 131072),
  state smallint NOT NULL DEFAULT 1 CHECK (state BETWEEN 1 AND 6),
  failure_code text,
  created_at_ms bigint NOT NULL,
  expires_at_ms bigint NOT NULL,
  reviewed_at_ms bigint,
  CHECK (expires_at_ms > created_at_ms AND expires_at_ms-created_at_ms <= 86400000),
  CHECK (failure_code IS NULL OR octet_length(failure_code) BETWEEN 1 AND 32),
  CHECK ((state=1 AND reviewed_at_ms IS NULL) OR (state<>1))
);
CREATE INDEX contact_requests_pending_target_idx ON identity.contact_requests(target_identity_id,target_device_id,created_at_ms,request_id) WHERE state=1;

CREATE TABLE identity.contact_delivery_outbox (
  request_id uuid PRIMARY KEY REFERENCES identity.contact_requests(request_id) ON DELETE RESTRICT,
  delivery_digest bytea NOT NULL CHECK (octet_length(delivery_digest)=32),
  sealed_delivery bytea NOT NULL CHECK (octet_length(sealed_delivery) BETWEEN 1 AND 262144),
  created_at_ms bigint NOT NULL
);

CREATE TABLE identity.contact_owner_commands (
  owner_identity_id text NOT NULL REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
  owner_device_id uuid NOT NULL CHECK ((get_byte(uuid_send(owner_device_id), 6) >> 4) = 7),
  idempotency_key_hash bytea NOT NULL CHECK (octet_length(idempotency_key_hash)=32),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  resource_id uuid NOT NULL CHECK ((get_byte(uuid_send(resource_id), 6) >> 4) = 7),
  action smallint NOT NULL CHECK (action BETWEEN 1 AND 3),
  receipt_bytes bytea NOT NULL CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
  created_at_ms bigint NOT NULL,
  PRIMARY KEY(owner_identity_id,owner_device_id,idempotency_key_hash)
);

CREATE TABLE identity.contact_rate_limits (
  owner_identity_id text NOT NULL,
  owner_device_id uuid NOT NULL,
  action smallint NOT NULL CHECK (action BETWEEN 1 AND 3),
  bucket_start_ms bigint NOT NULL,
  request_count integer NOT NULL CHECK (request_count BETWEEN 1 AND 120),
  PRIMARY KEY(owner_identity_id,owner_device_id,action,bucket_start_ms)
);

CREATE TRIGGER contact_delivery_outbox_immutable BEFORE UPDATE OR DELETE ON identity.contact_delivery_outbox FOR EACH ROW EXECUTE FUNCTION identity.reject_immutable_mutation();
CREATE TRIGGER contact_owner_commands_immutable BEFORE UPDATE OR DELETE ON identity.contact_owner_commands FOR EACH ROW EXECUTE FUNCTION identity.reject_immutable_mutation();

ALTER TABLE identity.contact_invites ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.contact_invites FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.contact_requests ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.contact_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.contact_delivery_outbox ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.contact_delivery_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.contact_owner_commands ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.contact_owner_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.contact_rate_limits ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.contact_rate_limits FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.contact_invites USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
CREATE POLICY identity_runtime_only ON identity.contact_requests USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
CREATE POLICY identity_runtime_only ON identity.contact_delivery_outbox USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
CREATE POLICY identity_runtime_only ON identity.contact_owner_commands USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
CREATE POLICY identity_runtime_only ON identity.contact_rate_limits USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

DO $grant$ BEGIN IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
  GRANT SELECT,INSERT,UPDATE ON identity.contact_invites,identity.contact_requests,identity.contact_rate_limits TO dtx_identity_runtime;
  GRANT SELECT,INSERT ON identity.contact_delivery_outbox,identity.contact_owner_commands TO dtx_identity_runtime;
END IF; END $grant$;
REVOKE ALL ON identity.contact_invites,identity.contact_requests,identity.contact_delivery_outbox,identity.contact_owner_commands,identity.contact_rate_limits FROM PUBLIC;
