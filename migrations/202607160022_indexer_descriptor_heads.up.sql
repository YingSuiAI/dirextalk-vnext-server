-- PD3b retains every registration attempt while index_registrations remains the accepted subject head.
CREATE TABLE directory.index_registration_attempts (
  tenant_id uuid NOT NULL,
  registration_id uuid NOT NULL,
  indexer_id uuid NOT NULL,
  subject_id text NOT NULL,
  descriptor_sequence bigint NOT NULL CHECK (descriptor_sequence > 0),
  descriptor_hash bytea NOT NULL CHECK (octet_length(descriptor_hash)=32),
  descriptor_exact_cbor bytea NOT NULL,
  status smallint NOT NULL CHECK (status BETWEEN 1 AND 5),
  failure_code text,
  created_at_ms bigint NOT NULL,
  updated_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id,indexer_id,subject_id,descriptor_sequence),
  UNIQUE (tenant_id,indexer_id,descriptor_hash),
  FOREIGN KEY (tenant_id,registration_id) REFERENCES directory.index_registrations (tenant_id,registration_id),
  CHECK (system.is_uuid_v7(registration_id)),
  CHECK (system.is_uuid_v7(indexer_id)),
  CHECK (failure_code IS NULL OR octet_length(failure_code) BETWEEN 1 AND 64)
);

INSERT INTO directory.index_registration_attempts(
  tenant_id,registration_id,indexer_id,subject_id,descriptor_sequence,
  descriptor_hash,descriptor_exact_cbor,status,failure_code,created_at_ms,updated_at_ms
)
SELECT tenant_id,registration_id,indexer_id,subject_id,descriptor_sequence,
       descriptor_hash,descriptor_exact_cbor,status,failure_code,created_at_ms,updated_at_ms
FROM directory.index_registrations;

CREATE TRIGGER index_registration_attempts_append_only
BEFORE DELETE ON directory.index_registration_attempts
FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();

ALTER TABLE directory.index_registration_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE directory.index_registration_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_tenant_only ON directory.index_registration_attempts
USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()))
WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));

DO $grant$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NOT NULL THEN
  GRANT SELECT,INSERT,UPDATE ON directory.index_registration_attempts TO dtx_public_feed_runtime;
END IF; END $grant$;
REVOKE ALL ON directory.index_registration_attempts FROM PUBLIC;
