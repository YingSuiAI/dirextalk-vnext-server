-- PD3 Indexer state is per logical Indexer. Signed descriptor/feed facts remain exact bytes.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE directory.index_registrations (
  tenant_id uuid NOT NULL,
  registration_id uuid NOT NULL,
  indexer_id uuid NOT NULL,
  subject_id text NOT NULL,
  subject_kind smallint NOT NULL CHECK (subject_kind IN (1,2)),
  status smallint NOT NULL CHECK (status BETWEEN 1 AND 5),
  descriptor_sequence bigint NOT NULL CHECK (descriptor_sequence > 0),
  descriptor_hash bytea NOT NULL CHECK (octet_length(descriptor_hash)=32),
  descriptor_exact_cbor bytea NOT NULL,
  feed_origin text,
  feed_sequence bigint,
  feed_hash bytea,
  search_document text NOT NULL DEFAULT '',
  search_vector tsvector GENERATED ALWAYS AS (to_tsvector('simple'::regconfig, search_document)) STORED,
  failure_code text,
  created_at_ms bigint NOT NULL,
  updated_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, registration_id),
  UNIQUE (tenant_id, indexer_id, subject_id),
  CHECK (system.is_uuid_v7(registration_id)),
  CHECK (system.is_uuid_v7(indexer_id)),
  CHECK (subject_id LIKE CASE subject_kind WHEN 1 THEN 'dtxc1%' ELSE 'dtxa1%' END),
  CHECK ((feed_sequence IS NULL) = (feed_hash IS NULL)),
  CHECK (feed_sequence IS NULL OR feed_sequence > 0),
  CHECK (feed_hash IS NULL OR octet_length(feed_hash)=32),
  CHECK (failure_code IS NULL OR octet_length(failure_code) BETWEEN 1 AND 64)
);
CREATE INDEX index_registrations_exact_subject ON directory.index_registrations (tenant_id,indexer_id,subject_id) WHERE status=2;
CREATE INDEX index_registrations_fts ON directory.index_registrations USING gin(search_vector) WHERE status=2;
CREATE INDEX index_registrations_trgm ON directory.index_registrations USING gin(search_document gin_trgm_ops) WHERE status=2;

CREATE TABLE directory.indexed_feed_entries (
  tenant_id uuid NOT NULL,
  indexer_id uuid NOT NULL,
  subject_id text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  entry_hash bytea NOT NULL CHECK (octet_length(entry_hash)=32),
  exact_cbor bytea NOT NULL,
  PRIMARY KEY (tenant_id,indexer_id,subject_id,sequence),
  UNIQUE (tenant_id,indexer_id,entry_hash),
  FOREIGN KEY (tenant_id,indexer_id,subject_id) REFERENCES directory.index_registrations (tenant_id,indexer_id,subject_id)
);

CREATE TABLE directory.index_rate_limits (
  tenant_id uuid NOT NULL,
  indexer_id uuid NOT NULL,
  bucket_start_ms bigint NOT NULL,
  request_count integer NOT NULL CHECK (request_count BETWEEN 1 AND 120),
  PRIMARY KEY (tenant_id,indexer_id,bucket_start_ms)
);

CREATE TRIGGER indexed_feed_entries_append_only BEFORE UPDATE OR DELETE ON directory.indexed_feed_entries FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();

ALTER TABLE directory.index_registrations ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.index_registrations FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.indexed_feed_entries ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.indexed_feed_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.index_rate_limits ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.index_rate_limits FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_tenant_only ON directory.index_registrations USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.indexed_feed_entries USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.index_rate_limits USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));

DO $grant$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NOT NULL THEN
  GRANT SELECT,INSERT,UPDATE ON directory.index_registrations,directory.index_rate_limits TO dtx_public_feed_runtime;
  GRANT SELECT,INSERT ON directory.indexed_feed_entries TO dtx_public_feed_runtime;
END IF; END $grant$;
REVOKE ALL ON directory.index_registrations,directory.indexed_feed_entries,directory.index_rate_limits FROM PUBLIC;
