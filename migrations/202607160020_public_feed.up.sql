-- PD2: public feeds are publisher-signed, append-only facts. They are not MLS timelines.
CREATE SCHEMA directory;

CREATE FUNCTION directory.public_feed_runtime_authorized()
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT COALESCE(pg_has_role(current_user, to_regrole('dtx_public_feed_runtime'), 'MEMBER'), false)
$$;
CREATE FUNCTION directory.public_feed_owner_authorized()
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT current_user = pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'directory'
$$;
CREATE FUNCTION directory.current_tenant_id()
RETURNS uuid LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT NULLIF(current_setting('dtx.tenant_id', true), '')::uuid
$$;

CREATE TABLE directory.public_subjects (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  subject_kind smallint NOT NULL CHECK (subject_kind IN (1, 2)),
  publisher_identity_id text NOT NULL,
  publisher_signing_key bytea NOT NULL CHECK (octet_length(publisher_signing_key) = 32),
  descriptor_head_sequence bigint NOT NULL CHECK (descriptor_head_sequence > 0),
  descriptor_head_hash bytea NOT NULL CHECK (octet_length(descriptor_head_hash) = 32),
  descriptor_expires_at_ms bigint NOT NULL,
  descriptor_tombstoned boolean NOT NULL DEFAULT false,
  feed_head_sequence bigint,
  feed_head_hash bytea,
  feed_tombstoned boolean NOT NULL DEFAULT false,
  PRIMARY KEY (tenant_id, subject_id),
  CHECK ((feed_head_sequence IS NULL) = (feed_head_hash IS NULL)),
  CHECK (feed_head_sequence IS NULL OR feed_head_sequence > 0),
  CHECK (feed_head_hash IS NULL OR octet_length(feed_head_hash) = 32),
  CHECK (subject_id LIKE CASE subject_kind WHEN 1 THEN 'dtxc1%' ELSE 'dtxa1%' END)
);

CREATE TABLE directory.descriptor_versions (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  previous_entry_hash bytea,
  entry_hash bytea NOT NULL CHECK (octet_length(entry_hash) = 32),
  exact_cbor bytea NOT NULL CHECK (octet_length(exact_cbor) > 0),
  tombstone boolean NOT NULL,
  PRIMARY KEY (tenant_id, subject_id, sequence),
  UNIQUE (tenant_id, entry_hash),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id),
  CHECK (previous_entry_hash IS NULL OR octet_length(previous_entry_hash) = 32)
);

CREATE TABLE directory.feed_entries (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  previous_entry_hash bytea,
  entry_hash bytea NOT NULL CHECK (octet_length(entry_hash) = 32),
  published_at_ms bigint NOT NULL,
  exact_cbor bytea NOT NULL CHECK (octet_length(exact_cbor) > 0),
  tombstone boolean NOT NULL,
  PRIMARY KEY (tenant_id, subject_id, sequence),
  UNIQUE (tenant_id, entry_hash),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id),
  CHECK (previous_entry_hash IS NULL OR octet_length(previous_entry_hash) = 32)
);

-- Moderation is a separate signed statement projection. It can never rewrite or occupy feed sequence.
CREATE TABLE directory.moderation_labels (
  tenant_id uuid NOT NULL,
  label_digest bytea NOT NULL CHECK (octet_length(label_digest) = 32),
  subject_id text NOT NULL,
  target_entry_hash bytea NOT NULL CHECK (octet_length(target_entry_hash) = 32),
  issuer_identity_id text NOT NULL,
  exact_signed_statement bytea NOT NULL CHECK (octet_length(exact_signed_statement) > 0),
  created_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, label_digest),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id)
);

CREATE FUNCTION directory.reject_immutable_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  RAISE EXCEPTION 'directory signed history is immutable' USING ERRCODE = '55000';
END $$;
CREATE TRIGGER descriptor_versions_append_only BEFORE UPDATE OR DELETE ON directory.descriptor_versions FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();
CREATE TRIGGER feed_entries_append_only BEFORE UPDATE OR DELETE ON directory.feed_entries FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();
CREATE TRIGGER moderation_labels_append_only BEFORE UPDATE OR DELETE ON directory.moderation_labels FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();

ALTER TABLE directory.public_subjects ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.public_subjects FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.descriptor_versions ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.descriptor_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.feed_entries ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.feed_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.moderation_labels ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.moderation_labels FORCE ROW LEVEL SECURITY;

CREATE POLICY directory_tenant_only ON directory.public_subjects USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.descriptor_versions USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.feed_entries USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.moderation_labels USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id = directory.current_tenant_id()));

DO $grant$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NOT NULL THEN
  GRANT USAGE ON SCHEMA directory TO dtx_public_feed_runtime;
  GRANT EXECUTE ON FUNCTION directory.public_feed_runtime_authorized(), directory.public_feed_owner_authorized(), directory.current_tenant_id() TO dtx_public_feed_runtime;
  GRANT SELECT, INSERT, UPDATE ON directory.public_subjects TO dtx_public_feed_runtime;
  GRANT SELECT, INSERT ON directory.descriptor_versions, directory.feed_entries, directory.moderation_labels TO dtx_public_feed_runtime;
END IF; END $grant$;
REVOKE ALL ON SCHEMA directory FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA directory FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA directory FROM PUBLIC;
