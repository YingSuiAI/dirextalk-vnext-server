-- PD7/PD8a: origin-hosted continued-feed idempotency and signed public discussion.
-- Subscriber/follower state is intentionally absent.

CREATE TABLE directory.feed_idempotency_receipts (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  idempotency_key_hash bytea NOT NULL CHECK (octet_length(idempotency_key_hash) = 32),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  exact_response bytea NOT NULL CHECK (octet_length(exact_response) > 0),
  created_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, subject_id, idempotency_key_hash),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id)
);

CREATE TABLE directory.discussion_policy_heads (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  current_revision bigint NOT NULL CHECK (current_revision > 0),
  current_digest bytea NOT NULL CHECK (octet_length(current_digest) = 32),
  updated_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, subject_id),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id)
);

CREATE TABLE directory.discussion_policy_versions (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  previous_policy_digest bytea,
  policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
  acceptance_policy smallint NOT NULL CHECK (acceptance_policy = 1),
  issued_at_ms bigint NOT NULL,
  exact_signed_policy bytea NOT NULL CHECK (octet_length(exact_signed_policy) > 0),
  PRIMARY KEY (tenant_id, subject_id, revision),
  UNIQUE (tenant_id, subject_id, policy_digest),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id),
  CHECK (previous_policy_digest IS NULL OR octet_length(previous_policy_digest) = 32),
  CHECK ((revision = 1) = (previous_policy_digest IS NULL))
);

CREATE TABLE directory.discussion_idempotency_receipts (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  mutation_kind smallint NOT NULL CHECK (mutation_kind IN (1, 2, 3)),
  idempotency_key_hash bytea NOT NULL CHECK (octet_length(idempotency_key_hash) = 32),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  exact_response bytea NOT NULL CHECK (octet_length(exact_response) > 0),
  created_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, subject_id, mutation_kind, idempotency_key_hash),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id)
);

CREATE TABLE directory.discussion_event_ids (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  event_id uuid NOT NULL CHECK (system.is_uuid_v7(event_id)),
  event_kind smallint NOT NULL CHECK (event_kind IN (1, 2)),
  event_digest bytea NOT NULL CHECK (octet_length(event_digest) = 32),
  recorded_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, subject_id, event_id),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id)
);

CREATE TABLE directory.feed_comment_threads (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  post_id bytea NOT NULL CHECK (octet_length(post_id) = 32),
  head_sequence bigint NOT NULL CHECK (head_sequence > 0),
  head_hash bytea NOT NULL CHECK (octet_length(head_hash) = 32),
  updated_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, subject_id, post_id),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id)
);

CREATE TABLE directory.feed_comment_entries (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  post_id bytea NOT NULL CHECK (octet_length(post_id) = 32),
  sequence bigint NOT NULL CHECK (sequence > 0),
  previous_entry_hash bytea,
  entry_hash bytea NOT NULL CHECK (octet_length(entry_hash) = 32),
  event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
  event_id uuid NOT NULL CHECK (system.is_uuid_v7(event_id)),
  parent_entry_hash bytea,
  actor_identity_id text NOT NULL,
  actor_device_id uuid NOT NULL CHECK (system.is_uuid_v7(actor_device_id)),
  actor_identity_origin text NOT NULL,
  policy_revision bigint NOT NULL CHECK (policy_revision > 0),
  policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
  created_at_ms bigint NOT NULL,
  accepted_at_ms bigint NOT NULL,
  exact_signed_event bytea NOT NULL CHECK (octet_length(exact_signed_event) > 0),
  exact_receipt bytea NOT NULL CHECK (octet_length(exact_receipt) > 0),
  PRIMARY KEY (tenant_id, subject_id, post_id, sequence),
  UNIQUE (tenant_id, subject_id, post_id, entry_hash),
  UNIQUE (tenant_id, subject_id, post_id, event_hash),
  FOREIGN KEY (tenant_id, subject_id, post_id)
    REFERENCES directory.feed_comment_threads (tenant_id, subject_id, post_id),
  CHECK (previous_entry_hash IS NULL OR octet_length(previous_entry_hash) = 32),
  CHECK (parent_entry_hash IS NULL OR octet_length(parent_entry_hash) = 32),
  CHECK ((sequence = 1) = (previous_entry_hash IS NULL))
);

CREATE TABLE directory.feed_reaction_entries (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  post_id bytea NOT NULL CHECK (octet_length(post_id) = 32),
  target_kind smallint NOT NULL CHECK (target_kind IN (1, 2)),
  target_hash bytea NOT NULL CHECK (octet_length(target_hash) = 32),
  reaction_kind smallint NOT NULL CHECK (reaction_kind = 1),
  actor_identity_id text NOT NULL,
  actor_device_id uuid NOT NULL CHECK (system.is_uuid_v7(actor_device_id)),
  actor_revision bigint NOT NULL CHECK (actor_revision > 0),
  expected_previous_digest bytea,
  event_digest bytea NOT NULL CHECK (octet_length(event_digest) = 32),
  event_id uuid NOT NULL CHECK (system.is_uuid_v7(event_id)),
  active boolean NOT NULL,
  policy_revision bigint NOT NULL CHECK (policy_revision > 0),
  policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
  created_at_ms bigint NOT NULL,
  accepted_at_ms bigint NOT NULL,
  exact_signed_event bytea NOT NULL CHECK (octet_length(exact_signed_event) > 0),
  exact_receipt bytea NOT NULL CHECK (octet_length(exact_receipt) > 0),
  PRIMARY KEY (tenant_id, subject_id, event_digest),
  UNIQUE (tenant_id, subject_id, post_id, target_kind, target_hash, reaction_kind, actor_identity_id, actor_revision),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id),
  CHECK (expected_previous_digest IS NULL OR octet_length(expected_previous_digest) = 32),
  CHECK ((actor_revision = 1) = (expected_previous_digest IS NULL)),
  CHECK (target_kind <> 1 OR target_hash = post_id)
);

CREATE TABLE directory.feed_reaction_projections (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  post_id bytea NOT NULL CHECK (octet_length(post_id) = 32),
  target_kind smallint NOT NULL CHECK (target_kind IN (1, 2)),
  target_hash bytea NOT NULL CHECK (octet_length(target_hash) = 32),
  reaction_kind smallint NOT NULL CHECK (reaction_kind = 1),
  actor_identity_id text NOT NULL,
  current_revision bigint NOT NULL CHECK (current_revision > 0),
  current_event_digest bytea NOT NULL CHECK (octet_length(current_event_digest) = 32),
  active boolean NOT NULL,
  exact_signed_event bytea NOT NULL CHECK (octet_length(exact_signed_event) > 0),
  updated_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, subject_id, post_id, target_kind, target_hash, reaction_kind, actor_identity_id),
  FOREIGN KEY (tenant_id, subject_id, current_event_digest)
    REFERENCES directory.feed_reaction_entries (tenant_id, subject_id, event_digest),
  CHECK (target_kind <> 1 OR target_hash = post_id)
);

CREATE TABLE directory.discussion_rate_limits (
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  actor_identity_id text NOT NULL,
  mutation_kind smallint NOT NULL CHECK (mutation_kind IN (2, 3)),
  bucket_start_ms bigint NOT NULL,
  request_count integer NOT NULL CHECK (request_count > 0 AND request_count <= 120),
  PRIMARY KEY (tenant_id, subject_id, actor_identity_id, mutation_kind, bucket_start_ms),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES directory.public_subjects (tenant_id, subject_id)
);

CREATE TRIGGER feed_idempotency_receipts_append_only BEFORE UPDATE OR DELETE ON directory.feed_idempotency_receipts FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();
CREATE TRIGGER discussion_policy_versions_append_only BEFORE UPDATE OR DELETE ON directory.discussion_policy_versions FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();
CREATE TRIGGER discussion_idempotency_receipts_append_only BEFORE UPDATE OR DELETE ON directory.discussion_idempotency_receipts FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();
CREATE TRIGGER discussion_event_ids_append_only BEFORE UPDATE OR DELETE ON directory.discussion_event_ids FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();
CREATE TRIGGER feed_comment_entries_append_only BEFORE UPDATE OR DELETE ON directory.feed_comment_entries FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();
CREATE TRIGGER feed_reaction_entries_append_only BEFORE UPDATE OR DELETE ON directory.feed_reaction_entries FOR EACH ROW EXECUTE FUNCTION directory.reject_immutable_mutation();

ALTER TABLE directory.feed_idempotency_receipts ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.feed_idempotency_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.discussion_policy_heads ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.discussion_policy_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.discussion_policy_versions ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.discussion_policy_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.discussion_idempotency_receipts ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.discussion_idempotency_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.discussion_event_ids ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.discussion_event_ids FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.feed_comment_threads ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.feed_comment_threads FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.feed_comment_entries ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.feed_comment_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.feed_reaction_entries ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.feed_reaction_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.feed_reaction_projections ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.feed_reaction_projections FORCE ROW LEVEL SECURITY;
ALTER TABLE directory.discussion_rate_limits ENABLE ROW LEVEL SECURITY; ALTER TABLE directory.discussion_rate_limits FORCE ROW LEVEL SECURITY;

CREATE POLICY directory_tenant_only ON directory.feed_idempotency_receipts USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.discussion_policy_heads USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.discussion_policy_versions USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.discussion_idempotency_receipts USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.discussion_event_ids USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.feed_comment_threads USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.feed_comment_entries USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.feed_reaction_entries USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.feed_reaction_projections USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));
CREATE POLICY directory_tenant_only ON directory.discussion_rate_limits USING (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())) WITH CHECK (directory.public_feed_owner_authorized() OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id()));

DO $grant$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NOT NULL THEN
  GRANT SELECT, INSERT ON directory.feed_idempotency_receipts,
    directory.discussion_policy_versions, directory.discussion_idempotency_receipts,
    directory.discussion_event_ids, directory.feed_comment_entries,
    directory.feed_reaction_entries TO dtx_public_feed_runtime;
  GRANT SELECT, INSERT, UPDATE ON directory.discussion_policy_heads,
    directory.feed_comment_threads, directory.feed_reaction_projections,
    directory.discussion_rate_limits TO dtx_public_feed_runtime;
END IF; END $grant$;

REVOKE ALL ON directory.feed_idempotency_receipts,
  directory.discussion_policy_heads, directory.discussion_policy_versions,
  directory.discussion_idempotency_receipts, directory.discussion_event_ids,
  directory.feed_comment_threads, directory.feed_comment_entries,
  directory.feed_reaction_entries, directory.feed_reaction_projections,
  directory.discussion_rate_limits FROM PUBLIC;
