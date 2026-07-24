-- Short-lived, digest-only Agent MCP credentials.
--
-- Raw bearer material is generated and retained by the local peer operator.
-- The registered digest is exactly:
-- SHA-256("dirextalk.agent-mcp-token.v1\0" || raw_32_token_bytes).
-- The server stores only that digest and revalidates the complete
-- installation/binding/device/conversation scope on every request.

CREATE TABLE agent.mcp_credentials (
    tenant_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    token_digest bytea NOT NULL,
    installation_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    agent_device_id uuid NOT NULL,
    node_id text NOT NULL,
    conversation_id uuid NOT NULL,
    capability text NOT NULL,
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    revoked_at_ms bigint,
    PRIMARY KEY (tenant_id, credential_id),
    CONSTRAINT agent_mcp_credentials_token_digest_unique UNIQUE (token_digest),
    CONSTRAINT agent_mcp_credentials_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_mcp_credentials_installation_fk
        FOREIGN KEY (tenant_id, installation_id)
        REFERENCES agent.installations (tenant_id, installation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_mcp_credentials_binding_fk
        FOREIGN KEY (tenant_id, binding_id)
        REFERENCES agent.connector_bindings (tenant_id, binding_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_mcp_credentials_agent_device_fk
        FOREIGN KEY (tenant_id, installation_id, agent_device_id)
        REFERENCES agent.agent_devices (tenant_id, installation_id, agent_device_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_mcp_credentials_grant_fk
        FOREIGN KEY (tenant_id, conversation_id, installation_id)
        REFERENCES agent.conversation_grant_heads
            (tenant_id, conversation_id, installation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_mcp_credentials_ids_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(credential_id)
        AND system.is_uuid_v7(installation_id)
        AND system.is_uuid_v7(binding_id)
        AND system.is_uuid_v7(agent_device_id)
        AND system.is_uuid_v7(conversation_id)
    ),
    CONSTRAINT agent_mcp_credentials_digest_size
        CHECK (octet_length(token_digest) = 32),
    CONSTRAINT agent_mcp_credentials_node_id_valid CHECK (
        char_length(node_id) BETWEEN 1 AND 128
        AND octet_length(node_id) BETWEEN 1 AND 128
        AND node_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT agent_mcp_credentials_capability_exact
        CHECK (capability = 'mcp.references.v1'),
    CONSTRAINT agent_mcp_credentials_lifetime_valid CHECK (
        created_at_ms BETWEEN 0 AND 253402300799998
        AND expires_at_ms BETWEEN created_at_ms + 1
                              AND created_at_ms + 86400000
        AND expires_at_ms <= 253402300799999
        AND (revoked_at_ms IS NULL
             OR revoked_at_ms BETWEEN created_at_ms AND 253402300799999)
    )
);

CREATE INDEX agent_mcp_credentials_active_digest_idx
    ON agent.mcp_credentials (tenant_id, token_digest, expires_at_ms)
    WHERE revoked_at_ms IS NULL;
CREATE INDEX agent_mcp_credentials_binding_expiry_idx
    ON agent.mcp_credentials (tenant_id, binding_id, expires_at_ms)
    WHERE revoked_at_ms IS NULL;

CREATE FUNCTION agent.enforce_mcp_credential_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Agent MCP credentials cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.token_digest IS DISTINCT FROM OLD.token_digest
       OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
       OR NEW.binding_id IS DISTINCT FROM OLD.binding_id
       OR NEW.agent_device_id IS DISTINCT FROM OLD.agent_device_id
       OR NEW.node_id IS DISTINCT FROM OLD.node_id
       OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
       OR NEW.capability IS DISTINCT FROM OLD.capability
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
       OR OLD.revoked_at_ms IS NOT NULL
       OR NEW.revoked_at_ms IS NULL
    THEN
        RAISE EXCEPTION 'invalid Agent MCP credential transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER agent_mcp_credentials_transition
BEFORE UPDATE OR DELETE ON agent.mcp_credentials
FOR EACH ROW EXECUTE FUNCTION agent.enforce_mcp_credential_transition();

ALTER TABLE agent.mcp_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.mcp_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.mcp_credentials
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

-- Digest-only peer-operator registration seam. Locking the binding row makes
-- the two-live-credential rotation bound race-free.
CREATE FUNCTION agent.register_mcp_credential_digest(
    requested_tenant_id uuid,
    requested_credential_id uuid,
    requested_token_digest bytea,
    requested_installation_id uuid,
    requested_binding_id uuid,
    requested_agent_device_id uuid,
    requested_node_id text,
    requested_conversation_id uuid,
    requested_capability text,
    requested_created_at_ms bigint,
    requested_expires_at_ms bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, agent, system
AS $$
DECLARE
    active_count integer;
    registration_now_ms bigint;
BEGIN
    IF requested_tenant_id IS DISTINCT FROM system.current_tenant_id() THEN
        RAISE EXCEPTION 'tenant scope rejected' USING ERRCODE = '42501';
    END IF;

    registration_now_ms :=
        floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint;
    IF requested_created_at_ms > registration_now_ms THEN
        RAISE EXCEPTION 'future Agent MCP credential creation rejected'
            USING ERRCODE = '22008';
    END IF;

    PERFORM 1
      FROM agent.connector_bindings
     WHERE tenant_id = requested_tenant_id
       AND binding_id = requested_binding_id
       AND installation_id = requested_installation_id
       AND agent_device_id = requested_agent_device_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'binding scope rejected' USING ERRCODE = '23503';
    END IF;

    SELECT count(*)
      INTO active_count
      FROM agent.mcp_credentials
     WHERE tenant_id = requested_tenant_id
       AND binding_id = requested_binding_id
       AND revoked_at_ms IS NULL
       AND expires_at_ms > registration_now_ms;
    IF active_count >= 2 THEN
        RAISE EXCEPTION 'at most two live Agent MCP credentials are allowed'
            USING ERRCODE = '23514';
    END IF;

    INSERT INTO agent.mcp_credentials (
        tenant_id, credential_id, token_digest, installation_id, binding_id,
        agent_device_id, node_id, conversation_id, capability,
        created_at_ms, expires_at_ms, revoked_at_ms
    ) VALUES (
        requested_tenant_id, requested_credential_id, requested_token_digest,
        requested_installation_id, requested_binding_id,
        requested_agent_device_id, requested_node_id,
        requested_conversation_id, requested_capability,
        requested_created_at_ms, requested_expires_at_ms, NULL
    );
END
$$;

CREATE FUNCTION agent.revoke_mcp_credential_digest(
    requested_tenant_id uuid,
    requested_credential_id uuid,
    requested_token_digest bytea,
    requested_revoked_at_ms bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, agent, system
AS $$
BEGIN
    IF requested_tenant_id IS DISTINCT FROM system.current_tenant_id() THEN
        RAISE EXCEPTION 'tenant scope rejected' USING ERRCODE = '42501';
    END IF;
    UPDATE agent.mcp_credentials
       SET revoked_at_ms = requested_revoked_at_ms
     WHERE tenant_id = requested_tenant_id
       AND credential_id = requested_credential_id
       AND token_digest = requested_token_digest
       AND revoked_at_ms IS NULL;
    RETURN FOUND;
END
$$;

-- Runtime authentication returns only the exact authorized conversation ID.
-- All mutable authority facts are joined and revalidated on every invocation.
CREATE FUNCTION agent.authenticate_mcp_reference_credential(
    requested_tenant_id uuid,
    requested_token_digest bytea,
    requested_node_id text,
    requested_now_ms bigint
)
RETURNS TABLE(conversation_id uuid)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, agent, system
AS $$
    SELECT credential.conversation_id
      FROM agent.mcp_credentials AS credential
      JOIN agent.installations AS installation
        ON installation.tenant_id = credential.tenant_id
       AND installation.installation_id = credential.installation_id
      JOIN agent.agent_devices AS device
        ON device.tenant_id = credential.tenant_id
       AND device.installation_id = credential.installation_id
       AND device.agent_device_id = credential.agent_device_id
      JOIN agent.connector_bindings AS binding
        ON binding.tenant_id = credential.tenant_id
       AND binding.binding_id = credential.binding_id
       AND binding.installation_id = credential.installation_id
       AND binding.agent_device_id = credential.agent_device_id
      JOIN agent.conversation_grant_heads AS grant_head
        ON grant_head.tenant_id = credential.tenant_id
       AND grant_head.conversation_id = credential.conversation_id
       AND grant_head.installation_id = credential.installation_id
      JOIN agent.conversation_grant_versions AS grant_version
        ON grant_version.tenant_id = grant_head.tenant_id
       AND grant_version.conversation_id = grant_head.conversation_id
       AND grant_version.installation_id = grant_head.installation_id
       AND grant_version.grant_version = grant_head.current_grant_version
       AND grant_version.grant_id = grant_head.current_grant_id
     WHERE requested_tenant_id = system.current_tenant_id()
       AND credential.tenant_id = requested_tenant_id
       AND credential.token_digest = requested_token_digest
       AND credential.node_id = requested_node_id
       AND credential.capability = 'mcp.references.v1'
       AND credential.revoked_at_ms IS NULL
       AND credential.created_at_ms <= requested_now_ms
       AND credential.expires_at_ms > requested_now_ms
       AND installation.desired_state = 'enabled'
       AND installation.observed_state = 'ready'
       AND device.state = 'active'
       AND binding.state = 'enabled'
       AND grant_version.revoked_at_ms IS NULL
       AND (grant_version.expires_at_ms IS NULL
            OR grant_version.expires_at_ms > requested_now_ms)
       AND NOT EXISTS (
            SELECT 1
              FROM agent.agent_installation_revocations AS revocation
             WHERE revocation.tenant_id = credential.tenant_id
               AND revocation.installation_id = credential.installation_id
               AND (revocation.scope = 1
                    OR (revocation.scope = 2
                        AND revocation.agent_device_id = credential.agent_device_id))
       )
$$;

-- V37 accidentally enforced the query limit as bytes. JSON Schema maxLength
-- counts Unicode scalar values, so the database accepts at most 256 scalars
-- and separately caps UTF-8 at 1024 bytes.
CREATE OR REPLACE FUNCTION groups.mcp_visible_private_conversations(
    requested_tenant_id uuid,
    requested_identity_id text,
    requested_query text,
    requested_limit integer
)
RETURNS TABLE(scope_id text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, groups, system
AS $$
BEGIN
    IF requested_tenant_id IS DISTINCT FROM system.current_tenant_id()
        OR requested_identity_id !~ '^dtxi1[a-z2-7]{52}$'
        OR char_length(requested_query) > 256
        OR octet_length(requested_query) > 1024
        OR requested_limit NOT BETWEEN 1 AND 32
    THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT policy.scope_id
      FROM groups.policy_heads AS policy
     WHERE policy.tenant_id = requested_tenant_id
       AND policy.scope_kind = 'private_conversation'
       AND (
            policy.owner_identity_id = requested_identity_id
            OR EXISTS (
                SELECT 1
                  FROM groups.members AS member
                 WHERE member.tenant_id = policy.tenant_id
                   AND member.scope_kind = policy.scope_kind
                   AND member.scope_id = policy.scope_id
                   AND member.identity_id = requested_identity_id
            )
       )
       AND (
            requested_query = ''
            OR strpos(lower(policy.scope_id), lower(requested_query)) > 0
       )
     ORDER BY policy.scope_id
     LIMIT requested_limit;
END
$$;

REVOKE ALL ON agent.mcp_credentials FROM PUBLIC;
REVOKE ALL ON FUNCTION
    agent.register_mcp_credential_digest(
        uuid, uuid, bytea, uuid, uuid, uuid, text, uuid, text, bigint, bigint
    ),
    agent.revoke_mcp_credential_digest(uuid, uuid, bytea, bigint),
    agent.authenticate_mcp_reference_credential(uuid, bytea, text, bigint)
    FROM PUBLIC;

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION
            agent.authenticate_mcp_reference_credential(uuid, bytea, text, bigint)
            TO dtx_agent_runtime;
    END IF;
    IF to_regrole('dtx_agent_peer_admin') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA agent TO dtx_agent_peer_admin;
        GRANT EXECUTE ON FUNCTION
            agent.register_mcp_credential_digest(
                uuid, uuid, bytea, uuid, uuid, uuid, text, uuid, text, bigint, bigint
            ),
            agent.revoke_mcp_credential_digest(uuid, uuid, bytea, bigint)
            TO dtx_agent_peer_admin;
    END IF;
END
$grant$;
-- V39: the root-operated acceptance finalizer uses the service credential but
-- writes only the fixed Agent Definition/Installation/Device topology. Grant
-- the exact missing relations; V31 already owns the Connector/Binding rights.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON agent.agent_definitions TO dtx_agent_runtime;
        GRANT SELECT, INSERT, UPDATE ON agent.agent_definition_heads
            TO dtx_agent_runtime;
        GRANT INSERT, UPDATE ON agent.installations, agent.agent_devices
            TO dtx_agent_runtime;
        GRANT SELECT ON agent.host_credentials TO dtx_agent_runtime;
    END IF;
END
$grant$;
-- V40: acceptance-prepare creates a new Owner-scoped Host and its initial
-- credential history when the retained client identity changes. Connector
-- runtime grants already cover the new Connector rows; add only the two Host
-- inserts that the canonical acceptance foundation requires.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT INSERT ON agent.hosts, agent.host_credentials TO dtx_agent_runtime;
    END IF;
END
$grant$;
-- V41: acceptance-prepare establishes the Owner tenant stream head before
-- writing Host and Connector topology. Grant only the idempotent insert
-- boundary used by that operation; reads, mutation, and deletion remain unavailable.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT INSERT ON system.tenant_stream_heads TO dtx_agent_runtime;
    END IF;
END
$grant$;
-- V42: PostgreSQL requires SELECT on the conflict target used by the
-- acceptance foundation's INSERT ... ON CONFLICT DO NOTHING statement.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT ON system.tenant_stream_heads TO dtx_agent_runtime;
    END IF;
END
$grant$;
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
