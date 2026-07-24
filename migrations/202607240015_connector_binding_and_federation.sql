-- V31: durable Owner receipts for Connector Binding enable/disable commands.
-- A committed Binding transition and its exact replay receipt share the same
-- tenant transaction, so a lost HTTP response cannot cause a second state
-- transition or reinterpret an already committed operation.

CREATE TABLE agent.connector_binding_state_owner_operations (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    action text NOT NULL,
    request_digest bytea NOT NULL,
    result_state text NOT NULL,
    result_revision bigint NOT NULL,
    owner_identity_id text NOT NULL,
    owner_device_id uuid NOT NULL,
    owner_session_id uuid NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    committed_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT connector_binding_state_owner_operations_binding_fk
        FOREIGN KEY (tenant_id, binding_id)
        REFERENCES agent.connector_bindings (tenant_id, binding_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_binding_state_owner_operations_ids_valid CHECK (
        system.is_uuid_v7(tenant_id)
        AND system.is_uuid_v7(operation_id)
        AND system.is_uuid_v7(binding_id)
        AND system.is_uuid_v7(owner_device_id)
        AND system.is_uuid_v7(owner_session_id)
        AND agent.is_public_id(owner_identity_id, 'dtxi1')
    ),
    CONSTRAINT connector_binding_state_owner_operations_values_valid CHECK (
        action IN ('enable', 'disable')
        AND octet_length(request_digest) = 32
        AND result_state IN ('enabled', 'disabled')
        AND result_revision BETWEEN 1 AND 9007199254740991
        AND octet_length(receipt_bytes) BETWEEN 1 AND 65536
        AND octet_length(receipt_digest) = 32
        AND committed_at_ms BETWEEN 0 AND 253402300799999
    )
);

CREATE TRIGGER connector_binding_state_owner_operations_append_only
BEFORE UPDATE OR DELETE ON agent.connector_binding_state_owner_operations
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

ALTER TABLE agent.connector_binding_state_owner_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_binding_state_owner_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_binding_state_owner_operations
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT ON agent.connector_binding_state_owner_operations
            TO dtx_agent_runtime;
        -- The Owner command may only transition the existing Binding aggregate.
        -- These are the exact rows touched by BindingSetRepository; RLS keeps
        -- every read and write inside the authenticated tenant transaction.
        GRANT SELECT ON agent.installations, agent.agent_devices,
            agent.connector_instances, agent.connector_conformance,
            agent.installation_routing_policies, agent.connector_bindings,
            agent.binding_set_heads
            TO dtx_agent_runtime;
        GRANT INSERT ON agent.connector_conformance,
            agent.installation_routing_policies, agent.connector_bindings,
            agent.binding_set_heads
            TO dtx_agent_runtime;
        GRANT UPDATE ON agent.connector_bindings, agent.binding_set_heads
            TO dtx_agent_runtime;
    END IF;
END
$grant$;
-- V4 adds first-class Hermes ACP support without changing any published
-- Connector projection below V4. These are the three durable adapter-kind
-- boundaries introduced by the original Agent Control schema.
ALTER TABLE agent.connector_instances
    DROP CONSTRAINT connector_instances_adapter_kind_valid;
ALTER TABLE agent.connector_instances
    ADD CONSTRAINT connector_instances_adapter_kind_valid
    CHECK (adapter_kind IN (
        'codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp', 'hermes_acp'
    ));

ALTER TABLE agent.connector_revisions
    DROP CONSTRAINT connector_revisions_adapter_kind_valid;
ALTER TABLE agent.connector_revisions
    ADD CONSTRAINT connector_revisions_adapter_kind_valid
    CHECK (adapter_kind IN (
        'codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp', 'hermes_acp'
    ));

ALTER TABLE agent.connector_conformance
    DROP CONSTRAINT connector_conformance_adapter_kind_valid;
ALTER TABLE agent.connector_conformance
    ADD CONSTRAINT connector_conformance_adapter_kind_valid
    CHECK (adapter_kind IN (
        'codex', 'openclaw_acp', 'eino', 'rig', 'claude_code', 'custom_acp', 'hermes_acp'
    ));
-- Federated claimants do not exist in this node's identity log. Scope every
-- idempotent claim by the verified identity origin and remove the local-only
-- claimant FK; the HTTP boundary must authenticate either a local session or
-- a current remote identity-log device before reaching these tables.
ALTER TABLE identity.key_package_claim_receipts
    DROP CONSTRAINT identity_key_package_claim_receipts_claim_fk;

ALTER TABLE identity.key_package_claims
    DROP CONSTRAINT identity_key_package_claims_claimant_fk;

ALTER TABLE identity.key_package_claim_receipts
    DROP CONSTRAINT key_package_claim_receipts_pkey;
ALTER TABLE identity.key_package_claims
    DROP CONSTRAINT key_package_claims_pkey;

ALTER TABLE identity.key_package_claims
    ADD COLUMN claimant_identity_origin text NOT NULL DEFAULT '';
ALTER TABLE identity.key_package_claim_receipts
    ADD COLUMN claimant_identity_origin text NOT NULL DEFAULT '';

ALTER TABLE identity.key_package_claims
    ADD CONSTRAINT identity_key_package_claims_origin_bounded
        CHECK (
            claimant_identity_origin = ''
            OR octet_length(claimant_identity_origin) BETWEEN 8 AND 512
        ),
    ADD PRIMARY KEY (
        claimant_identity_origin,
        claimant_identity_id,
        claimant_device_id,
        idempotency_key_hash
    );

ALTER TABLE identity.key_package_claim_receipts
    ADD CONSTRAINT identity_key_package_claim_receipts_origin_bounded
        CHECK (
            claimant_identity_origin = ''
            OR octet_length(claimant_identity_origin) BETWEEN 8 AND 512
        ),
    ADD PRIMARY KEY (
        claimant_identity_origin,
        claimant_identity_id,
        claimant_device_id,
        idempotency_key_hash
    ),
    ADD CONSTRAINT identity_key_package_claim_receipts_claim_fk
        FOREIGN KEY (
            claimant_identity_origin,
            claimant_identity_id,
            claimant_device_id,
            idempotency_key_hash
        )
        REFERENCES identity.key_package_claims (
            claimant_identity_origin,
            claimant_identity_id,
            claimant_device_id,
            idempotency_key_hash
        )
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION identity.prune_expired_key_packages(
    target_cutoff_ms bigint,
    maximum_rows integer DEFAULT 256
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
AS $$
DECLARE
    removed bigint := 0;
BEGIN
    IF target_cutoff_ms NOT BETWEEN -62135596800000 AND 253402301699999 THEN
        RAISE EXCEPTION 'key package retention cutoff is invalid'
            USING ERRCODE = '22003';
    END IF;
    IF maximum_rows NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'key package retention batch is invalid'
            USING ERRCODE = '22023';
    END IF;

    PERFORM set_config('identity.key_package_retention_prune', 'on', true);
    WITH expired_packages AS MATERIALIZED (
        SELECT package_id
          FROM identity.key_packages
         WHERE retention_until_ms <= target_cutoff_ms
         ORDER BY retention_until_ms, package_id
         LIMIT maximum_rows
         FOR UPDATE SKIP LOCKED
    ), deleted_claim_receipts AS (
        DELETE FROM identity.key_package_claim_receipts AS receipt
         USING expired_packages AS expired
         WHERE receipt.package_id = expired.package_id
         RETURNING
             receipt.claimant_identity_origin,
             receipt.claimant_identity_id,
             receipt.claimant_device_id,
             receipt.idempotency_key_hash
    ), deleted_claims AS (
        DELETE FROM identity.key_package_claims AS claim
         USING deleted_claim_receipts AS receipt
         WHERE receipt.claimant_identity_origin = claim.claimant_identity_origin
           AND receipt.claimant_identity_id = claim.claimant_identity_id
           AND receipt.claimant_device_id = claim.claimant_device_id
           AND receipt.idempotency_key_hash = claim.idempotency_key_hash
         RETURNING 1
    ), deleted_publish_claims AS (
        DELETE FROM identity.key_package_publish_claims AS claim
         USING expired_packages AS expired
         WHERE claim.package_id = expired.package_id
         RETURNING 1
    ), deleted_packages AS (
        DELETE FROM identity.key_packages AS package
         USING expired_packages AS expired
         WHERE package.package_id = expired.package_id
         RETURNING 1
    )
    SELECT count(*) INTO removed FROM deleted_packages;
    RETURN removed;
END
$$;
-- PD3d gives every logical Indexer a durable, monotonic search projection
-- generation. Public replicas probe this narrow row before consulting their
-- local body cache, so a successful publish/revoke cannot remain hidden until
-- an unrelated process-local TTL expires.
CREATE TABLE directory.index_cache_generations (
  tenant_id uuid NOT NULL,
  indexer_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  updated_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, indexer_id),
  CHECK (system.is_uuid_v7(indexer_id))
);

INSERT INTO directory.index_cache_generations (tenant_id, indexer_id, generation, updated_at_ms)
SELECT tenant_id, indexer_id, 1, max(updated_at_ms)
FROM directory.index_registrations
WHERE status IN (2, 5)
GROUP BY tenant_id, indexer_id;

ALTER TABLE directory.index_cache_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE directory.index_cache_generations FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_tenant_only ON directory.index_cache_generations
USING (
  directory.public_feed_owner_authorized()
  OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())
)
WITH CHECK (
  directory.public_feed_owner_authorized()
  OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())
);

DO $grant$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NOT NULL THEN
  GRANT SELECT,INSERT,UPDATE ON directory.index_cache_generations TO dtx_public_feed_runtime;
END IF; END $grant$;
REVOKE ALL ON directory.index_cache_generations FROM PUBLIC;
-- V35: grant the Agent runtime exactly the AR3 execution-reporting and
-- cancellation rights introduced by V16/V17.
--
-- Keep this forward-only repair separate from the already-applied schema
-- migrations so existing databases receive the missing capability without a
-- checksum rewrite.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON agent.agent_run_execution_heads
            TO dtx_agent_runtime;
        GRANT SELECT, INSERT ON agent.agent_run_checkpoints,
            agent.agent_run_outputs,
            agent.agent_run_terminals,
            agent.agent_run_cancellation_intents
            TO dtx_agent_runtime;
    END IF;
END
$grant$;
-- V32 / MLS V4 adds an Owner-only, response-loss-safe member-removal effect.
-- The accepted opaque MLS Commit, product policy revision, member deletion,
-- removed-leaf tombstone, group head, outbox, and signed receipt are committed
-- by one Group runtime transaction.
ALTER TABLE groups.mls_commit_intents
    ADD COLUMN expected_policy_revision bigint,
    ADD COLUMN result_policy_revision bigint;

ALTER TABLE groups.mls_device_members
    ADD COLUMN removed_epoch bigint;

-- Preserve any pre-V32 defensive tombstones without granting them access to a
-- later commit. New V4 removals always record the exact removal epoch.
UPDATE groups.mls_device_members
   SET removed_epoch = admitted_epoch
 WHERE state = 'removed' AND removed_epoch IS NULL;

ALTER TABLE groups.mls_device_members
    ADD CONSTRAINT groups_mls_device_members_removed_epoch_valid
    CHECK (((state = 'removed') = (removed_epoch IS NOT NULL))
           AND (removed_epoch IS NULL
                OR removed_epoch BETWEEN admitted_epoch AND 9007199254740991));

ALTER TABLE groups.mls_commit_intents
    DROP CONSTRAINT groups_mls_commit_intents_v3_admission_digests_valid,
    DROP CONSTRAINT groups_mls_commit_intents_protocol_version_valid;

-- The original V21 checks were unnamed. Locate only the two authorization
-- checks by their reviewed defining fields, then replace them with stable names.
DO $migration$
DECLARE
    constraint_name name;
BEGIN
    FOR constraint_name IN
        SELECT conname
          FROM pg_constraint
         WHERE conrelid = 'groups.mls_commit_intents'::regclass
           AND contype = 'c'
           AND position('authorization_kind' IN pg_get_constraintdef(oid)) > 0
    LOOP
        EXECUTE format(
            'ALTER TABLE groups.mls_commit_intents DROP CONSTRAINT %I',
            constraint_name
        );
    END LOOP;
END
$migration$;

ALTER TABLE groups.mls_commit_intents
    ADD CONSTRAINT groups_mls_commit_intents_authorization_kind_valid
    CHECK (authorization_kind IN ('owner_bootstrap', 'approved_identity_join',
                                  'existing_member_device_add', 'member_removal')),
    ADD CONSTRAINT groups_mls_commit_intents_authorization_shape_valid
    CHECK ((authorization_kind = 'owner_bootstrap'
            AND membership_command_id IS NULL
            AND authorization_digest IS NULL
            AND controller_device_id IS NULL
            AND controller_consent_digest IS NULL)
           OR (authorization_kind = 'approved_identity_join'
               AND membership_command_id IS NOT NULL
               AND octet_length(authorization_digest) = 32
               AND controller_device_id IS NULL
               AND controller_consent_digest IS NULL)
           OR (authorization_kind = 'existing_member_device_add'
               AND membership_command_id IS NULL
               AND authorization_digest IS NULL
               AND controller_device_id IS NOT NULL
               AND octet_length(controller_consent_digest) = 32)
           OR (authorization_kind = 'member_removal'
               AND membership_command_id IS NULL
               AND authorization_digest IS NULL
               AND controller_device_id IS NULL
               AND controller_consent_digest IS NULL)),
    ADD CONSTRAINT groups_mls_commit_intents_protocol_version_valid
    CHECK (protocol_version IN (2, 3, 4)),
    ADD CONSTRAINT groups_mls_commit_intents_versioned_bindings_valid
    CHECK ((protocol_version = 2
            AND join_request_digest IS NULL
            AND approval_request_digest IS NULL
            AND expected_policy_revision IS NULL
            AND result_policy_revision IS NULL)
           OR (protocol_version = 3
               AND authorization_kind = 'approved_identity_join'
               AND octet_length(join_request_digest) = 32
               AND octet_length(approval_request_digest) = 32
               AND expected_policy_revision IS NULL
               AND result_policy_revision IS NULL)
           OR (protocol_version = 4
               AND authorization_kind = 'member_removal'
               AND join_request_digest IS NULL
               AND approval_request_digest IS NULL
               AND expected_policy_revision BETWEEN 1 AND 9007199254740990
               AND result_policy_revision = expected_policy_revision + 1));

-- `groups.members` was append-only before removal existed. Keep that guard for
-- every mutation except the exact member DELETE covered by a V4 intent, the
-- newly persisted product-policy head, and the still-current parent MLS head.
-- Because all three facts are in the same transaction, a crash cannot leave a
-- product deletion without the corresponding durable sequencer intent.
DROP TRIGGER groups_members_append_only ON groups.members;

CREATE FUNCTION groups.enforce_member_removal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'DELETE' OR NOT EXISTS (
        SELECT 1
          FROM groups.mls_commit_intents AS intent
          JOIN groups.policy_heads AS policy
            ON policy.tenant_id = intent.tenant_id
           AND policy.scope_kind = intent.scope_kind
           AND policy.scope_id = intent.scope_id
          JOIN groups.mls_heads AS mls
            ON mls.tenant_id = intent.tenant_id
           AND mls.scope_kind = intent.scope_kind
           AND mls.scope_id = intent.scope_id
         WHERE intent.tenant_id = OLD.tenant_id
           AND intent.scope_kind = OLD.scope_kind
           AND intent.scope_id = OLD.scope_id
           AND intent.candidate_identity_id = OLD.identity_id
           AND intent.protocol_version = 4
           AND intent.authorization_kind = 'member_removal'
           AND policy.policy_revision = intent.result_policy_revision
           AND mls.epoch = intent.parent_epoch
           AND mls.head_digest = intent.parent_head_digest
    ) THEN
        RAISE EXCEPTION 'group membership immutable relation cannot be rewritten'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER groups_members_remove_only
BEFORE UPDATE OR DELETE ON groups.members
FOR EACH ROW
EXECUTE FUNCTION groups.enforce_member_removal();

REVOKE ALL ON FUNCTION groups.enforce_member_removal() FROM PUBLIC;

DO $grant$
BEGIN
    IF to_regrole('dtx_group_runtime') IS NOT NULL THEN
        GRANT DELETE ON groups.members TO dtx_group_runtime;
    END IF;
END
$grant$;
-- MCP ReferenceV1 reuses authoritative group membership and signed PublicFeed
-- facts without granting the Agent runtime direct table access.

CREATE FUNCTION groups.mcp_visible_private_conversations(
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
        OR octet_length(requested_query) > 256
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

CREATE FUNCTION directory.mcp_public_reference_facts(
    requested_tenant_id uuid,
    requested_kind_mask integer,
    requested_scan_limit integer,
    requested_now_ms bigint
)
RETURNS TABLE(
    reference_kind smallint,
    subject_id text,
    sequence bigint,
    exact_cbor bytea
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, directory, system
AS $$
BEGIN
    IF requested_tenant_id IS DISTINCT FROM system.current_tenant_id()
        OR requested_kind_mask < 1
        OR requested_kind_mask > 7
        OR (requested_kind_mask & ~6) <> 0
        OR requested_scan_limit NOT BETWEEN 1 AND 256
        OR requested_now_ms NOT BETWEEN 0 AND 253402300799999
    THEN
        RETURN;
    END IF;

    IF (requested_kind_mask & 2) <> 0 THEN
        RETURN QUERY
        SELECT 2::smallint, subject.subject_id, NULL::bigint, NULL::bytea
          FROM directory.public_subjects AS subject
         WHERE subject.tenant_id = requested_tenant_id
           AND subject.subject_kind = 1
           AND NOT subject.descriptor_tombstoned
           AND subject.descriptor_expires_at_ms > requested_now_ms
         ORDER BY subject.subject_id
         LIMIT requested_scan_limit;
    END IF;

    IF (requested_kind_mask & 4) <> 0 THEN
        RETURN QUERY
        SELECT 3::smallint, entry.subject_id, entry.sequence, entry.exact_cbor
          FROM directory.feed_entries AS entry
          JOIN directory.public_subjects AS subject
            ON subject.tenant_id = entry.tenant_id
           AND subject.subject_id = entry.subject_id
         WHERE entry.tenant_id = requested_tenant_id
           AND subject.subject_kind = 1
           AND NOT subject.descriptor_tombstoned
           AND subject.descriptor_expires_at_ms > requested_now_ms
           AND NOT subject.feed_tombstoned
           AND NOT entry.tombstone
         ORDER BY entry.subject_id, entry.sequence DESC
         LIMIT requested_scan_limit;
    END IF;
END
$$;

REVOKE ALL ON FUNCTION groups.mcp_visible_private_conversations(uuid, text, text, integer)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION directory.mcp_public_reference_facts(uuid, integer, integer, bigint)
    FROM PUBLIC;

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA groups, directory TO dtx_agent_runtime;
        GRANT EXECUTE ON FUNCTION
            groups.mcp_visible_private_conversations(uuid, text, text, integer),
            directory.mcp_public_reference_facts(uuid, integer, integer, bigint)
            TO dtx_agent_runtime;
    END IF;
END
$grant$;
