-- The bootstrap handoff itself remains a root-only local file.  This table is
-- deliberately non-secret: it fences that file's exact immutable facts and
-- digests, so losing or changing the file can never cause a token re-mint.
CREATE TABLE agent.connector_bootstrap_issuances (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    host_id uuid NOT NULL,
    enrollment_request_id uuid NOT NULL,
    enrollment_intent_id uuid NOT NULL,
    connector_generation bigint NOT NULL,
    spec_revision bigint NOT NULL,
    request_digest bytea NOT NULL,
    plan_digest bytea NOT NULL,
    handoff_digest bytea NOT NULL,
    enrollment_token_digest bytea NOT NULL,
    mcp_bearer_digest bytea NOT NULL,
    handoff_path text NOT NULL,
    plan_path text NOT NULL,
    request_json jsonb NOT NULL,
    plan_json jsonb NOT NULL,
    state text NOT NULL,
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT connector_bootstrap_issuances_operation_v7
        CHECK (system.is_uuid_v7(operation_id)),
    CONSTRAINT connector_bootstrap_issuances_connector_v7
        CHECK (system.is_uuid_v7(connector_id)),
    CONSTRAINT connector_bootstrap_issuances_host_v7
        CHECK (system.is_uuid_v7(host_id)),
    CONSTRAINT connector_bootstrap_issuances_request_v7
        CHECK (system.is_uuid_v7(enrollment_request_id)),
    CONSTRAINT connector_bootstrap_issuances_intent_v7
        CHECK (system.is_uuid_v7(enrollment_intent_id)),
    CONSTRAINT connector_bootstrap_issuances_digest_valid CHECK (
        octet_length(request_digest)=32 AND octet_length(plan_digest)=32
        AND octet_length(handoff_digest)=32 AND octet_length(enrollment_token_digest)=32
        AND octet_length(mcp_bearer_digest)=32
    ),
    CONSTRAINT connector_bootstrap_issuances_paths_valid CHECK (
        handoff_path LIKE '/%' AND plan_path LIKE '/%'
        AND octet_length(handoff_path) BETWEEN 2 AND 4096
        AND octet_length(plan_path) BETWEEN 2 AND 4096
        AND handoff_path <> plan_path
    ),
    CONSTRAINT connector_bootstrap_issuances_state_valid CHECK (state='ready'),
    CONSTRAINT connector_bootstrap_issuances_fence_positive
        CHECK (connector_generation > 0 AND spec_revision > 0),
    CONSTRAINT connector_bootstrap_issuances_expiry_valid
        CHECK (expires_at_ms BETWEEN created_at_ms+1 AND LEAST(created_at_ms+600000, 9007199254740991)),
    CONSTRAINT connector_bootstrap_issuances_operation_unique
        UNIQUE (tenant_id, enrollment_request_id),
    CONSTRAINT connector_bootstrap_issuances_intent_unique
        UNIQUE (tenant_id, enrollment_intent_id),
    CONSTRAINT connector_bootstrap_issuances_enrollment_fk
        FOREIGN KEY (tenant_id, enrollment_intent_id)
        REFERENCES agent.connector_enrollment_intents (tenant_id, enrollment_intent_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_bootstrap_issuances_request_fk
        FOREIGN KEY (tenant_id, enrollment_request_id)
        REFERENCES agent.connector_enrollment_intents (tenant_id, request_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TRIGGER connector_bootstrap_issuances_append_only
BEFORE UPDATE OR DELETE ON agent.connector_bootstrap_issuances
FOR EACH ROW EXECUTE FUNCTION agent.reject_immutable_mutation();

-- A bootstrap row is not merely adjacent to an enrollment intent: it is bound
-- to the exact current Connector fence and the one-way enrollment token proof.
CREATE FUNCTION agent.enforce_connector_bootstrap_issuance_fence()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE intent record;
BEGIN
  SELECT connector_id, host_id, request_id, token_digest, connector_generation,
         spec_revision, expires_at_ms, status
    INTO intent
    FROM agent.connector_enrollment_intents
   WHERE tenant_id=NEW.tenant_id AND enrollment_intent_id=NEW.enrollment_intent_id;
  IF NOT FOUND OR intent.connector_id<>NEW.connector_id
     OR intent.host_id<>NEW.host_id OR intent.request_id<>NEW.enrollment_request_id
     OR intent.token_digest<>NEW.enrollment_token_digest OR intent.status<>'active'
     OR intent.connector_generation<>NEW.connector_generation
     OR intent.spec_revision<>NEW.spec_revision
     OR intent.expires_at_ms<>NEW.expires_at_ms THEN
    RAISE EXCEPTION 'Connector bootstrap issuance has an invalid enrollment fence'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

CREATE CONSTRAINT TRIGGER connector_bootstrap_issuances_fence
AFTER INSERT ON agent.connector_bootstrap_issuances
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_bootstrap_issuance_fence();

ALTER TABLE agent.connector_bootstrap_issuances ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_bootstrap_issuances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_bootstrap_issuances
  USING (tenant_id=system.current_tenant_id())
  WITH CHECK (tenant_id=system.current_tenant_id());

DO $grant$ BEGIN
  IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
    GRANT SELECT, INSERT ON agent.connector_bootstrap_issuances TO dtx_agent_runtime;
  END IF;
END $grant$;

REVOKE ALL ON FUNCTION agent.enforce_connector_bootstrap_issuance_fence() FROM PUBLIC;
-- The Agent reader branch remains SELECT-only; `WITH CHECK` stays
-- identity-writer/owner-only.
ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_agent_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_agent_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_group_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_realtime_sync_runtime'),'MEMBER'),
                    false
                )
              OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname='identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname='identity'
        )
    );

ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_agent_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_agent_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_group_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_realtime_sync_runtime'),'MEMBER'),
                    false
                )
              OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname='identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname='identity'
        )
    );

ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_agent_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_agent_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_group_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_realtime_sync_runtime'),'MEMBER'),
                    false
                )
              OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname='identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname='identity'
        )
    );
-- Authorization is represented only by a domain-separated digest.  This
-- identity-runtime relation is the one durable authority for a client import.
CREATE TABLE identity.client_bindings (
    binding_id uuid PRIMARY KEY,
    deployment_operation_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    server_origin text NOT NULL,
    tls_root_ca_sha256 bytea NOT NULL,
    authorization_digest bytea NOT NULL,
    artifact_digest bytea NOT NULL,
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    state text NOT NULL,
    identity_id text,
    device_id uuid,
    identity_request_digest bytea,
    identity_idempotency_key_hash bytea,
    consume_request_digest bytea,
    consume_idempotency_key_hash bytea,
    revision bigint NOT NULL DEFAULT 1,
    CONSTRAINT client_bindings_ids_v7 CHECK (system.is_uuid_v7(binding_id) AND system.is_uuid_v7(deployment_operation_id) AND system.is_uuid_v7(tenant_id)),
    CONSTRAINT client_bindings_origin CHECK (server_origin ~ '^https://[^/?#@]+$'),
    CONSTRAINT client_bindings_digest_lengths CHECK (octet_length(tls_root_ca_sha256)=32 AND octet_length(authorization_digest)=32 AND octet_length(artifact_digest)=32 AND (identity_request_digest IS NULL OR octet_length(identity_request_digest)=32) AND (identity_idempotency_key_hash IS NULL OR octet_length(identity_idempotency_key_hash)=32) AND (consume_request_digest IS NULL OR octet_length(consume_request_digest)=32) AND (consume_idempotency_key_hash IS NULL OR octet_length(consume_idempotency_key_hash)=32)),
    CONSTRAINT client_bindings_lifetime CHECK (expires_at_ms BETWEEN issued_at_ms+1 AND issued_at_ms+900000),
    CONSTRAINT client_bindings_state CHECK (state IN ('issued','identity_bound','consumed','expired','revoked')),
    CONSTRAINT client_bindings_shape CHECK ((state='issued' AND identity_id IS NULL AND device_id IS NULL AND identity_request_digest IS NULL AND identity_idempotency_key_hash IS NULL AND consume_request_digest IS NULL AND consume_idempotency_key_hash IS NULL) OR (state='identity_bound' AND identity_id IS NOT NULL AND device_id IS NULL AND identity_request_digest IS NOT NULL AND identity_idempotency_key_hash IS NOT NULL AND consume_request_digest IS NULL AND consume_idempotency_key_hash IS NULL) OR (state='consumed' AND identity_id IS NOT NULL AND device_id IS NOT NULL AND identity_request_digest IS NOT NULL AND identity_idempotency_key_hash IS NOT NULL AND consume_request_digest IS NOT NULL AND consume_idempotency_key_hash IS NOT NULL) OR state IN ('expired','revoked')),
    CONSTRAINT client_bindings_revision CHECK (revision > 0)
);
ALTER TABLE identity.client_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.client_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.client_bindings USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized()) WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
DO $grant$ BEGIN
  IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
    GRANT EXECUTE ON FUNCTION system.is_uuid_v7(uuid) TO dtx_identity_runtime;
    GRANT SELECT, INSERT, UPDATE ON identity.client_bindings TO dtx_identity_runtime;
  END IF;
END $grant$;
-- Issuance remains correct across processes and restarts: no two durable
-- bindings can carry the same bearer digest, and an operation has one live
-- import at a time.
ALTER TABLE identity.client_bindings
  ADD CONSTRAINT client_bindings_authorization_digest_unique UNIQUE (authorization_digest),
  ADD CONSTRAINT client_bindings_device_id_v7 CHECK (device_id IS NULL OR system.is_uuid_v7(device_id));
CREATE UNIQUE INDEX client_bindings_live_operation_unique
  ON identity.client_bindings (tenant_id, deployment_operation_id)
  WHERE state IN ('issued', 'identity_bound');
-- Persist the exact domain-separated canonical issue request, including the
-- protected CA filepath. Existing rows intentionally remain NULL because
-- their historical request bytes are unavailable; they cannot be replayed.
ALTER TABLE identity.client_bindings
  ADD COLUMN issue_request_digest bytea;

ALTER TABLE identity.client_bindings
  ADD CONSTRAINT client_bindings_issue_request_digest_length
  CHECK (issue_request_digest IS NULL OR octet_length(issue_request_digest)=32);
