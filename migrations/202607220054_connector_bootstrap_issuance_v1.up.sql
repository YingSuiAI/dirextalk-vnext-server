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
