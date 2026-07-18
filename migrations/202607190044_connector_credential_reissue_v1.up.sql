-- Certificate-only offline Connector recovery. This is intentionally separate from the live
-- RotateCredential command: it preserves the Connector generation/spec/command cursor.
ALTER TABLE agent.connector_control_operations
  DROP CONSTRAINT connector_control_operations_kind_valid,
  ADD CONSTRAINT connector_control_operations_kind_valid CHECK (operation_kind IN (
    'enrollment', 'apply_config', 'rotate_credential', 'close_stream', 'credential_reissue'
  ));

ALTER TABLE agent.connector_control_credentials
  DROP CONSTRAINT connector_control_credentials_generation_unique,
  DROP CONSTRAINT connector_control_credentials_revision_unique,
  DROP CONSTRAINT connector_control_credentials_origin_valid,
  ADD CONSTRAINT connector_control_credentials_origin_valid CHECK (
    (origin_kind = 'enrollment' AND enrollment_intent_id IS NOT NULL AND predecessor_credential_id IS NULL)
    OR (origin_kind IN ('rotation', 'reissue') AND enrollment_intent_id IS NULL AND predecessor_credential_id IS NOT NULL)
  );

CREATE TABLE agent.connector_credential_reissue_intents (
  tenant_id uuid NOT NULL,
  intent_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  connector_id uuid NOT NULL,
  host_id uuid NOT NULL,
  current_credential_id uuid NOT NULL,
  current_leaf_fingerprint bytea NOT NULL CHECK (octet_length(current_leaf_fingerprint) = 32),
  connector_generation bigint NOT NULL CHECK (connector_generation BETWEEN 1 AND 9007199254740991),
  spec_revision bigint NOT NULL CHECK (spec_revision BETWEEN 1 AND 9007199254740991),
  plan_digest bytea NOT NULL CHECK (octet_length(plan_digest) = 32),
  token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
  operation_kind text GENERATED ALWAYS AS ('credential_reissue') STORED,
  status text NOT NULL CHECK (status IN ('active', 'consumed', 'aborted')),
  created_at_ms bigint NOT NULL CHECK (created_at_ms BETWEEN 0 AND 9007199254740990),
  expires_at_ms bigint NOT NULL CHECK (expires_at_ms BETWEEN created_at_ms + 1 AND LEAST(created_at_ms + 600000, 9007199254740991)),
  transitioned_at_ms bigint,
  request_digest bytea,
  result_digest bytea,
  credential_id uuid,
  PRIMARY KEY (tenant_id, intent_id),
  UNIQUE (tenant_id, operation_id),
  FOREIGN KEY (tenant_id, operation_id, connector_id, operation_kind)
    REFERENCES agent.connector_control_operations (tenant_id, operation_id, connector_id, operation_kind)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, connector_id, host_id)
    REFERENCES agent.connector_instances (tenant_id, connector_id, host_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, connector_id, current_credential_id)
    REFERENCES agent.connector_control_credentials (tenant_id, connector_id, credential_id)
    DEFERRABLE INITIALLY DEFERRED,
  CHECK (system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(intent_id)
    AND system.is_uuid_v7(operation_id) AND system.is_uuid_v7(connector_id)
    AND system.is_uuid_v7(host_id) AND system.is_uuid_v7(current_credential_id)),
  CHECK ((status = 'active' AND transitioned_at_ms IS NULL AND request_digest IS NULL AND result_digest IS NULL AND credential_id IS NULL)
    OR (status = 'consumed' AND transitioned_at_ms BETWEEN created_at_ms AND expires_at_ms AND octet_length(request_digest) = 32 AND octet_length(result_digest) = 32 AND credential_id IS NOT NULL)
    OR (status = 'aborted' AND transitioned_at_ms BETWEEN created_at_ms AND expires_at_ms - 1 AND request_digest IS NULL AND result_digest IS NULL AND credential_id IS NULL))
);
CREATE UNIQUE INDEX connector_credential_reissue_one_live_idx
  ON agent.connector_credential_reissue_intents (tenant_id, connector_id) WHERE status='active';
CREATE TRIGGER connector_credential_reissue_intents_append_only
BEFORE DELETE ON agent.connector_credential_reissue_intents FOR EACH ROW EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE OR REPLACE FUNCTION agent.enforce_connector_control_operation_published()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.operation_kind = 'enrollment' THEN
    IF NOT EXISTS (SELECT 1 FROM agent.connector_enrollment_intents WHERE tenant_id=NEW.tenant_id AND request_id=NEW.operation_id AND connector_id=NEW.connector_id) THEN
      RAISE EXCEPTION 'Connector enrollment operation was not published' USING ERRCODE='23514';
    END IF;
  ELSIF NEW.operation_kind = 'credential_reissue' THEN
    IF NOT EXISTS (SELECT 1 FROM agent.connector_credential_reissue_intents WHERE tenant_id=NEW.tenant_id AND operation_id=NEW.operation_id AND connector_id=NEW.connector_id) THEN
      RAISE EXCEPTION 'Connector credential reissue operation was not published' USING ERRCODE='23514';
    END IF;
  ELSIF NOT EXISTS (SELECT 1 FROM agent.connector_control_commands WHERE tenant_id=NEW.tenant_id AND operation_id=NEW.operation_id AND connector_id=NEW.connector_id AND command_kind=NEW.operation_kind) THEN
    RAISE EXCEPTION 'Connector command operation was not published' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION agent.enforce_connector_enrollment_consumed()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.origin_kind = 'enrollment' THEN
    IF NOT EXISTS (SELECT 1 FROM agent.connector_enrollment_intents WHERE tenant_id=NEW.tenant_id AND enrollment_intent_id=NEW.enrollment_intent_id AND connector_id=NEW.connector_id AND status='consumed' AND credential_id=NEW.credential_id AND enrollment_request_digest=NEW.request_digest AND enrollment_result_digest=NEW.result_digest) THEN
      RAISE EXCEPTION 'Connector enrollment was not atomically consumed' USING ERRCODE='23514';
    END IF;
  ELSIF NEW.origin_kind = 'reissue' THEN
    IF NOT EXISTS (SELECT 1 FROM agent.connector_credential_reissue_intents WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id AND operation_id=NEW.origin_operation_id AND status='consumed' AND credential_id=NEW.credential_id AND current_credential_id=NEW.predecessor_credential_id AND request_digest=NEW.request_digest AND result_digest=NEW.result_digest) THEN
      RAISE EXCEPTION 'Connector credential reissue was not atomically consumed' USING ERRCODE='23514';
    END IF;
  ELSIF NOT EXISTS (SELECT 1 FROM agent.connector_control_credential_rotations WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id AND successor_credential_id=NEW.credential_id AND request_id=NEW.origin_operation_id AND request_digest=NEW.request_digest AND result_digest=NEW.result_digest) THEN
    RAISE EXCEPTION 'Connector rotation was not atomically recorded' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION agent.enforce_connector_credential_revision_insert()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE previous agent.connector_control_credential_revisions%ROWTYPE;
DECLARE head_revision bigint; DECLARE high_water bigint; DECLARE connector_generation bigint;
DECLARE pending_generation bigint; DECLARE pending_predecessor uuid;
BEGIN
  PERFORM connector_id FROM agent.connector_instances WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Connector credential target is unavailable' USING ERRCODE='23503'; END IF;
  SELECT generation INTO connector_generation FROM agent.connector_instances WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id;
  SELECT current_revision INTO head_revision FROM agent.connector_control_credential_heads WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id;
  SELECT max(authorization_revision) INTO high_water FROM agent.connector_control_credential_revisions WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id;
  IF head_revision IS NULL THEN RETURN NEW; END IF;
  IF high_water IS DISTINCT FROM head_revision OR NEW.authorization_revision <> head_revision + 1 THEN RAISE EXCEPTION 'Connector credential authorization is not contiguous' USING ERRCODE='23514'; END IF;
  SELECT * INTO STRICT previous FROM agent.connector_control_credential_revisions WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id AND authorization_revision=head_revision;
  IF previous.lifecycle='revoked' THEN RAISE EXCEPTION 'revoked Connector credentials cannot advance' USING ERRCODE='23514'; END IF;
  IF NEW.cause_kind IN ('reissue_started','rotation_started') THEN
    SELECT connector_generation, predecessor_credential_id INTO pending_generation,pending_predecessor FROM agent.connector_control_credentials WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id AND credential_id=NEW.pending_credential_id;
    IF previous.pending_credential_id IS NOT NULL OR NEW.lifecycle <> 'active' OR NEW.current_credential_id <> previous.current_credential_id OR NEW.pending_credential_id IS NULL OR NEW.connector_generation <> connector_generation OR pending_predecessor IS DISTINCT FROM previous.current_credential_id THEN RAISE EXCEPTION 'invalid pending Connector credential' USING ERRCODE='23514'; END IF;
    IF (NEW.cause_kind='reissue_started' AND (pending_generation <> previous.connector_generation OR NOT EXISTS (SELECT 1 FROM agent.connector_credential_reissue_intents WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id AND operation_id=NEW.cause_operation_id AND credential_id=NEW.pending_credential_id AND status='consumed')))
      OR (NEW.cause_kind='rotation_started' AND pending_generation <> previous.connector_generation + 1) THEN RAISE EXCEPTION 'pending Connector credential has the wrong fence' USING ERRCODE='23514'; END IF;
  ELSIF NEW.cause_kind IN ('reissue_promoted','rotation_promoted') THEN
    IF previous.pending_credential_id IS NULL OR NEW.lifecycle<>'active' OR NEW.current_credential_id<>previous.pending_credential_id OR NEW.pending_credential_id IS NOT NULL OR NEW.connector_generation<>connector_generation THEN RAISE EXCEPTION 'invalid Connector credential promotion' USING ERRCODE='23514'; END IF;
    IF (NEW.cause_kind='reissue_promoted' AND NEW.connector_generation<>previous.connector_generation) OR (NEW.cause_kind='rotation_promoted' AND NEW.connector_generation<>previous.connector_generation+1) THEN RAISE EXCEPTION 'invalid Connector credential promotion generation' USING ERRCODE='23514'; END IF;
  ELSIF NEW.cause_kind='revoked' THEN
    IF NEW.lifecycle<>'revoked' OR NEW.current_credential_id<>previous.current_credential_id OR NEW.pending_credential_id IS DISTINCT FROM previous.pending_credential_id OR NEW.connector_generation<>previous.connector_generation OR NEW.connector_generation<>connector_generation THEN RAISE EXCEPTION 'invalid Connector credential revocation' USING ERRCODE='23514'; END IF;
  ELSE RAISE EXCEPTION 'invalid Connector credential authorization cause' USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $$;

ALTER TABLE agent.connector_control_credential_revisions
  DROP CONSTRAINT connector_credential_revisions_cause_valid,
  ADD CONSTRAINT connector_credential_revisions_cause_valid CHECK (cause_kind IN (
    'enrollment', 'rotation_started', 'rotation_promoted', 'reissue_started', 'reissue_promoted', 'revoked'
  ));

DO $grant$ BEGIN
  IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE ON agent.connector_credential_reissue_intents TO dtx_agent_runtime;
  END IF;
END $grant$;
ALTER TABLE agent.connector_credential_reissue_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_credential_reissue_intents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_credential_reissue_intents
  USING (tenant_id=system.current_tenant_id())
  WITH CHECK (tenant_id=system.current_tenant_id());
