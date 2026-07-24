-- Certificate-only offline Connector recovery. This is intentionally separate from the live
-- RotateCredential command: it preserves the Connector generation/spec/command cursor.
ALTER TABLE agent.connector_control_operations
  DROP CONSTRAINT connector_control_operations_kind_valid,
  ADD CONSTRAINT connector_control_operations_kind_valid CHECK (operation_kind IN (
    'enrollment', 'apply_config', 'rotate_credential', 'close_stream',
    'deliver_agent_provisioning', 'revoke_agent_provisioning',
    'prepare_agent_route_recipient', 'deliver_agent_route_bootstrap',
    'credential_reissue'
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

CREATE FUNCTION agent.enforce_connector_credential_reissue_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  current_host_id uuid;
  current_generation bigint;
  current_spec_revision bigint;
  current_desired_state text;
  authorized_lifecycle text;
  authorized_credential_id uuid;
  authorized_pending_id uuid;
  credential_generation bigint;
  credential_revision bigint;
  credential_fingerprint bytea;
  credential_not_before bigint;
  credential_not_after bigint;
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'Connector credential reissue intents cannot be deleted'
      USING ERRCODE='55000';
  END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.status<>'active' THEN
      RAISE EXCEPTION 'Connector credential reissue intent must begin active'
        USING ERRCODE='23514';
    END IF;
    SELECT host_id,generation,spec_revision,desired_state
      INTO current_host_id,current_generation,current_spec_revision,current_desired_state
      FROM agent.connector_instances
     WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id
     FOR UPDATE;
    SELECT revision.lifecycle,revision.current_credential_id,revision.pending_credential_id
      INTO authorized_lifecycle,authorized_credential_id,authorized_pending_id
      FROM agent.connector_control_credential_heads AS head
      JOIN agent.connector_control_credential_revisions AS revision
        ON revision.tenant_id=head.tenant_id
       AND revision.connector_id=head.connector_id
       AND revision.authorization_revision=head.current_revision
     WHERE head.tenant_id=NEW.tenant_id AND head.connector_id=NEW.connector_id;
    SELECT credential.connector_generation,credential.credential_revision,
           credential.certificate_fingerprint,credential.not_before_ms,
           credential.not_after_ms
      INTO credential_generation,credential_revision,credential_fingerprint,
           credential_not_before,credential_not_after
      FROM agent.connector_control_credentials AS credential
     WHERE credential.tenant_id=NEW.tenant_id
       AND credential.connector_id=NEW.connector_id
       AND credential.credential_id=NEW.current_credential_id;
    IF current_host_id IS NULL
       OR NEW.host_id IS DISTINCT FROM current_host_id
       OR NEW.connector_generation IS DISTINCT FROM current_generation
       OR NEW.spec_revision IS DISTINCT FROM current_spec_revision
       OR current_desired_state='revoked'
       OR authorized_lifecycle IS DISTINCT FROM 'active'
       OR authorized_credential_id IS DISTINCT FROM NEW.current_credential_id
       OR authorized_pending_id IS NOT NULL
       OR credential_generation IS DISTINCT FROM NEW.connector_generation
       OR credential_revision IS DISTINCT FROM NEW.spec_revision
       OR credential_fingerprint IS DISTINCT FROM NEW.current_leaf_fingerprint
       OR NEW.created_at_ms<credential_not_before
       OR NEW.created_at_ms<credential_not_after THEN
      RAISE EXCEPTION 'Connector credential reissue intent has a stale Connector fence'
        USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.status<>'active'
     OR NEW.status NOT IN ('consumed','aborted')
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.intent_id IS DISTINCT FROM OLD.intent_id
     OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
     OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
     OR NEW.host_id IS DISTINCT FROM OLD.host_id
     OR NEW.current_credential_id IS DISTINCT FROM OLD.current_credential_id
     OR NEW.current_leaf_fingerprint IS DISTINCT FROM OLD.current_leaf_fingerprint
     OR NEW.connector_generation IS DISTINCT FROM OLD.connector_generation
     OR NEW.spec_revision IS DISTINCT FROM OLD.spec_revision
     OR NEW.plan_digest IS DISTINCT FROM OLD.plan_digest
     OR NEW.token_digest IS DISTINCT FROM OLD.token_digest
     OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
     OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms THEN
    RAISE EXCEPTION 'invalid Connector credential reissue transition'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER connector_credential_reissue_transition
BEFORE INSERT OR UPDATE OR DELETE ON agent.connector_credential_reissue_intents
FOR EACH ROW EXECUTE FUNCTION agent.enforce_connector_credential_reissue_transition();

CREATE OR REPLACE FUNCTION agent.enforce_connector_control_credential_insert()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  intent_generation bigint;
  intent_spec_revision bigint;
  intent_request_id uuid;
  intent_status text;
  predecessor_generation bigint;
  predecessor_revision bigint;
  predecessor_refresh_key bytea;
  reissue_current uuid;
  reissue_generation bigint;
  reissue_revision bigint;
  reissue_status text;
  reissue_credential uuid;
  reissue_request_digest bytea;
  reissue_result_digest bytea;
BEGIN
  IF NEW.origin_kind='enrollment' THEN
    SELECT connector_generation,spec_revision,request_id,status
      INTO intent_generation,intent_spec_revision,intent_request_id,intent_status
      FROM agent.connector_enrollment_intents
     WHERE tenant_id=NEW.tenant_id
       AND enrollment_intent_id=NEW.enrollment_intent_id
       AND connector_id=NEW.connector_id
     FOR UPDATE;
    IF intent_generation IS NULL OR intent_status<>'active'
       OR NEW.connector_generation IS DISTINCT FROM intent_generation
       OR NEW.credential_revision IS DISTINCT FROM intent_spec_revision
       OR NEW.origin_operation_id IS DISTINCT FROM intent_request_id THEN
      RAISE EXCEPTION 'Connector credential does not match its enrollment intent'
        USING ERRCODE='23514';
    END IF;
  ELSE
    SELECT credential.connector_generation,credential.credential_revision,
           credential.refresh_public_key
      INTO predecessor_generation,predecessor_revision,predecessor_refresh_key
      FROM agent.connector_control_credentials AS credential
     WHERE credential.tenant_id=NEW.tenant_id
       AND credential.connector_id=NEW.connector_id
       AND credential.credential_id=NEW.predecessor_credential_id;
    IF NEW.origin_kind='reissue' THEN
      SELECT current_credential_id,connector_generation,spec_revision,status,
             credential_id,request_digest,result_digest
        INTO reissue_current,reissue_generation,reissue_revision,reissue_status,
             reissue_credential,reissue_request_digest,reissue_result_digest
        FROM agent.connector_credential_reissue_intents
       WHERE tenant_id=NEW.tenant_id
         AND connector_id=NEW.connector_id
         AND operation_id=NEW.origin_operation_id
       FOR UPDATE;
      IF predecessor_generation IS NULL
         OR NEW.connector_generation IS DISTINCT FROM predecessor_generation
         OR NEW.credential_revision IS DISTINCT FROM predecessor_revision
         OR NEW.refresh_public_key IS DISTINCT FROM predecessor_refresh_key
         OR reissue_current IS DISTINCT FROM NEW.predecessor_credential_id
         OR reissue_generation IS DISTINCT FROM NEW.connector_generation
         OR reissue_revision IS DISTINCT FROM NEW.credential_revision
         OR reissue_status IS DISTINCT FROM 'consumed'
         OR reissue_credential IS DISTINCT FROM NEW.credential_id
         OR reissue_request_digest IS DISTINCT FROM NEW.request_digest
         OR reissue_result_digest IS DISTINCT FROM NEW.result_digest THEN
        RAISE EXCEPTION 'Connector reissue credential has the wrong predecessor fence'
          USING ERRCODE='23514';
      END IF;
    ELSIF predecessor_generation IS NULL
       OR NEW.connector_generation IS DISTINCT FROM predecessor_generation+1
       OR NEW.credential_revision<=predecessor_revision
       OR NEW.refresh_public_key IS DISTINCT FROM predecessor_refresh_key THEN
      RAISE EXCEPTION 'Connector rotation credential has the wrong predecessor fence'
        USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END $$;

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
DECLARE
  previous agent.connector_control_credential_revisions%ROWTYPE;
  head_revision bigint;
  high_water bigint;
  connector_generation bigint;
  pending_generation bigint;
  pending_predecessor uuid;
  pending_origin text;
  pending_operation uuid;
  selected_credential_generation bigint;
  selected_credential_origin text;
  selected_credential_operation uuid;
BEGIN
  PERFORM connector_id
    FROM agent.connector_instances
   WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Connector credential target is unavailable' USING ERRCODE='23503';
  END IF;
  SELECT generation INTO connector_generation
    FROM agent.connector_instances
   WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id;
  SELECT current_revision INTO head_revision
    FROM agent.connector_control_credential_heads
   WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id;
  SELECT max(authorization_revision) INTO high_water
    FROM agent.connector_control_credential_revisions
   WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id;
  IF head_revision IS NULL THEN
    SELECT credential.connector_generation,credential.origin_kind,
           credential.origin_operation_id
      INTO selected_credential_generation,selected_credential_origin,
           selected_credential_operation
      FROM agent.connector_control_credentials AS credential
     WHERE credential.tenant_id=NEW.tenant_id
       AND credential.connector_id=NEW.connector_id
       AND credential.credential_id=NEW.current_credential_id;
    IF high_water IS NOT NULL OR NEW.authorization_revision<>1
       OR NEW.lifecycle<>'active' OR NEW.pending_credential_id IS NOT NULL
       OR NEW.cause_kind<>'enrollment'
       OR NEW.connector_generation<>connector_generation
       OR selected_credential_generation IS DISTINCT FROM NEW.connector_generation
       OR selected_credential_origin IS DISTINCT FROM 'enrollment'
       OR selected_credential_operation IS DISTINCT FROM NEW.cause_operation_id THEN
      RAISE EXCEPTION 'invalid initial Connector credential authorization'
        USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  IF high_water IS DISTINCT FROM head_revision
     OR NEW.authorization_revision<>head_revision+1 THEN
    RAISE EXCEPTION 'Connector credential authorization is not contiguous'
      USING ERRCODE='23514';
  END IF;
  SELECT * INTO STRICT previous
    FROM agent.connector_control_credential_revisions
   WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id
     AND authorization_revision=head_revision;
  IF previous.lifecycle='revoked' THEN
    RAISE EXCEPTION 'revoked Connector credentials cannot advance' USING ERRCODE='23514';
  END IF;
  IF NEW.cause_kind IN ('reissue_started','rotation_started') THEN
    SELECT credential.connector_generation,credential.predecessor_credential_id,
           credential.origin_kind,credential.origin_operation_id
      INTO pending_generation,pending_predecessor,pending_origin,pending_operation
      FROM agent.connector_control_credentials AS credential
     WHERE credential.tenant_id=NEW.tenant_id
       AND credential.connector_id=NEW.connector_id
       AND credential.credential_id=NEW.pending_credential_id;
    IF previous.pending_credential_id IS NOT NULL OR NEW.lifecycle<>'active'
       OR NEW.current_credential_id<>previous.current_credential_id
       OR NEW.pending_credential_id IS NULL
       OR NEW.connector_generation<>connector_generation
       OR pending_predecessor IS DISTINCT FROM previous.current_credential_id
       OR pending_operation IS DISTINCT FROM NEW.cause_operation_id THEN
      RAISE EXCEPTION 'invalid pending Connector credential' USING ERRCODE='23514';
    END IF;
    IF NEW.cause_kind='reissue_started' THEN
      IF pending_generation IS DISTINCT FROM previous.connector_generation
         OR pending_origin IS DISTINCT FROM 'reissue'
         OR NOT EXISTS (
           SELECT 1 FROM agent.connector_credential_reissue_intents
            WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id
              AND operation_id=NEW.cause_operation_id
              AND current_credential_id=NEW.current_credential_id
              AND credential_id=NEW.pending_credential_id AND status='consumed'
         ) THEN
        RAISE EXCEPTION 'pending Connector reissue credential has the wrong fence'
          USING ERRCODE='23514';
      END IF;
    ELSIF pending_generation IS DISTINCT FROM previous.connector_generation+1
       OR pending_origin IS DISTINCT FROM 'rotation'
       OR NOT EXISTS (
         SELECT 1 FROM agent.connector_control_credential_rotations
          WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id
            AND current_credential_id=NEW.current_credential_id
            AND successor_credential_id=NEW.pending_credential_id
            AND request_id=NEW.cause_operation_id
       ) THEN
      RAISE EXCEPTION 'pending Connector rotation credential has the wrong fence'
        USING ERRCODE='23514';
    END IF;
  ELSIF NEW.cause_kind IN ('reissue_promoted','rotation_promoted') THEN
    IF previous.pending_credential_id IS NULL OR NEW.lifecycle<>'active'
       OR NEW.current_credential_id<>previous.pending_credential_id
       OR NEW.pending_credential_id IS NOT NULL
       OR NEW.connector_generation<>connector_generation THEN
      RAISE EXCEPTION 'invalid Connector credential promotion' USING ERRCODE='23514';
    END IF;
    IF NEW.cause_kind='reissue_promoted' THEN
      IF NEW.connector_generation<>previous.connector_generation
         OR NOT EXISTS (
           SELECT 1 FROM agent.connector_credential_reissue_intents
            WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id
              AND operation_id=NEW.cause_operation_id
              AND credential_id=NEW.current_credential_id AND status='consumed'
         ) THEN
        RAISE EXCEPTION 'invalid Connector reissue promotion' USING ERRCODE='23514';
      END IF;
    ELSIF NEW.connector_generation<>previous.connector_generation+1
       OR NOT EXISTS (
         SELECT 1 FROM agent.connector_control_credential_rotations
          WHERE tenant_id=NEW.tenant_id AND connector_id=NEW.connector_id
            AND request_id=NEW.cause_operation_id
            AND successor_credential_id=NEW.current_credential_id
       ) THEN
      RAISE EXCEPTION 'invalid Connector rotation promotion' USING ERRCODE='23514';
    END IF;
  ELSIF NEW.cause_kind='revoked' THEN
    IF NEW.lifecycle<>'revoked'
       OR NEW.current_credential_id<>previous.current_credential_id
       OR NEW.pending_credential_id IS DISTINCT FROM previous.pending_credential_id
       OR NEW.connector_generation<>previous.connector_generation
       OR NEW.connector_generation<>connector_generation THEN
      RAISE EXCEPTION 'invalid Connector credential revocation' USING ERRCODE='23514';
    END IF;
  ELSE
    RAISE EXCEPTION 'invalid Connector credential authorization cause' USING ERRCODE='23514';
  END IF;
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

REVOKE ALL ON FUNCTION agent.enforce_connector_credential_reissue_transition() FROM PUBLIC;
CREATE SCHEMA realtime;

CREATE FUNCTION realtime.runtime_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT pg_has_role(session_user, 'dtx_realtime_sync_runtime', 'MEMBER')
       AND NOT pg_has_role(session_user, 'dtx_mailbox_runtime', 'MEMBER')
       AND NOT pg_has_role(session_user, 'dtx_identity_runtime', 'MEMBER')
$$;

REVOKE ALL ON FUNCTION realtime.runtime_authorized() FROM PUBLIC;

CREATE FUNCTION identity.identity_realtime_reader_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT COALESCE(
        pg_has_role(current_user, to_regrole('dtx_realtime_sync_runtime'), 'MEMBER'),
        false
    )
$$;

REVOKE ALL ON FUNCTION identity.identity_realtime_reader_authorized() FROM PUBLIC;

ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_realtime_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_realtime_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());
ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (identity.identity_runtime_authorized()
        OR identity.identity_mailbox_reader_authorized()
        OR identity.identity_realtime_reader_authorized()
        OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

CREATE TABLE messaging.identity_delivery_heads (
    identity_id text PRIMARY KEY REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
    next_sequence bigint NOT NULL DEFAULT 0 CHECK (next_sequence BETWEEN 0 AND 9007199254740991)
);

CREATE TABLE messaging.identity_delivery_journal (
    identity_id text NOT NULL,
    delivery_sequence bigint NOT NULL CHECK (delivery_sequence BETWEEN 1 AND 9007199254740991),
    mailbox_id uuid NOT NULL,
    envelope_id uuid NOT NULL,
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, delivery_sequence),
    UNIQUE (mailbox_id, envelope_id),
    FOREIGN KEY (identity_id) REFERENCES messaging.identity_delivery_heads(identity_id) ON DELETE RESTRICT,
    FOREIGN KEY (mailbox_id, envelope_id) REFERENCES messaging.mailbox_envelopes(mailbox_id, envelope_id) ON DELETE RESTRICT,
    CHECK (expires_at_ms > created_at_ms)
);

CREATE TABLE messaging.device_delivery_state (
    identity_id text NOT NULL,
    device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(device_id)),
    contiguous_ack_sequence bigint NOT NULL DEFAULT 0 CHECK (contiguous_ack_sequence BETWEEN 0 AND 9007199254740991),
    earliest_authorized_sequence bigint NOT NULL CHECK (earliest_authorized_sequence BETWEEN 1 AND 9007199254740991),
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, device_id),
    FOREIGN KEY (identity_id) REFERENCES messaging.identity_delivery_heads(identity_id) ON DELETE RESTRICT
);

CREATE TABLE messaging.device_delivery_ack_claims (
    identity_id text NOT NULL,
    device_id uuid NOT NULL,
    idempotency_key_hash bytea NOT NULL CHECK (octet_length(idempotency_key_hash)=32),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    ack_sequence bigint NOT NULL CHECK (ack_sequence BETWEEN 0 AND 9007199254740991),
    receipt_bytes bytea NOT NULL CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 16384),
    receipt_hash bytea NOT NULL CHECK (octet_length(receipt_hash)=32),
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, device_id, idempotency_key_hash),
    FOREIGN KEY (identity_id, device_id) REFERENCES messaging.device_delivery_state(identity_id, device_id) ON DELETE RESTRICT
);

CREATE TABLE messaging.device_history_grants (
    identity_id text NOT NULL,
    new_device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(new_device_id)),
    identity_head bytea NOT NULL CHECK (octet_length(identity_head)=32),
    earliest_sequence bigint NOT NULL CHECK (earliest_sequence BETWEEN 1 AND 9007199254740991),
    encrypted_history_digest bytea NOT NULL CHECK (octet_length(encrypted_history_digest)=32),
    authorization_kind text NOT NULL CHECK (authorization_kind IN ('grantor_device','recovery','root')),
    authorizer_id text NOT NULL CHECK (octet_length(authorizer_id) BETWEEN 8 AND 128),
    new_device_pop_digest bytea NOT NULL CHECK (octet_length(new_device_pop_digest)=32),
    canonical_grant bytea NOT NULL CHECK (octet_length(canonical_grant) BETWEEN 1 AND 16384),
    grant_digest bytea NOT NULL CHECK (octet_length(grant_digest)=32),
    signature bytea NOT NULL CHECK (octet_length(signature)=64),
    new_device_pop_signature bytea NOT NULL CHECK (octet_length(new_device_pop_signature)=64),
    granted_at_ms bigint NOT NULL,
    revoked_at_ms bigint,
    PRIMARY KEY (identity_id, new_device_id),
    FOREIGN KEY (identity_id) REFERENCES messaging.identity_delivery_heads(identity_id) ON DELETE RESTRICT,
    CHECK (revoked_at_ms IS NULL OR revoked_at_ms >= granted_at_ms)
);

CREATE TABLE realtime.identity_heads (
    identity_id text PRIMARY KEY REFERENCES identity.log_heads(identity_id) ON DELETE RESTRICT,
    next_cursor bigint NOT NULL DEFAULT 0 CHECK (next_cursor BETWEEN 0 AND 9007199254740991),
    journal_floor bigint NOT NULL DEFAULT 1 CHECK (journal_floor BETWEEN 1 AND 9007199254740991)
);

CREATE TABLE realtime.journal (
    identity_id text NOT NULL,
    cursor bigint NOT NULL CHECK (cursor BETWEEN 1 AND 9007199254740991),
    event_kind text NOT NULL CHECK (event_kind IN ('mailbox_delivery','conversation_read','durable_invalidation')),
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest)=32),
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, cursor),
    FOREIGN KEY (identity_id) REFERENCES realtime.identity_heads(identity_id) ON DELETE RESTRICT,
    CHECK (expires_at_ms > created_at_ms)
);

CREATE TABLE realtime.outbox (
    identity_id text NOT NULL,
    cursor bigint NOT NULL,
    published_at_ms bigint,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1000),
    PRIMARY KEY (identity_id, cursor),
    FOREIGN KEY (identity_id, cursor) REFERENCES realtime.journal(identity_id, cursor) ON DELETE RESTRICT
);

CREATE TABLE realtime.device_sync_acks (
    identity_id text NOT NULL,
    device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(device_id)),
    ack_cursor bigint NOT NULL DEFAULT 0 CHECK (ack_cursor BETWEEN 0 AND 9007199254740991),
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, device_id),
    FOREIGN KEY (identity_id) REFERENCES realtime.identity_heads(identity_id) ON DELETE RESTRICT
);

CREATE TABLE realtime.device_leases (
    identity_id text NOT NULL,
    device_id uuid NOT NULL CHECK (messaging.is_uuid_v7(device_id)),
    lease_id uuid NOT NULL CHECK (messaging.is_uuid_v7(lease_id)),
    fence bigint NOT NULL CHECK (fence BETWEEN 1 AND 9007199254740991),
    heartbeat_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, device_id),
    UNIQUE (lease_id),
    FOREIGN KEY (identity_id) REFERENCES realtime.identity_heads(identity_id) ON DELETE RESTRICT,
    CHECK (expires_at_ms = heartbeat_at_ms + 45000)
);

CREATE TABLE realtime.encrypted_account_read_cursors (
    identity_id text NOT NULL,
    conversation_digest bytea NOT NULL CHECK (octet_length(conversation_digest)=32),
    encrypted_cursor bytea NOT NULL CHECK (octet_length(encrypted_cursor) BETWEEN 1 AND 4096),
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    updated_by_device uuid NOT NULL CHECK (messaging.is_uuid_v7(updated_by_device)),
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, conversation_digest),
    FOREIGN KEY (identity_id) REFERENCES realtime.identity_heads(identity_id) ON DELETE RESTRICT
);

REVOKE ALL ON SCHEMA realtime FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA realtime FROM PUBLIC;
REVOKE ALL ON messaging.identity_delivery_heads, messaging.identity_delivery_journal,
    messaging.device_delivery_state, messaging.device_delivery_ack_claims,
    messaging.device_history_grants FROM PUBLIC;

DO $grants$
BEGIN
    IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION identity.identity_realtime_reader_authorized() TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT, UPDATE ON messaging.identity_delivery_heads TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON messaging.identity_delivery_journal TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT, UPDATE ON messaging.device_delivery_state TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON messaging.device_delivery_ack_claims TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT, UPDATE ON messaging.device_history_grants TO dtx_mailbox_runtime;
        GRANT USAGE ON SCHEMA realtime TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT, UPDATE ON realtime.identity_heads TO dtx_mailbox_runtime;
        GRANT SELECT, INSERT ON realtime.journal, realtime.outbox TO dtx_mailbox_runtime;
    END IF;
    IF to_regrole('dtx_realtime_sync_runtime') IS NOT NULL THEN
        -- `messaging` schema visibility is required only so startup can prove
        -- that the gateway has no mailbox payload table privilege.
        GRANT USAGE ON SCHEMA realtime, identity, messaging TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION realtime.runtime_authorized() TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION messaging.is_uuid_v7(uuid) TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_runtime_authorized() TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_owner_authorized() TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_realtime_reader_authorized() TO dtx_realtime_sync_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_mailbox_reader_authorized() TO dtx_realtime_sync_runtime;
        GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries TO dtx_realtime_sync_runtime;
        GRANT SELECT ON realtime.identity_heads, realtime.journal TO dtx_realtime_sync_runtime;
        GRANT SELECT, INSERT, UPDATE ON realtime.device_sync_acks, realtime.device_leases TO dtx_realtime_sync_runtime;
    END IF;
END
$grants$;
