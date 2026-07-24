CREATE TRIGGER connector_control_credentials_append_only
BEFORE UPDATE OR DELETE ON agent.connector_control_credentials
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

ALTER TABLE agent.connector_enrollment_intents
    ADD CONSTRAINT connector_enrollment_intents_credential_fk
    FOREIGN KEY (tenant_id, connector_id, credential_id)
    REFERENCES agent.connector_control_credentials (tenant_id, connector_id, credential_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE agent.connector_control_credential_rotations (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    rotation_sequence bigint NOT NULL,
    request_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    result_digest bytea NOT NULL,
    current_credential_id uuid NOT NULL,
    successor_credential_id uuid NOT NULL,
    command_sequence bigint NOT NULL,
    command_payload_digest bytea NOT NULL,
    nonce bytea NOT NULL,
    accepted_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id, rotation_sequence),
    CONSTRAINT connector_credential_rotations_request_unique
        UNIQUE (tenant_id, request_id),
    CONSTRAINT connector_credential_rotations_successor_unique
        UNIQUE (tenant_id, connector_id, successor_credential_id),
    CONSTRAINT connector_credential_rotations_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_credential_rotations_current_fk
        FOREIGN KEY (tenant_id, connector_id, current_credential_id)
        REFERENCES agent.connector_control_credentials (tenant_id, connector_id, credential_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_credential_rotations_successor_fk
        FOREIGN KEY (tenant_id, connector_id, successor_credential_id)
        REFERENCES agent.connector_control_credentials (tenant_id, connector_id, credential_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_credential_rotations_sequence_safe
        CHECK (rotation_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_credential_rotations_request_id_v7
        CHECK (system.is_uuid_v7(request_id)),
    CONSTRAINT connector_credential_rotations_request_digest_valid
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT connector_credential_rotations_result_digest_valid
        CHECK (octet_length(result_digest) = 32),
    CONSTRAINT connector_credential_rotations_distinct_credentials
        CHECK (current_credential_id <> successor_credential_id),
    CONSTRAINT connector_credential_rotations_command_sequence_safe
        CHECK (command_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_credential_rotations_command_digest_valid
        CHECK (octet_length(command_payload_digest) = 32),
    CONSTRAINT connector_credential_rotations_nonce_valid
        CHECK (octet_length(nonce) = 32),
    CONSTRAINT connector_credential_rotations_accepted_at_valid
        CHECK (accepted_at_ms BETWEEN 0 AND 9007199254740991)
);

CREATE FUNCTION agent.enforce_connector_credential_rotation_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    high_water bigint;
    current_generation bigint;
    current_revision bigint;
    successor_generation bigint;
    successor_revision bigint;
    successor_origin text;
    successor_predecessor uuid;
    successor_operation uuid;
    successor_request_digest bytea;
    successor_result_digest bytea;
BEGIN
    PERFORM connector_id
      FROM agent.connector_instances
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Connector credential rotation target is unavailable'
            USING ERRCODE = '23503';
    END IF;
    SELECT max(rotation_sequence)
      INTO high_water
      FROM agent.connector_control_credential_rotations
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id;
    IF NEW.rotation_sequence <> COALESCE(high_water + 1, 1) THEN
        RAISE EXCEPTION 'Connector credential rotations are not contiguous'
            USING ERRCODE = '23514';
    END IF;
    SELECT connector_generation, credential_revision
      INTO current_generation, current_revision
      FROM agent.connector_control_credentials
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id
       AND credential_id = NEW.current_credential_id;
    SELECT connector_generation, credential_revision, origin_kind,
           predecessor_credential_id, origin_operation_id,
           request_digest, result_digest
      INTO successor_generation, successor_revision, successor_origin,
           successor_predecessor, successor_operation,
           successor_request_digest, successor_result_digest
      FROM agent.connector_control_credentials
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id
       AND credential_id = NEW.successor_credential_id;
    IF current_generation IS NULL
       OR successor_generation IS NULL
       OR successor_generation <> current_generation + 1
       OR successor_revision <= current_revision
       OR successor_origin <> 'rotation'
       OR successor_predecessor <> NEW.current_credential_id
       OR successor_operation <> NEW.request_id
       OR successor_request_digest <> NEW.request_digest
       OR successor_result_digest <> NEW.result_digest THEN
        RAISE EXCEPTION 'Connector credential rotation does not match its exact successor'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_credential_rotation_insert
BEFORE INSERT ON agent.connector_control_credential_rotations
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_credential_rotation_insert();

CREATE TRIGGER connector_credential_rotations_append_only
BEFORE UPDATE OR DELETE ON agent.connector_control_credential_rotations
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE FUNCTION agent.enforce_connector_enrollment_consumed()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.origin_kind = 'enrollment' THEN
        IF NOT EXISTS (
            SELECT 1
             FROM agent.connector_enrollment_intents
            WHERE tenant_id = NEW.tenant_id
              AND enrollment_intent_id = NEW.enrollment_intent_id
              AND connector_id = NEW.connector_id
              AND status = 'consumed'
              AND credential_id = NEW.credential_id
              AND enrollment_request_digest = NEW.request_digest
              AND enrollment_result_digest = NEW.result_digest
        ) THEN
            RAISE EXCEPTION 'Connector enrollment was not atomically consumed'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1
          FROM agent.connector_control_credential_rotations
         WHERE tenant_id = NEW.tenant_id
           AND connector_id = NEW.connector_id
           AND successor_credential_id = NEW.credential_id
           AND request_id = NEW.origin_operation_id
           AND request_digest = NEW.request_digest
           AND result_digest = NEW.result_digest
    ) THEN
        RAISE EXCEPTION 'Connector rotation was not atomically recorded'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER connector_enrollment_consumed
AFTER INSERT ON agent.connector_control_credentials
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_enrollment_consumed();

CREATE TABLE agent.connector_control_credential_revisions (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    authorization_revision bigint NOT NULL,
    connector_generation bigint NOT NULL,
    lifecycle text NOT NULL,
    current_credential_id uuid NOT NULL,
    pending_credential_id uuid,
    cause_kind text NOT NULL,
    cause_operation_id uuid NOT NULL,
    recorded_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id, authorization_revision),
    CONSTRAINT connector_credential_revisions_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_credential_revisions_current_fk
        FOREIGN KEY (tenant_id, connector_id, current_credential_id)
        REFERENCES agent.connector_control_credentials (tenant_id, connector_id, credential_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_credential_revisions_pending_fk
        FOREIGN KEY (tenant_id, connector_id, pending_credential_id)
        REFERENCES agent.connector_control_credentials (tenant_id, connector_id, credential_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_credential_revisions_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT connector_credential_revisions_connector_id_v7
        CHECK (system.is_uuid_v7(connector_id)),
    CONSTRAINT connector_credential_revisions_revision_safe
        CHECK (authorization_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_credential_revisions_generation_safe
        CHECK (connector_generation BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_credential_revisions_lifecycle_valid
        CHECK (lifecycle IN ('active', 'revoked')),
    CONSTRAINT connector_credential_revisions_distinct_credentials
        CHECK (pending_credential_id IS NULL OR pending_credential_id <> current_credential_id),
    CONSTRAINT connector_credential_revisions_cause_valid
        CHECK (cause_kind IN ('enrollment', 'rotation_started', 'rotation_promoted', 'revoked')),
    CONSTRAINT connector_credential_revisions_cause_operation_id_v7
        CHECK (system.is_uuid_v7(cause_operation_id)),
    CONSTRAINT connector_credential_revisions_recorded_at_valid
        CHECK (recorded_at_ms BETWEEN 0 AND 9007199254740991)
);

CREATE TRIGGER connector_credential_revisions_append_only
BEFORE UPDATE OR DELETE ON agent.connector_control_credential_revisions
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.connector_control_credential_heads (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    current_revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id),
    CONSTRAINT connector_credential_heads_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_credential_heads_revision_fk
        FOREIGN KEY (tenant_id, connector_id, current_revision)
        REFERENCES agent.connector_control_credential_revisions
            (tenant_id, connector_id, authorization_revision)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_credential_heads_revision_safe
        CHECK (current_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_credential_heads_created_at_valid
        CHECK (created_at_ms BETWEEN 0 AND 9007199254740991),
    CONSTRAINT connector_credential_heads_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 9007199254740991)
);

CREATE FUNCTION agent.enforce_connector_credential_revision_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    head_revision bigint;
    high_water bigint;
    connector_generation bigint;
    previous agent.connector_control_credential_revisions%ROWTYPE;
    pending_generation bigint;
    pending_predecessor uuid;
    selected_credential_generation bigint;
    selected_credential_origin text;
    selected_credential_operation uuid;
BEGIN
    PERFORM connector_id
      FROM agent.connector_instances
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Connector credential target is unavailable'
            USING ERRCODE = '23503';
    END IF;

    SELECT generation
      INTO connector_generation
      FROM agent.connector_instances
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id;
    SELECT current_revision
      INTO head_revision
      FROM agent.connector_control_credential_heads
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id;
    SELECT max(authorization_revision)
      INTO high_water
      FROM agent.connector_control_credential_revisions
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id;

    IF head_revision IS NULL THEN
        SELECT credential.connector_generation,
               credential.origin_kind,
               credential.origin_operation_id
          INTO selected_credential_generation, selected_credential_origin,
               selected_credential_operation
          FROM agent.connector_control_credentials AS credential
         WHERE credential.tenant_id = NEW.tenant_id
           AND credential.connector_id = NEW.connector_id
           AND credential.credential_id = NEW.current_credential_id;
        IF high_water IS NOT NULL
           OR NEW.authorization_revision <> 1
           OR NEW.lifecycle <> 'active'
           OR NEW.pending_credential_id IS NOT NULL
           OR NEW.cause_kind <> 'enrollment'
           OR NEW.connector_generation <> connector_generation
           OR selected_credential_generation IS DISTINCT FROM NEW.connector_generation
           OR selected_credential_origin IS DISTINCT FROM 'enrollment'
           OR selected_credential_operation IS DISTINCT FROM NEW.cause_operation_id THEN
            RAISE EXCEPTION 'invalid initial Connector credential authorization'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF high_water IS DISTINCT FROM head_revision
       OR NEW.authorization_revision <> head_revision + 1 THEN
        RAISE EXCEPTION 'Connector credential authorization is not contiguous'
            USING ERRCODE = '23514';
    END IF;
    SELECT * INTO STRICT previous
      FROM agent.connector_control_credential_revisions
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id
       AND authorization_revision = head_revision;
    IF previous.lifecycle = 'revoked' THEN
        RAISE EXCEPTION 'revoked Connector credentials cannot advance'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.cause_kind = 'rotation_started' THEN
        IF previous.pending_credential_id IS NOT NULL
           OR NEW.lifecycle <> 'active'
           OR NEW.current_credential_id <> previous.current_credential_id
           OR NEW.pending_credential_id IS NULL
           OR NEW.connector_generation <> previous.connector_generation
           OR NEW.connector_generation <> connector_generation THEN
            RAISE EXCEPTION 'invalid Connector credential rotation start'
                USING ERRCODE = '23514';
        END IF;
        SELECT credential.connector_generation,
               credential.predecessor_credential_id
          INTO pending_generation, pending_predecessor
          FROM agent.connector_control_credentials AS credential
         WHERE credential.tenant_id = NEW.tenant_id
           AND credential.connector_id = NEW.connector_id
           AND credential.credential_id = NEW.pending_credential_id;
        IF pending_generation IS DISTINCT FROM previous.connector_generation + 1
           OR pending_predecessor IS DISTINCT FROM previous.current_credential_id
           OR NOT EXISTS (
               SELECT 1
                 FROM agent.connector_control_credential_rotations
                WHERE tenant_id = NEW.tenant_id
                  AND connector_id = NEW.connector_id
                  AND current_credential_id = NEW.current_credential_id
                  AND successor_credential_id = NEW.pending_credential_id
                  AND request_id = NEW.cause_operation_id
           ) THEN
            RAISE EXCEPTION 'pending Connector credential has the wrong fence'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.cause_kind = 'rotation_promoted' THEN
        IF previous.pending_credential_id IS NULL
           OR NEW.lifecycle <> 'active'
           OR NEW.current_credential_id <> previous.pending_credential_id
           OR NEW.pending_credential_id IS NOT NULL
           OR NEW.connector_generation <> previous.connector_generation + 1
           OR NEW.connector_generation <> connector_generation THEN
            RAISE EXCEPTION 'invalid Connector credential promotion'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.cause_kind = 'revoked' THEN
        IF NEW.lifecycle <> 'revoked'
           OR NEW.current_credential_id <> previous.current_credential_id
           OR NEW.pending_credential_id IS DISTINCT FROM previous.pending_credential_id
           OR NEW.connector_generation <> previous.connector_generation
           OR NEW.connector_generation <> connector_generation THEN
            RAISE EXCEPTION 'invalid Connector credential revocation'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid Connector credential authorization cause'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_credential_revision_insert
BEFORE INSERT ON agent.connector_control_credential_revisions
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_credential_revision_insert();

CREATE FUNCTION agent.enforce_connector_credential_revision_published()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM agent.connector_control_credential_heads
         WHERE tenant_id = NEW.tenant_id
           AND connector_id = NEW.connector_id
           AND current_revision >= NEW.authorization_revision
    ) THEN
        RAISE EXCEPTION 'Connector credential authorization revision was not published'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER connector_credential_revision_published
AFTER INSERT ON agent.connector_control_credential_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_credential_revision_published();

CREATE FUNCTION agent.enforce_connector_credential_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Connector credential authorization heads cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.current_revision <> 1 THEN
            RAISE EXCEPTION 'Connector credential authorization must begin at revision one'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.current_revision <> OLD.current_revision + 1
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Connector credential authorization head transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_credential_head_transition
BEFORE INSERT OR UPDATE OR DELETE ON agent.connector_control_credential_heads
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_credential_head_transition();

CREATE FUNCTION agent.connector_runtime_name_valid(candidate text, maximum_bytes integer)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT octet_length(candidate) BETWEEN 1 AND maximum_bytes
       AND candidate ~ '^[a-z0-9][a-z0-9._/:-]*$'
$$;

CREATE FUNCTION agent.connector_claim_codes_valid(candidates text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT cardinality(candidates) <= 64
       AND array_position(candidates, NULL) IS NULL
       AND NOT EXISTS (
            SELECT 1 FROM unnest(candidates) value
             WHERE NOT agent.connector_runtime_name_valid(value, 128)
       )
       AND cardinality(candidates) = (SELECT count(DISTINCT value) FROM unnest(candidates) value)
$$;

CREATE FUNCTION agent.connector_run_ids_valid(candidates uuid[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT cardinality(candidates) <= 1024
       AND array_position(candidates, NULL) IS NULL
       AND NOT EXISTS (
           SELECT 1 FROM unnest(candidates) value
            WHERE NOT system.is_uuid_v7(value)
       )
       AND cardinality(candidates) = (SELECT count(DISTINCT value) FROM unnest(candidates) value)
$$;

CREATE FUNCTION agent.connector_runtime_error_code_valid(candidate text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT octet_length(candidate) BETWEEN 3 AND 64
       AND candidate ~ '^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$'
$$;

CREATE TABLE agent.connector_runtime_claims (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    claim_revision bigint NOT NULL,
    lease_id uuid NOT NULL,
    boot_id uuid NOT NULL,
    connector_generation bigint NOT NULL,
    source_kind text NOT NULL,
    heartbeat_sequence bigint,
    runtime_kind text NOT NULL,
    runtime_version text NOT NULL,
    adapter_build_digest bytea NOT NULL,
    capability_codes text[] NOT NULL,
    active_run_ids uuid[] NOT NULL,
    queue_depth bigint NOT NULL,
    maximum_concurrent_runs bigint NOT NULL,
    available_concurrent_runs bigint NOT NULL,
    maximum_queue_depth bigint NOT NULL,
    stable_error_code text,
    claim_digest bytea NOT NULL,
    observed_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id, claim_revision),
    CONSTRAINT connector_runtime_claims_lease_fk
        FOREIGN KEY (tenant_id, connector_id, lease_id, boot_id, connector_generation)
        REFERENCES agent.connector_leases
            (tenant_id, connector_id, lease_id, boot_id, generation)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_runtime_claims_heartbeat_unique
        UNIQUE (tenant_id, connector_id, lease_id, heartbeat_sequence),
    CONSTRAINT connector_runtime_claims_revision_safe
        CHECK (claim_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_runtime_claims_generation_safe
        CHECK (connector_generation BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_runtime_claims_source_valid
        CHECK (
            (source_kind = 'hello' AND heartbeat_sequence IS NULL)
            OR (
                source_kind = 'heartbeat'
                AND heartbeat_sequence BETWEEN 1 AND 9007199254740991
            )
        ),
    CONSTRAINT connector_runtime_claims_runtime_kind_valid
        CHECK (agent.connector_runtime_name_valid(runtime_kind, 64)),
    CONSTRAINT connector_runtime_claims_runtime_version_valid
        CHECK (octet_length(runtime_version) BETWEEN 1 AND 128),
    CONSTRAINT connector_runtime_claims_adapter_digest_valid
        CHECK (octet_length(adapter_build_digest) = 32),
    CONSTRAINT connector_runtime_claims_capabilities_valid
        CHECK (agent.connector_claim_codes_valid(capability_codes)),
    CONSTRAINT connector_runtime_claims_active_runs_valid
        CHECK (agent.connector_run_ids_valid(active_run_ids)),
    CONSTRAINT connector_runtime_claims_queue_depth_valid
        CHECK (queue_depth BETWEEN 0 AND maximum_queue_depth),
    CONSTRAINT connector_runtime_claims_concurrency_capacity_valid
        CHECK (
            maximum_concurrent_runs BETWEEN 1 AND 65535
            AND available_concurrent_runs BETWEEN 0 AND maximum_concurrent_runs
        ),
    CONSTRAINT connector_runtime_claims_queue_capacity_valid
        CHECK (maximum_queue_depth BETWEEN 1 AND 1000000),
    CONSTRAINT connector_runtime_claims_error_code_valid
        CHECK (
            stable_error_code IS NULL
            OR agent.connector_runtime_error_code_valid(stable_error_code)
        ),
    CONSTRAINT connector_runtime_claims_digest_valid
        CHECK (octet_length(claim_digest) = 32),
    CONSTRAINT connector_runtime_claims_observed_at_valid
        CHECK (observed_at_ms BETWEEN 0 AND 9007199254740991)
);

CREATE UNIQUE INDEX connector_runtime_claims_hello_unique
    ON agent.connector_runtime_claims (tenant_id, connector_id, lease_id)
    WHERE source_kind = 'hello';

-- Runtime claims are immutable observations, but old observations are
-- deliberately deleted by the bounded-retention writer after the head moves.
CREATE TRIGGER connector_runtime_claims_immutable
BEFORE UPDATE ON agent.connector_runtime_claims
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.connector_runtime_claim_heads (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    current_claim_revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id),
    CONSTRAINT connector_runtime_claim_heads_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_runtime_claim_heads_claim_fk
        FOREIGN KEY (tenant_id, connector_id, current_claim_revision)
        REFERENCES agent.connector_runtime_claims (tenant_id, connector_id, claim_revision)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_runtime_claim_heads_revision_safe
        CHECK (current_claim_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_runtime_claim_heads_created_at_valid
        CHECK (created_at_ms BETWEEN 0 AND 9007199254740991),
    CONSTRAINT connector_runtime_claim_heads_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 9007199254740991)
);

CREATE FUNCTION agent.enforce_connector_runtime_claim_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    head_revision bigint;
    high_water bigint;
    configured_capacity bigint;
    lease_status text;
    lease_generation bigint;
    lease_heartbeat_sequence bigint;
    lease_capacity_available bigint;
    lease_issued_at_ms bigint;
    lease_heartbeat_at_ms bigint;
BEGIN
    SELECT max_concurrency
      INTO configured_capacity
      FROM agent.connector_instances
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id
     FOR UPDATE;
    IF configured_capacity IS NULL THEN
        RAISE EXCEPTION 'Connector runtime claim target is unavailable'
            USING ERRCODE = '23503';
    END IF;
    IF NEW.maximum_concurrent_runs <> configured_capacity THEN
        RAISE EXCEPTION 'Connector runtime capacity mismatches its configured capacity'
            USING ERRCODE = '23514';
    END IF;
    SELECT status, generation, last_heartbeat_sequence, capacity_available,
           issued_at_ms, last_heartbeat_at_ms
      INTO lease_status, lease_generation, lease_heartbeat_sequence,
           lease_capacity_available, lease_issued_at_ms, lease_heartbeat_at_ms
      FROM agent.connector_leases
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id
       AND lease_id = NEW.lease_id
       AND boot_id = NEW.boot_id;
    IF lease_status IS DISTINCT FROM 'active'
       OR lease_generation IS DISTINCT FROM NEW.connector_generation
       OR (
           NEW.source_kind = 'hello'
           AND (
               lease_heartbeat_sequence <> 0
               OR NEW.observed_at_ms < lease_issued_at_ms
           )
       )
       OR (
           NEW.source_kind = 'heartbeat'
           AND (
               lease_heartbeat_sequence IS DISTINCT FROM NEW.heartbeat_sequence
               OR lease_capacity_available IS DISTINCT FROM NEW.available_concurrent_runs
               OR lease_heartbeat_at_ms IS DISTINCT FROM NEW.observed_at_ms
           )
       ) THEN
        RAISE EXCEPTION 'Connector runtime claim has a stale lease or heartbeat fence'
            USING ERRCODE = '23514';
    END IF;
    SELECT current_claim_revision
      INTO head_revision
      FROM agent.connector_runtime_claim_heads
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id;
    SELECT max(claim_revision)
      INTO high_water
      FROM agent.connector_runtime_claims
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id;
    IF high_water IS DISTINCT FROM head_revision
       OR NEW.claim_revision <> COALESCE(head_revision + 1, 1) THEN
        RAISE EXCEPTION 'Connector runtime claim revision is not contiguous'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_runtime_claim_insert
BEFORE INSERT ON agent.connector_runtime_claims
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_runtime_claim_insert();

CREATE FUNCTION agent.enforce_connector_runtime_claim_published()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM agent.connector_runtime_claim_heads
         WHERE tenant_id = NEW.tenant_id
           AND connector_id = NEW.connector_id
           AND current_claim_revision >= NEW.claim_revision
    ) THEN
        RAISE EXCEPTION 'Connector runtime claim revision was not published'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER connector_runtime_claim_published
AFTER INSERT ON agent.connector_runtime_claims
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_runtime_claim_published();

CREATE FUNCTION agent.enforce_connector_runtime_claim_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Connector runtime claim heads cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.current_claim_revision <> 1 THEN
            RAISE EXCEPTION 'Connector runtime claims must begin at revision one'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.current_claim_revision <> OLD.current_claim_revision + 1
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Connector runtime claim head transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_runtime_claim_head_transition
BEFORE INSERT OR UPDATE OR DELETE ON agent.connector_runtime_claim_heads
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_runtime_claim_head_transition();

