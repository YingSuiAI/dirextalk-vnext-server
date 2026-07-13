ALTER TABLE agent.connector_instances
    ADD CONSTRAINT connector_instances_host_scope_unique
    UNIQUE (tenant_id, connector_id, host_id);

ALTER TABLE agent.connector_leases
    ADD CONSTRAINT connector_leases_runtime_fence_unique
    UNIQUE (tenant_id, connector_id, lease_id, boot_id, generation);

CREATE TABLE agent.connector_control_operations (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    operation_kind text NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT connector_control_operations_exact_reference_unique
        UNIQUE (tenant_id, operation_id, connector_id, operation_kind),
    CONSTRAINT connector_control_operations_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_control_operations_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT connector_control_operations_operation_id_v7
        CHECK (system.is_uuid_v7(operation_id)),
    CONSTRAINT connector_control_operations_connector_id_v7
        CHECK (system.is_uuid_v7(connector_id)),
    CONSTRAINT connector_control_operations_kind_valid
        CHECK (operation_kind IN (
            'enrollment', 'apply_config', 'rotate_credential', 'close_stream'
        )),
    CONSTRAINT connector_control_operations_created_at_valid
        CHECK (created_at_ms BETWEEN 0 AND 9007199254740991)
);

CREATE FUNCTION agent.enforce_connector_control_operation_published()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.operation_kind = 'enrollment' THEN
        IF NOT EXISTS (
            SELECT 1
              FROM agent.connector_enrollment_intents
             WHERE tenant_id = NEW.tenant_id
               AND request_id = NEW.operation_id
               AND connector_id = NEW.connector_id
        ) THEN
            RAISE EXCEPTION 'Connector enrollment operation was not published'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1
          FROM agent.connector_control_commands
         WHERE tenant_id = NEW.tenant_id
           AND operation_id = NEW.operation_id
           AND connector_id = NEW.connector_id
           AND command_kind = NEW.operation_kind
    ) THEN
        RAISE EXCEPTION 'Connector command operation was not published'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER connector_control_operation_published
AFTER INSERT ON agent.connector_control_operations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_control_operation_published();

CREATE TRIGGER connector_control_operations_append_only
BEFORE UPDATE OR DELETE ON agent.connector_control_operations
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.connector_enrollment_intents (
    tenant_id uuid NOT NULL,
    enrollment_intent_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    host_id uuid NOT NULL,
    request_id uuid NOT NULL,
    connector_generation bigint NOT NULL,
    spec_revision bigint NOT NULL,
    token_digest bytea NOT NULL,
    status text NOT NULL,
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    transitioned_at_ms bigint,
    enrollment_request_digest bytea,
    enrollment_result_digest bytea,
    credential_id uuid,
    operation_kind text GENERATED ALWAYS AS ('enrollment') STORED,
    PRIMARY KEY (tenant_id, enrollment_intent_id),
    CONSTRAINT connector_enrollment_intents_request_unique
        UNIQUE (tenant_id, request_id),
    CONSTRAINT connector_enrollment_intents_token_unique
        UNIQUE (token_digest),
    CONSTRAINT connector_enrollment_intents_connector_fk
        FOREIGN KEY (tenant_id, connector_id, host_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id, host_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_enrollment_intents_operation_fk
        FOREIGN KEY (tenant_id, request_id, connector_id, operation_kind)
        REFERENCES agent.connector_control_operations
            (tenant_id, operation_id, connector_id, operation_kind)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_enrollment_intents_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT connector_enrollment_intents_id_v7
        CHECK (system.is_uuid_v7(enrollment_intent_id)),
    CONSTRAINT connector_enrollment_intents_connector_id_v7
        CHECK (system.is_uuid_v7(connector_id)),
    CONSTRAINT connector_enrollment_intents_host_id_v7
        CHECK (system.is_uuid_v7(host_id)),
    CONSTRAINT connector_enrollment_intents_request_id_v7
        CHECK (system.is_uuid_v7(request_id)),
    CONSTRAINT connector_enrollment_intents_generation_safe
        CHECK (connector_generation BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_enrollment_intents_spec_revision_safe
        CHECK (spec_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_enrollment_intents_token_digest_valid
        CHECK (octet_length(token_digest) = 32),
    CONSTRAINT connector_enrollment_intents_status_valid
        CHECK (status IN ('active', 'consumed', 'expired', 'revoked')),
    CONSTRAINT connector_enrollment_intents_created_at_valid
        CHECK (created_at_ms BETWEEN 0 AND 9007199254740990),
    CONSTRAINT connector_enrollment_intents_expiry_valid
        CHECK (
            expires_at_ms BETWEEN created_at_ms + 1
                AND LEAST(created_at_ms + 600000, 9007199254740991)
        ),
    CONSTRAINT connector_enrollment_intents_terminal_consistent
        CHECK (
            (
                status = 'active'
                AND transitioned_at_ms IS NULL
                AND enrollment_request_digest IS NULL
                AND enrollment_result_digest IS NULL
                AND credential_id IS NULL
            )
            OR (
                status = 'consumed'
                AND transitioned_at_ms BETWEEN created_at_ms AND expires_at_ms
                AND octet_length(enrollment_request_digest) = 32
                AND octet_length(enrollment_result_digest) = 32
                AND credential_id IS NOT NULL
            )
            OR (
                status = 'expired'
                AND transitioned_at_ms BETWEEN expires_at_ms AND 9007199254740991
                AND enrollment_request_digest IS NULL
                AND enrollment_result_digest IS NULL
                AND credential_id IS NULL
            )
            OR (
                status = 'revoked'
                AND transitioned_at_ms BETWEEN created_at_ms AND expires_at_ms - 1
                AND enrollment_request_digest IS NULL
                AND enrollment_result_digest IS NULL
                AND credential_id IS NULL
            )
        )
);

CREATE UNIQUE INDEX connector_enrollment_one_active_idx
    ON agent.connector_enrollment_intents (tenant_id, connector_id)
    WHERE status = 'active';

CREATE FUNCTION agent.enforce_connector_enrollment_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_host_id uuid;
    current_generation bigint;
    current_spec_revision bigint;
    current_desired_state text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Connector enrollment intents cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'active' THEN
            RAISE EXCEPTION 'Connector enrollment intent must begin active'
                USING ERRCODE = '23514';
        END IF;
        SELECT host_id, generation, spec_revision, desired_state
          INTO current_host_id, current_generation, current_spec_revision,
               current_desired_state
          FROM agent.connector_instances
         WHERE tenant_id = NEW.tenant_id
           AND connector_id = NEW.connector_id
         FOR UPDATE;
        IF current_host_id IS NULL
           OR NEW.host_id IS DISTINCT FROM current_host_id
           OR NEW.connector_generation IS DISTINCT FROM current_generation
           OR NEW.spec_revision IS DISTINCT FROM current_spec_revision
           OR current_desired_state = 'revoked'
           OR EXISTS (
               SELECT 1
                 FROM agent.connector_control_credential_heads
                WHERE tenant_id = NEW.tenant_id
                  AND connector_id = NEW.connector_id
           ) THEN
            RAISE EXCEPTION 'Connector enrollment intent has a stale Connector fence'
                USING ERRCODE = '23514';
        END IF;
        UPDATE agent.connector_enrollment_intents
           SET status = 'expired', transitioned_at_ms = NEW.created_at_ms
         WHERE tenant_id = NEW.tenant_id
           AND connector_id = NEW.connector_id
           AND status = 'active'
           AND expires_at_ms <= NEW.created_at_ms;
        RETURN NEW;
    END IF;
    IF OLD.status <> 'active'
       OR NEW.status NOT IN ('consumed', 'expired', 'revoked')
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.enrollment_intent_id IS DISTINCT FROM OLD.enrollment_intent_id
       OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
       OR NEW.host_id IS DISTINCT FROM OLD.host_id
       OR NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.connector_generation IS DISTINCT FROM OLD.connector_generation
       OR NEW.spec_revision IS DISTINCT FROM OLD.spec_revision
       OR NEW.token_digest IS DISTINCT FROM OLD.token_digest
       OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'invalid Connector enrollment transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_enrollment_transition
BEFORE INSERT OR UPDATE OR DELETE ON agent.connector_enrollment_intents
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_enrollment_transition();

CREATE FUNCTION agent.connector_certificate_chain_valid(chain_der bytea[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT cardinality(chain_der) BETWEEN 1 AND 4
       AND array_position(chain_der, NULL) IS NULL
       AND NOT EXISTS (
           SELECT 1 FROM unnest(chain_der) certificate_der
            WHERE octet_length(certificate_der) NOT BETWEEN 1 AND 16384
       )
       AND (SELECT sum(octet_length(certificate_der)) FROM unnest(chain_der) certificate_der)
           <= 65536
$$;

CREATE TABLE agent.connector_control_credentials (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    connector_generation bigint NOT NULL,
    credential_revision bigint NOT NULL,
    origin_kind text NOT NULL,
    enrollment_intent_id uuid,
    predecessor_credential_id uuid,
    origin_operation_id uuid NOT NULL,
    online_public_key bytea NOT NULL,
    refresh_public_key bytea NOT NULL,
    certificate_fingerprint bytea NOT NULL,
    certificate_chain_der bytea[] NOT NULL,
    not_before_ms bigint NOT NULL,
    not_after_ms bigint NOT NULL,
    request_digest bytea NOT NULL,
    result_digest bytea NOT NULL,
    issued_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id, credential_id),
    CONSTRAINT connector_control_credentials_fingerprint_unique
        UNIQUE (certificate_fingerprint),
    CONSTRAINT connector_control_credentials_control_key_unique
        UNIQUE (online_public_key),
    CONSTRAINT connector_control_credentials_enrollment_unique
        UNIQUE (tenant_id, enrollment_intent_id),
    CONSTRAINT connector_control_credentials_operation_unique
        UNIQUE (tenant_id, origin_operation_id),
    CONSTRAINT connector_control_credentials_generation_unique
        UNIQUE (tenant_id, connector_id, connector_generation),
    CONSTRAINT connector_control_credentials_revision_unique
        UNIQUE (tenant_id, connector_id, credential_revision),
    CONSTRAINT connector_control_credentials_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_control_credentials_operation_fk
        FOREIGN KEY (tenant_id, origin_operation_id)
        REFERENCES agent.connector_control_operations (tenant_id, operation_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_control_credentials_enrollment_fk
        FOREIGN KEY (tenant_id, enrollment_intent_id)
        REFERENCES agent.connector_enrollment_intents (tenant_id, enrollment_intent_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_control_credentials_predecessor_fk
        FOREIGN KEY (tenant_id, connector_id, predecessor_credential_id)
        REFERENCES agent.connector_control_credentials (tenant_id, connector_id, credential_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_control_credentials_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT connector_control_credentials_connector_id_v7
        CHECK (system.is_uuid_v7(connector_id)),
    CONSTRAINT connector_control_credentials_credential_id_v7
        CHECK (system.is_uuid_v7(credential_id)),
    CONSTRAINT connector_control_credentials_generation_safe
        CHECK (connector_generation BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_control_credentials_revision_safe
        CHECK (credential_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_control_credentials_origin_valid
        CHECK (
            (
                origin_kind = 'enrollment'
                AND enrollment_intent_id IS NOT NULL
                AND predecessor_credential_id IS NULL
            )
            OR (
                origin_kind = 'rotation'
                AND enrollment_intent_id IS NULL
                AND predecessor_credential_id IS NOT NULL
            )
        ),
    CONSTRAINT connector_control_credentials_origin_operation_id_v7
        CHECK (system.is_uuid_v7(origin_operation_id)),
    CONSTRAINT connector_control_credentials_online_key_valid
        CHECK (octet_length(online_public_key) = 32),
    CONSTRAINT connector_control_credentials_refresh_key_valid
        CHECK (octet_length(refresh_public_key) = 32),
    CONSTRAINT connector_control_credentials_distinct_keys
        CHECK (online_public_key <> refresh_public_key),
    CONSTRAINT connector_control_credentials_fingerprint_valid
        CHECK (octet_length(certificate_fingerprint) = 32),
    CONSTRAINT connector_control_credentials_chain_valid
        CHECK (agent.connector_certificate_chain_valid(certificate_chain_der)),
    CONSTRAINT connector_control_credentials_not_before_valid
        CHECK (not_before_ms BETWEEN 0 AND 9007199254740990),
    CONSTRAINT connector_control_credentials_not_after_valid
        CHECK (
            not_after_ms BETWEEN not_before_ms + 1
                AND LEAST(not_before_ms + 86400000, 9007199254740991)
        ),
    CONSTRAINT connector_control_credentials_issued_at_valid
        CHECK (issued_at_ms >= not_before_ms AND issued_at_ms < not_after_ms),
    CONSTRAINT connector_control_credentials_request_digest_valid
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT connector_control_credentials_result_digest_valid
        CHECK (octet_length(result_digest) = 32)
);

CREATE FUNCTION agent.enforce_connector_control_credential_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    intent_generation bigint;
    intent_spec_revision bigint;
    intent_request_id uuid;
    intent_status text;
    predecessor_generation bigint;
    predecessor_revision bigint;
    predecessor_refresh_key bytea;
BEGIN
    IF NEW.origin_kind = 'enrollment' THEN
        SELECT connector_generation, spec_revision, request_id, status
          INTO intent_generation, intent_spec_revision, intent_request_id, intent_status
          FROM agent.connector_enrollment_intents
         WHERE tenant_id = NEW.tenant_id
           AND enrollment_intent_id = NEW.enrollment_intent_id
           AND connector_id = NEW.connector_id
         FOR UPDATE;
        IF intent_generation IS NULL
           OR intent_status <> 'active'
           OR NEW.connector_generation IS DISTINCT FROM intent_generation
           OR NEW.credential_revision IS DISTINCT FROM intent_spec_revision
           OR NEW.origin_operation_id IS DISTINCT FROM intent_request_id THEN
            RAISE EXCEPTION 'Connector credential does not match its enrollment intent'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT connector_generation, credential_revision, refresh_public_key
          INTO predecessor_generation, predecessor_revision, predecessor_refresh_key
          FROM agent.connector_control_credentials
         WHERE tenant_id = NEW.tenant_id
           AND connector_id = NEW.connector_id
           AND credential_id = NEW.predecessor_credential_id;
        IF predecessor_generation IS NULL
           OR NEW.connector_generation IS DISTINCT FROM predecessor_generation + 1
           OR NEW.credential_revision <= predecessor_revision
           OR NEW.refresh_public_key IS DISTINCT FROM predecessor_refresh_key THEN
            RAISE EXCEPTION 'Connector rotation credential has the wrong predecessor fence'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_control_credential_insert
BEFORE INSERT ON agent.connector_control_credentials
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_control_credential_insert();

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

CREATE FUNCTION agent.prune_connector_runtime_claim_history(
    candidate_tenant_id uuid,
    candidate_connector_id uuid,
    retention_limit integer
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, agent, system
AS $$
DECLARE
    head_revision bigint;
    retention_floor bigint;
    deleted_count bigint;
BEGIN
    IF candidate_tenant_id IS DISTINCT FROM system.current_tenant_id() THEN
        RAISE EXCEPTION 'runtime claim retention crossed a tenant boundary'
            USING ERRCODE = '42501';
    END IF;
    IF retention_limit NOT BETWEEN 1 AND 4096 THEN
        RAISE EXCEPTION 'runtime claim retention limit is invalid'
            USING ERRCODE = '22023';
    END IF;
    SELECT current_claim_revision
      INTO head_revision
      FROM agent.connector_runtime_claim_heads
     WHERE tenant_id = candidate_tenant_id
       AND connector_id = candidate_connector_id
     FOR UPDATE;
    IF head_revision IS NULL THEN
        RAISE EXCEPTION 'runtime claim retention target is unavailable'
            USING ERRCODE = '23503';
    END IF;
    retention_floor := GREATEST(head_revision - retention_limit + 1, 1);
    DELETE FROM agent.connector_runtime_claims
     WHERE tenant_id = candidate_tenant_id
       AND connector_id = candidate_connector_id
       AND claim_revision < retention_floor;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END
$$;

CREATE TABLE agent.connector_control_stream_heads (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    connector_generation bigint NOT NULL,
    spec_revision bigint NOT NULL,
    state text NOT NULL,
    last_command_sequence bigint NOT NULL DEFAULT 0,
    acknowledged_command_sequence bigint NOT NULL DEFAULT 0,
    acknowledged_payload_digest bytea,
    acknowledged_encoded_command_digest bytea,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id),
    CONSTRAINT connector_control_stream_heads_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_control_stream_heads_generation_safe
        CHECK (connector_generation BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_control_stream_heads_spec_revision_safe
        CHECK (spec_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_control_stream_heads_state_valid
        CHECK (state IN ('active', 'revoked')),
    CONSTRAINT connector_control_stream_heads_last_sequence_safe
        CHECK (last_command_sequence BETWEEN 0 AND 9007199254740991),
    CONSTRAINT connector_control_stream_heads_ack_sequence_safe
        CHECK (
            acknowledged_command_sequence BETWEEN 0 AND last_command_sequence
            AND last_command_sequence - acknowledged_command_sequence <= 4097
        ),
    CONSTRAINT connector_control_stream_heads_ack_digests_consistent
        CHECK (
            (
                acknowledged_command_sequence = 0
                AND acknowledged_payload_digest IS NULL
                AND acknowledged_encoded_command_digest IS NULL
            )
            OR (
                acknowledged_command_sequence > 0
                AND octet_length(acknowledged_payload_digest) = 32
                AND octet_length(acknowledged_encoded_command_digest) = 32
            )
        ),
    CONSTRAINT connector_control_stream_heads_created_at_valid
        CHECK (created_at_ms BETWEEN 0 AND 9007199254740991),
    CONSTRAINT connector_control_stream_heads_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 9007199254740991)
);

CREATE TABLE agent.connector_control_commands (
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    command_sequence bigint NOT NULL,
    operation_id uuid NOT NULL,
    connector_generation bigint NOT NULL,
    spec_revision bigint NOT NULL,
    command_kind text NOT NULL,
    terminal_revoke boolean NOT NULL,
    payload_digest bytea NOT NULL,
    encoded_command bytea NOT NULL,
    encoded_command_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, connector_id, command_sequence),
    CONSTRAINT connector_control_commands_operation_unique
        UNIQUE (tenant_id, operation_id),
    CONSTRAINT connector_control_commands_connector_fk
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES agent.connector_instances (tenant_id, connector_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_control_commands_operation_fk
        FOREIGN KEY (tenant_id, operation_id, connector_id, command_kind)
        REFERENCES agent.connector_control_operations
            (tenant_id, operation_id, connector_id, operation_kind)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT connector_control_commands_sequence_safe
        CHECK (command_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_control_commands_operation_id_v7
        CHECK (system.is_uuid_v7(operation_id)),
    CONSTRAINT connector_control_commands_generation_safe
        CHECK (connector_generation BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_control_commands_spec_revision_safe
        CHECK (spec_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT connector_control_commands_kind_valid
        CHECK (command_kind IN ('apply_config', 'rotate_credential', 'close_stream')),
    CONSTRAINT connector_control_commands_terminal_revoke_valid
        CHECK (NOT terminal_revoke OR command_kind = 'close_stream'),
    CONSTRAINT connector_control_commands_payload_digest_valid
        CHECK (octet_length(payload_digest) = 32),
    CONSTRAINT connector_control_commands_encoded_valid
        CHECK (octet_length(encoded_command) BETWEEN 1 AND 196608),
    CONSTRAINT connector_control_commands_encoded_digest_valid
        CHECK (octet_length(encoded_command_digest) = 32),
    CONSTRAINT connector_control_commands_created_at_valid
        CHECK (created_at_ms BETWEEN 0 AND 9007199254740991)
);

CREATE TRIGGER connector_control_commands_append_only
BEFORE UPDATE OR DELETE ON agent.connector_control_commands
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE FUNCTION agent.enforce_connector_control_stream_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    stored_payload_digest bytea;
    stored_encoded_digest bytea;
    terminal_fence_transition boolean;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Connector control stream heads cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.last_command_sequence <> 0
           OR NEW.acknowledged_command_sequence <> 0
           OR NEW.acknowledged_payload_digest IS NOT NULL
           OR NEW.acknowledged_encoded_command_digest IS NOT NULL
           OR NEW.state <> 'active' THEN
            RAISE EXCEPTION 'Connector control stream must begin at cursor zero'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    terminal_fence_transition :=
        OLD.state = 'active'
        AND NEW.state = 'revoked'
        AND NEW.connector_generation = OLD.connector_generation
        AND NEW.spec_revision = OLD.spec_revision + 1
        AND NEW.last_command_sequence = OLD.last_command_sequence
        AND NEW.acknowledged_command_sequence = OLD.acknowledged_command_sequence
        AND NEW.last_command_sequence > 0
        AND EXISTS (
            SELECT 1
              FROM agent.connector_control_commands
             WHERE tenant_id = NEW.tenant_id
               AND connector_id = NEW.connector_id
               AND command_sequence = NEW.last_command_sequence
               AND terminal_revoke
        );
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.connector_generation NOT BETWEEN OLD.connector_generation AND OLD.connector_generation + 1
       OR NEW.spec_revision NOT BETWEEN OLD.spec_revision AND OLD.spec_revision + 1
       OR NEW.last_command_sequence NOT BETWEEN OLD.last_command_sequence AND OLD.last_command_sequence + 1
       OR NEW.acknowledged_command_sequence NOT BETWEEN OLD.acknowledged_command_sequence AND OLD.acknowledged_command_sequence + 1
       OR OLD.state = 'revoked'
       OR (OLD.state = 'active' AND NEW.state NOT IN ('active', 'revoked'))
       OR (
            NEW.last_command_sequence > OLD.last_command_sequence
            AND NEW.acknowledged_command_sequence > OLD.acknowledged_command_sequence
       )
       OR (
            (NEW.connector_generation, NEW.spec_revision)
                IS DISTINCT FROM (OLD.connector_generation, OLD.spec_revision)
            AND NOT terminal_fence_transition
            AND (
                NEW.spec_revision <> OLD.spec_revision + 1
                OR NEW.last_command_sequence <> OLD.last_command_sequence
                OR NEW.acknowledged_command_sequence <> OLD.acknowledged_command_sequence
                OR OLD.acknowledged_command_sequence <> OLD.last_command_sequence
            )
       )
       OR (
            NEW.connector_generation = OLD.connector_generation
            AND NEW.spec_revision <> OLD.spec_revision
            AND NEW.spec_revision <> OLD.spec_revision + 1
       )
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Connector control stream head transition'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.last_command_sequence > OLD.last_command_sequence
       AND (
           OLD.state <> 'active'
           OR NEW.state <> 'active'
           OR NOT EXISTS (
            SELECT 1 FROM agent.connector_control_commands
            WHERE tenant_id = NEW.tenant_id
              AND connector_id = NEW.connector_id
              AND command_sequence = NEW.last_command_sequence
              AND connector_generation = NEW.connector_generation
              AND spec_revision = NEW.spec_revision
           )
       ) THEN
        RAISE EXCEPTION 'Connector control command tail has no exact command'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.acknowledged_command_sequence > OLD.acknowledged_command_sequence THEN
        SELECT payload_digest, encoded_command_digest
          INTO stored_payload_digest, stored_encoded_digest
          FROM agent.connector_control_commands
         WHERE tenant_id = NEW.tenant_id
           AND connector_id = NEW.connector_id
           AND command_sequence = NEW.acknowledged_command_sequence;
        IF stored_payload_digest IS NULL
           OR stored_encoded_digest IS NULL
           OR NEW.acknowledged_payload_digest IS DISTINCT FROM stored_payload_digest
           OR NEW.acknowledged_encoded_command_digest IS DISTINCT FROM stored_encoded_digest THEN
            RAISE EXCEPTION 'Connector control acknowledgement digest mismatched'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.acknowledged_payload_digest IS DISTINCT FROM OLD.acknowledged_payload_digest
       OR NEW.acknowledged_encoded_command_digest
            IS DISTINCT FROM OLD.acknowledged_encoded_command_digest THEN
        RAISE EXCEPTION 'Connector control acknowledgement digests changed'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.state = 'revoked' AND OLD.state = 'active'
       AND (
           NEW.last_command_sequence = 0
           OR NOT EXISTS (
               SELECT 1
                 FROM agent.connector_control_commands
                WHERE tenant_id = NEW.tenant_id
                  AND connector_id = NEW.connector_id
                  AND command_sequence = NEW.last_command_sequence
                   AND terminal_revoke
           )
       ) THEN
        RAISE EXCEPTION 'Connector control revocation lacks a terminal close command'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_control_stream_head_transition
BEFORE INSERT OR UPDATE OR DELETE ON agent.connector_control_stream_heads
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_control_stream_head_transition();

CREATE FUNCTION agent.enforce_connector_control_stream_fence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    stream_generation bigint;
    stream_spec_revision bigint;
    connector_generation bigint;
    connector_spec_revision bigint;
BEGIN
    SELECT stream.connector_generation, stream.spec_revision,
           connector.generation, connector.spec_revision
      INTO stream_generation, stream_spec_revision,
           connector_generation, connector_spec_revision
      FROM agent.connector_control_stream_heads AS stream
      JOIN agent.connector_instances AS connector
        ON connector.tenant_id = stream.tenant_id
       AND connector.connector_id = stream.connector_id
     WHERE stream.tenant_id = NEW.tenant_id
       AND stream.connector_id = NEW.connector_id;
    IF stream_generation IS NULL THEN
        IF TG_TABLE_NAME = 'connector_control_stream_heads' THEN
            RAISE EXCEPTION 'Connector control stream final fence is unavailable'
                USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    END IF;
    IF stream_generation IS DISTINCT FROM connector_generation
       OR stream_spec_revision IS DISTINCT FROM connector_spec_revision THEN
        RAISE EXCEPTION 'Connector control stream final fence is stale'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER connector_control_stream_fence
AFTER INSERT OR UPDATE ON agent.connector_control_stream_heads
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_control_stream_fence();

CREATE CONSTRAINT TRIGGER connector_instance_control_stream_fence
AFTER UPDATE OF generation, spec_revision ON agent.connector_instances
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_control_stream_fence();

CREATE FUNCTION agent.enforce_connector_control_command_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    head agent.connector_control_stream_heads%ROWTYPE;
BEGIN
    SELECT * INTO STRICT head
      FROM agent.connector_control_stream_heads
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id
     FOR UPDATE;
    IF NEW.command_sequence <> head.last_command_sequence + 1
       OR head.state <> 'active'
       OR NEW.connector_generation <> head.connector_generation
       OR NEW.spec_revision <> head.spec_revision
       OR (
           head.last_command_sequence - head.acknowledged_command_sequence >= 4096
           AND NOT (
               head.last_command_sequence - head.acknowledged_command_sequence = 4096
               AND NEW.terminal_revoke
           )
       )
       OR NEW.created_at_ms < head.updated_at_ms THEN
        RAISE EXCEPTION 'invalid or stale Connector control command'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER connector_control_command_insert
BEFORE INSERT ON agent.connector_control_commands
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_control_command_insert();

CREATE FUNCTION agent.advance_connector_control_command_tail()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE agent.connector_control_stream_heads
       SET last_command_sequence = NEW.command_sequence,
           updated_at_ms = NEW.created_at_ms
     WHERE tenant_id = NEW.tenant_id
       AND connector_id = NEW.connector_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Connector control stream head disappeared'
            USING ERRCODE = '23503';
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER connector_control_command_tail
AFTER INSERT ON agent.connector_control_commands
FOR EACH ROW
EXECUTE FUNCTION agent.advance_connector_control_command_tail();

CREATE FUNCTION agent.enforce_connector_terminal_revoke_commit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.terminal_revoke AND NOT EXISTS (
        SELECT 1
          FROM agent.connector_control_stream_heads AS stream
          JOIN agent.connector_instances AS connector
            ON connector.tenant_id=stream.tenant_id
           AND connector.connector_id=stream.connector_id
          JOIN agent.connector_control_credential_heads AS credential_head
            ON credential_head.tenant_id=stream.tenant_id
           AND credential_head.connector_id=stream.connector_id
          JOIN agent.connector_control_credential_revisions AS credential_revision
            ON credential_revision.tenant_id=credential_head.tenant_id
           AND credential_revision.connector_id=credential_head.connector_id
           AND credential_revision.authorization_revision=credential_head.current_revision
         WHERE stream.tenant_id = NEW.tenant_id
           AND stream.connector_id = NEW.connector_id
           AND stream.state = 'revoked'
           AND stream.last_command_sequence = NEW.command_sequence
           AND connector.desired_state = 'revoked'
           AND connector.observed_state = 'revoked'
           AND credential_revision.lifecycle = 'revoked'
           AND credential_revision.cause_operation_id = NEW.operation_id
           AND NOT EXISTS (
               SELECT 1
                 FROM agent.connector_leases AS lease
                WHERE lease.tenant_id=NEW.tenant_id
                  AND lease.connector_id=NEW.connector_id
                  AND lease.status='active'
           )
    ) THEN
        RAISE EXCEPTION 'terminal Connector command was not finalized atomically'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER connector_terminal_revoke_commit
AFTER INSERT ON agent.connector_control_commands
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_terminal_revoke_commit();

CREATE FUNCTION agent.enforce_connector_revocation_bundle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    stream_state text;
    stream_last_sequence bigint;
    connector_desired_state text;
    connector_observed_state text;
    credential_lifecycle text;
    credential_cause_kind text;
    credential_cause_operation_id uuid;
    terminal_revoke boolean;
    terminal_operation_id uuid;
BEGIN
    SELECT stream.state, stream.last_command_sequence,
           connector.desired_state, connector.observed_state,
           credential_revision.lifecycle, credential_revision.cause_kind,
           credential_revision.cause_operation_id,
           command.terminal_revoke, command.operation_id
      INTO stream_state, stream_last_sequence,
           connector_desired_state, connector_observed_state,
           credential_lifecycle, credential_cause_kind,
           credential_cause_operation_id,
           terminal_revoke, terminal_operation_id
      FROM agent.connector_instances AS connector
      LEFT JOIN agent.connector_control_stream_heads AS stream
        ON stream.tenant_id=connector.tenant_id
       AND stream.connector_id=connector.connector_id
      LEFT JOIN agent.connector_control_credential_heads AS credential_head
        ON credential_head.tenant_id=connector.tenant_id
       AND credential_head.connector_id=connector.connector_id
      LEFT JOIN agent.connector_control_credential_revisions AS credential_revision
        ON credential_revision.tenant_id=credential_head.tenant_id
       AND credential_revision.connector_id=credential_head.connector_id
       AND credential_revision.authorization_revision=credential_head.current_revision
      LEFT JOIN agent.connector_control_commands AS command
        ON command.tenant_id=stream.tenant_id
       AND command.connector_id=stream.connector_id
       AND command.command_sequence=stream.last_command_sequence
     WHERE connector.tenant_id=NEW.tenant_id
       AND connector.connector_id=NEW.connector_id;

    IF stream_state IS NULL AND credential_lifecycle IS NULL THEN
        RETURN NULL;
    END IF;
    IF stream_state = 'revoked'
       OR credential_lifecycle = 'revoked'
       OR connector_desired_state = 'revoked'
       OR connector_observed_state = 'revoked' THEN
        IF stream_state IS DISTINCT FROM 'revoked'
           OR connector_desired_state IS DISTINCT FROM 'revoked'
           OR connector_observed_state IS DISTINCT FROM 'revoked'
           OR credential_lifecycle IS DISTINCT FROM 'revoked'
           OR credential_cause_kind IS DISTINCT FROM 'revoked'
           OR stream_last_sequence IS NULL
           OR terminal_revoke IS DISTINCT FROM true
           OR credential_cause_operation_id IS DISTINCT FROM terminal_operation_id
           OR EXISTS (
               SELECT 1
                 FROM agent.connector_leases AS lease
                WHERE lease.tenant_id=NEW.tenant_id
                  AND lease.connector_id=NEW.connector_id
                  AND lease.status='active'
           ) THEN
            RAISE EXCEPTION 'Connector revocation was not committed as one terminal bundle'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER connector_stream_revocation_bundle
AFTER INSERT OR UPDATE ON agent.connector_control_stream_heads
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_revocation_bundle();

CREATE CONSTRAINT TRIGGER connector_credential_revocation_bundle
AFTER INSERT OR UPDATE ON agent.connector_control_credential_heads
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_revocation_bundle();

CREATE CONSTRAINT TRIGGER connector_instance_revocation_bundle
AFTER UPDATE ON agent.connector_instances
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_revocation_bundle();

CREATE CONSTRAINT TRIGGER connector_lease_revocation_bundle
AFTER INSERT ON agent.connector_leases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (NEW.status = 'active')
EXECUTE FUNCTION agent.enforce_connector_revocation_bundle();

CREATE CONSTRAINT TRIGGER connector_lease_reactivated_bundle
AFTER UPDATE ON agent.connector_leases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (NEW.status = 'active' AND OLD.status IS DISTINCT FROM 'active')
EXECUTE FUNCTION agent.enforce_connector_revocation_bundle();

ALTER TABLE agent.connector_control_credential_rotations
    ADD CONSTRAINT connector_credential_rotations_command_fk
    FOREIGN KEY (tenant_id, connector_id, command_sequence)
    REFERENCES agent.connector_control_commands
        (tenant_id, connector_id, command_sequence)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION agent.enforce_connector_credential_rotation_command()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM agent.connector_control_commands
         WHERE tenant_id = NEW.tenant_id
           AND connector_id = NEW.connector_id
           AND command_sequence = NEW.command_sequence
           AND operation_id = NEW.request_id
           AND command_kind = 'rotate_credential'
           AND payload_digest = NEW.command_payload_digest
    ) THEN
        RAISE EXCEPTION 'Connector rotation is not bound to its exact durable command'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER connector_credential_rotation_command
AFTER INSERT ON agent.connector_control_credential_rotations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_connector_credential_rotation_command();

ALTER TABLE agent.connector_control_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_control_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_control_operations
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_enrollment_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_enrollment_intents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_enrollment_intents
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_control_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_control_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_control_credentials
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_control_credential_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_control_credential_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_control_credential_revisions
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_control_credential_rotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_control_credential_rotations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_control_credential_rotations
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_control_credential_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_control_credential_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_control_credential_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_runtime_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_runtime_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_runtime_claims
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_runtime_claim_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_runtime_claim_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_runtime_claim_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_control_stream_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_control_stream_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_control_stream_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_control_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_control_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_control_commands
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.connector_control_operations FROM PUBLIC;
REVOKE ALL ON agent.connector_enrollment_intents FROM PUBLIC;
REVOKE ALL ON agent.connector_control_credentials FROM PUBLIC;
REVOKE ALL ON agent.connector_control_credential_revisions FROM PUBLIC;
REVOKE ALL ON agent.connector_control_credential_rotations FROM PUBLIC;
REVOKE ALL ON agent.connector_control_credential_heads FROM PUBLIC;
REVOKE ALL ON agent.connector_runtime_claims FROM PUBLIC;
REVOKE ALL ON agent.connector_runtime_claim_heads FROM PUBLIC;
REVOKE ALL ON agent.connector_control_stream_heads FROM PUBLIC;
REVOKE ALL ON agent.connector_control_commands FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_enrollment_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.connector_certificate_chain_valid(bytea[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_control_credential_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_credential_rotation_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_enrollment_consumed() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_credential_revision_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_credential_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.connector_runtime_name_valid(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.connector_claim_codes_valid(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.connector_run_ids_valid(uuid[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.connector_runtime_error_code_valid(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_runtime_claim_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_runtime_claim_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.prune_connector_runtime_claim_history(uuid, uuid, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_control_stream_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_control_stream_fence() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_control_command_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.advance_connector_control_command_tail() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_revocation_bundle() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_credential_rotation_command() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_control_operation_published() FROM PUBLIC;
