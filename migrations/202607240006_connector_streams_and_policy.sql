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
