CREATE SCHEMA system;

CREATE TABLE system.schema_epoch (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    epoch text NOT NULL,
    baseline_digest bytea NOT NULL CHECK (octet_length(baseline_digest) = 32),
    installed_at timestamptz NOT NULL DEFAULT now()
);

DO $schema_epoch_grants$
DECLARE
    runtime_role text;
BEGIN
    FOREACH runtime_role IN ARRAY ARRAY[
        'dtx_identity_runtime', 'dtx_group_runtime', 'dtx_mailbox_runtime',
        'dtx_realtime_sync_runtime'
    ] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = runtime_role) THEN
            EXECUTE format('GRANT USAGE ON SCHEMA system TO %I', runtime_role);
            EXECUTE format('GRANT SELECT ON system.schema_epoch TO %I', runtime_role);
        END IF;
    END LOOP;
END
$schema_epoch_grants$;

CREATE FUNCTION system.current_tenant_id()
RETURNS uuid
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT NULLIF(current_setting('dtx.tenant_id', true), '')::uuid
$$;

CREATE FUNCTION system.is_stable_code(candidate text, maximum_bytes integer)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT octet_length(candidate) BETWEEN 1 AND maximum_bytes
       AND candidate ~ '^[a-z0-9_.]+$'
       AND candidate !~ '(^|[.])[0-9_]'
       AND candidate !~ '(__|_($|[.])|[.]($|[.]))'
$$;

CREATE FUNCTION system.is_uuid_v7(candidate uuid)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT (get_byte(uuid_send(candidate), 6) >> 4) = 7
       AND (get_byte(uuid_send(candidate), 8) >> 6) = 2
$$;

CREATE TABLE system.tenant_stream_heads (
    tenant_id uuid PRIMARY KEY,
    last_sequence bigint NOT NULL DEFAULT 0,
    CONSTRAINT tenant_stream_heads_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT tenant_stream_heads_last_sequence_safe
        CHECK (last_sequence BETWEEN 0 AND 9007199254740991)
);

CREATE TABLE system.durable_events (
    tenant_id uuid NOT NULL,
    stream_sequence bigint NOT NULL,
    event_id uuid NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_revision bigint NOT NULL,
    event_index smallint NOT NULL,
    occurred_at_ms bigint NOT NULL,
    schema_version integer NOT NULL,
    event_type text NOT NULL,
    envelope bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, event_id),
    CONSTRAINT durable_events_tenant_stream_sequence_unique
        UNIQUE (tenant_id, stream_sequence),
    CONSTRAINT durable_events_aggregate_revision_unique
        UNIQUE (
            tenant_id, aggregate_type, aggregate_id, aggregate_revision, event_index
        ),
    CONSTRAINT durable_events_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_events_event_id_v7
        CHECK (system.is_uuid_v7(event_id)),
    CONSTRAINT durable_events_aggregate_id_v7
        CHECK (system.is_uuid_v7(aggregate_id)),
    CONSTRAINT durable_events_stream_sequence_safe
        CHECK (stream_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT durable_events_aggregate_revision_safe
        CHECK (aggregate_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT durable_events_event_index_valid
        CHECK (event_index >= 0),
    CONSTRAINT durable_events_occurred_at_valid
        CHECK (occurred_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT durable_events_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT durable_events_schema_version_valid
        CHECK (schema_version BETWEEN 1 AND 65535),
    CONSTRAINT durable_events_aggregate_type_bounded
        CHECK (system.is_stable_code(aggregate_type, 128)),
    CONSTRAINT durable_events_event_type_bounded
        CHECK (system.is_stable_code(event_type, 255)),
    CONSTRAINT durable_events_envelope_bounded
        CHECK (octet_length(envelope) BETWEEN 1 AND 1048576)
);

CREATE INDEX durable_events_aggregate_order_idx
    ON system.durable_events
        (tenant_id, aggregate_type, aggregate_id, aggregate_revision, event_index);

CREATE TABLE system.outbox_events (
    tenant_id uuid NOT NULL,
    outbox_id uuid NOT NULL,
    event_id uuid NOT NULL,
    destination text NOT NULL,
    available_at_ms bigint NOT NULL,
    attempt_count bigint NOT NULL DEFAULT 0,
    published_at_ms bigint,
    last_error_code text,
    PRIMARY KEY (tenant_id, outbox_id),
    CONSTRAINT outbox_events_event_unique
        UNIQUE (tenant_id, event_id, destination),
    CONSTRAINT outbox_events_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT outbox_events_event_fk
        FOREIGN KEY (tenant_id, event_id)
        REFERENCES system.durable_events (tenant_id, event_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT outbox_events_outbox_id_v7
        CHECK (system.is_uuid_v7(outbox_id)),
    CONSTRAINT outbox_events_available_at_valid
        CHECK (available_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT outbox_events_attempt_count_safe
        CHECK (attempt_count BETWEEN 0 AND 9007199254740991),
    CONSTRAINT outbox_events_published_at_valid
        CHECK (
            published_at_ms IS NULL
            OR published_at_ms BETWEEN -62135596800000 AND 253402300799999
        ),
    CONSTRAINT outbox_events_destination_bounded
        CHECK (system.is_stable_code(destination, 128)),
    CONSTRAINT outbox_events_last_error_code_bounded
        CHECK (
            last_error_code IS NULL
            OR system.is_stable_code(last_error_code, 128)
        )
);

CREATE INDEX outbox_events_dispatch_idx
    ON system.outbox_events (tenant_id, available_at_ms, outbox_id)
    WHERE published_at_ms IS NULL;

CREATE TABLE system.inbox_dedup (
    tenant_id uuid NOT NULL,
    consumer text NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    request_hash bytea NOT NULL,
    command_id uuid NOT NULL,
    state text NOT NULL,
    result_bytes bytea,
    result_hash bytea,
    created_at_ms bigint NOT NULL,
    completed_at_ms bigint,
    PRIMARY KEY (tenant_id, consumer, idempotency_key_hash),
    CONSTRAINT inbox_dedup_command_unique
        UNIQUE (tenant_id, command_id),
    CONSTRAINT inbox_dedup_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT inbox_dedup_command_id_v7
        CHECK (system.is_uuid_v7(command_id)),
    CONSTRAINT inbox_dedup_consumer_bounded
        CHECK (system.is_stable_code(consumer, 128)),
    CONSTRAINT inbox_dedup_idempotency_key_hash_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT inbox_dedup_request_hash_size
        CHECK (octet_length(request_hash) = 32),
    CONSTRAINT inbox_dedup_state_bounded
        CHECK (state IN ('pending', 'completed')),
    CONSTRAINT inbox_dedup_state_consistent
        CHECK (
            (
                state = 'pending'
                AND result_bytes IS NULL
                AND result_hash IS NULL
                AND completed_at_ms IS NULL
            )
            OR (
                state = 'completed'
                AND result_bytes IS NOT NULL
                AND result_hash IS NOT NULL
                AND octet_length(result_bytes) BETWEEN 0 AND 1048576
                AND octet_length(result_hash) = 32
                AND completed_at_ms IS NOT NULL
            )
        ),
    CONSTRAINT inbox_dedup_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT inbox_dedup_completed_at_valid
        CHECK (
            completed_at_ms IS NULL
            OR completed_at_ms BETWEEN created_at_ms AND 253402300799999
        )
);

CREATE FUNCTION system.enforce_completed_inbox()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM system.inbox_dedup
         WHERE tenant_id = NEW.tenant_id
           AND consumer = NEW.consumer
           AND idempotency_key_hash = NEW.idempotency_key_hash
           AND state <> 'completed'
    ) THEN
        RAISE EXCEPTION 'inbox command must be completed before commit'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER inbox_dedup_must_complete
AFTER INSERT OR UPDATE ON system.inbox_dedup
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION system.enforce_completed_inbox();

CREATE FUNCTION system.enforce_inbox_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' THEN
            RAISE EXCEPTION 'inbox command must be inserted as pending'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state <> 'pending' OR NEW.state <> 'completed' THEN
        RAISE EXCEPTION 'inbox command permits only pending to completed transition'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.consumer IS DISTINCT FROM OLD.consumer
       OR NEW.idempotency_key_hash IS DISTINCT FROM OLD.idempotency_key_hash
       OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
       OR NEW.command_id IS DISTINCT FROM OLD.command_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'inbox command identity is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER inbox_dedup_transition
BEFORE INSERT OR UPDATE ON system.inbox_dedup
FOR EACH ROW
EXECUTE FUNCTION system.enforce_inbox_transition();

CREATE TABLE system.audit_events (
    tenant_id uuid NOT NULL,
    audit_id uuid NOT NULL,
    command_id uuid NOT NULL,
    action text NOT NULL,
    result_code text NOT NULL,
    occurred_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, audit_id),
    CONSTRAINT audit_events_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT audit_events_command_fk
        FOREIGN KEY (tenant_id, command_id)
        REFERENCES system.inbox_dedup (tenant_id, command_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT audit_events_audit_id_v7
        CHECK (system.is_uuid_v7(audit_id)),
    CONSTRAINT audit_events_command_id_v7
        CHECK (system.is_uuid_v7(command_id)),
    CONSTRAINT audit_events_action_bounded
        CHECK (system.is_stable_code(action, 128)),
    CONSTRAINT audit_events_result_code_bounded
        CHECK (system.is_stable_code(result_code, 128)),
    CONSTRAINT audit_events_occurred_at_valid
        CHECK (occurred_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE INDEX audit_events_occurred_at_idx
    ON system.audit_events (tenant_id, occurred_at_ms, audit_id);

CREATE TABLE system.projection_cursors (
    tenant_id uuid NOT NULL,
    projection_name text NOT NULL,
    projection_version integer NOT NULL,
    last_sequence bigint NOT NULL DEFAULT 0,
    projection_hash bytea NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, projection_name, projection_version),
    CONSTRAINT projection_cursors_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT projection_cursors_name_bounded
        CHECK (system.is_stable_code(projection_name, 128)),
    CONSTRAINT projection_cursors_version_valid
        CHECK (projection_version BETWEEN 1 AND 65535),
    CONSTRAINT projection_cursors_last_sequence_safe
        CHECK (last_sequence BETWEEN 0 AND 9007199254740991),
    CONSTRAINT projection_cursors_hash_size
        CHECK (octet_length(projection_hash) = 32),
    CONSTRAINT projection_cursors_updated_at_valid
        CHECK (updated_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

ALTER TABLE system.tenant_stream_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE system.tenant_stream_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON system.tenant_stream_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE system.durable_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE system.durable_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON system.durable_events
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE system.outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE system.outbox_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON system.outbox_events
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE system.inbox_dedup ENABLE ROW LEVEL SECURITY;
ALTER TABLE system.inbox_dedup FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON system.inbox_dedup
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE system.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE system.audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON system.audit_events
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE system.projection_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE system.projection_cursors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON system.projection_cursors
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

CREATE VIEW system.schema_versions AS
SELECT DISTINCT version, description, installed_on, success, checksum, execution_time
FROM public._sqlx_migrations;

REVOKE ALL ON FUNCTION system.current_tenant_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION system.is_uuid_v7(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION system.is_stable_code(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION system.enforce_completed_inbox() FROM PUBLIC;
REVOKE ALL ON FUNCTION system.enforce_inbox_transition() FROM PUBLIC;
