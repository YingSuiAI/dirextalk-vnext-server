CREATE FUNCTION agent.enforce_agent_run_state_bundle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    run_head agent.agent_runs%ROWTYPE;
    current_offer_status text;
    current_offer_attempt bigint;
    current_offer_candidate integer;
    current_lease_status text;
    current_lease_epoch bigint;
    current_lease_offer uuid;
    current_lease_attempt bigint;
    current_lease_candidate integer;
    active_offer_count bigint;
    active_lease_count bigint;
BEGIN
    SELECT * INTO STRICT run_head
      FROM agent.agent_runs
     WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id;

    SELECT count(*) FILTER (WHERE status = 'offered')
      INTO active_offer_count
      FROM agent.agent_run_offers
     WHERE tenant_id = run_head.tenant_id AND run_id = run_head.run_id;
    SELECT count(*) FILTER (WHERE status = 'active')
      INTO active_lease_count
      FROM agent.agent_run_leases
     WHERE tenant_id = run_head.tenant_id AND run_id = run_head.run_id;

    IF run_head.current_offer_id IS NOT NULL THEN
        SELECT status, offer_attempt, candidate_ordinal
          INTO current_offer_status, current_offer_attempt, current_offer_candidate
          FROM agent.agent_run_offers
         WHERE tenant_id = run_head.tenant_id AND run_id = run_head.run_id
           AND offer_id = run_head.current_offer_id;
    END IF;
    IF run_head.current_run_lease_id IS NOT NULL THEN
        SELECT status, run_lease_epoch, offer_id, offer_attempt, candidate_ordinal
          INTO current_lease_status, current_lease_epoch, current_lease_offer,
               current_lease_attempt, current_lease_candidate
          FROM agent.agent_run_leases
         WHERE tenant_id = run_head.tenant_id AND run_id = run_head.run_id
           AND run_lease_id = run_head.current_run_lease_id;
    END IF;

    IF run_head.state IN ('queued', 'expired') THEN
        IF active_offer_count <> 0 OR active_lease_count <> 0 THEN
            RAISE EXCEPTION 'Queued or expired Agent Run retains active routing rows'
                USING ERRCODE = '23514';
        END IF;
    ELSIF run_head.state = 'offered' THEN
        IF active_offer_count <> 1 OR active_lease_count <> 0
           OR current_offer_status IS DISTINCT FROM 'offered'
           OR current_offer_attempt IS DISTINCT FROM run_head.highest_offer_attempt
           OR current_offer_candidate IS DISTINCT FROM run_head.candidate_cursor
        THEN
            RAISE EXCEPTION 'Offered Agent Run head diverges from its offer'
                USING ERRCODE = '23514';
        END IF;
    ELSIF run_head.state = 'leased' THEN
        IF active_offer_count <> 0 OR active_lease_count <> 1
           OR current_offer_status IS DISTINCT FROM 'claimed'
           OR current_lease_status IS DISTINCT FROM 'active'
           OR current_lease_offer IS DISTINCT FROM run_head.current_offer_id
           OR current_lease_attempt IS DISTINCT FROM current_offer_attempt
           OR current_lease_candidate IS DISTINCT FROM run_head.candidate_cursor
           OR current_lease_epoch IS DISTINCT FROM run_head.highest_run_lease_epoch
        THEN
            RAISE EXCEPTION 'Leased Agent Run head diverges from its lease'
                USING ERRCODE = '23514';
        END IF;
    ELSIF run_head.state = 'reconcile_required' THEN
        IF active_offer_count <> 0 OR active_lease_count <> 0
           OR current_offer_status IS DISTINCT FROM 'claimed'
           OR current_lease_status IS NULL
           OR current_lease_status NOT IN ('released', 'expired')
           OR current_lease_offer IS DISTINCT FROM run_head.current_offer_id
           OR current_lease_attempt IS DISTINCT FROM current_offer_attempt
           OR current_lease_candidate IS DISTINCT FROM run_head.candidate_cursor
           OR current_lease_epoch IS DISTINCT FROM run_head.highest_run_lease_epoch
        THEN
            RAISE EXCEPTION 'Reconciled Agent Run head diverges from terminal lease status'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER agent_run_state_bundle_from_run
AFTER INSERT OR UPDATE ON agent.agent_runs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_state_bundle();
CREATE CONSTRAINT TRIGGER agent_run_state_bundle_from_offer
AFTER INSERT OR UPDATE ON agent.agent_run_offers
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_state_bundle();
CREATE CONSTRAINT TRIGGER agent_run_state_bundle_from_lease
AFTER INSERT OR UPDATE ON agent.agent_run_leases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agent.enforce_agent_run_state_bundle();

CREATE FUNCTION agent.notify_agent_run_offer()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('dtx_agent_run_offer_v1', NEW.tenant_id::text || ':' || NEW.connector_id::text);
    RETURN NULL;
END
$$;

CREATE TRIGGER agent_run_offer_notify
AFTER INSERT ON agent.agent_run_offers
FOR EACH ROW EXECUTE FUNCTION agent.notify_agent_run_offer();

ALTER TABLE agent.agent_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_runs
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.agent_run_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_candidates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_candidates
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.connector_run_capacity_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.connector_run_capacity_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.connector_run_capacity_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.binding_run_capacity_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.binding_run_capacity_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.binding_run_capacity_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.agent_run_offers ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_offers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_offers
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.agent_run_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_leases FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_leases
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.agent_runs FROM PUBLIC;
REVOKE ALL ON agent.agent_run_candidates FROM PUBLIC;
REVOKE ALL ON agent.connector_run_capacity_heads FROM PUBLIC;
REVOKE ALL ON agent.binding_run_capacity_heads FROM PUBLIC;
REVOKE ALL ON agent.agent_run_offers FROM PUBLIC;
REVOKE ALL ON agent.agent_run_leases FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.router_stable_names(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_offer_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_lease_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_connector_run_capacity_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_binding_run_capacity_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_candidate_scope() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_candidate_count() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_offer_bundle() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_agent_run_lease_bundle() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.notify_agent_run_offer() FROM PUBLIC;
CREATE TABLE agent.host_provisioning_operations (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    host_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT host_provisioning_operations_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_provisioning_operations_host_fk
        FOREIGN KEY (tenant_id, host_id)
        REFERENCES agent.hosts (tenant_id, host_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_provisioning_operations_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT host_provisioning_operations_operation_id_v7
        CHECK (system.is_uuid_v7(operation_id)),
    CONSTRAINT host_provisioning_operations_host_id_v7
        CHECK (system.is_uuid_v7(host_id)),
    CONSTRAINT host_provisioning_operations_request_digest_valid
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT host_provisioning_operations_created_at_valid
        CHECK (created_at_ms BETWEEN 0 AND 9007199254740991)
);

CREATE TRIGGER host_provisioning_operations_append_only
BEFORE UPDATE OR DELETE ON agent.host_provisioning_operations
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

ALTER TABLE agent.host_provisioning_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.host_provisioning_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.host_provisioning_operations
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.host_provisioning_operations FROM PUBLIC;
-- The self-certifying identity log is deliberately not tenant-scoped.  Its
-- public `identity_id` remains its primary key; tenant UUIDs never stand in
-- for it.  The migration owner owns these relations.  Application writers
-- must use the non-owner `dtx_identity_runtime` group role provisioned by the
-- host database operator; PUBLIC receives no schema, table, or function grant.
CREATE SCHEMA identity;

CREATE FUNCTION identity.identity_runtime_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT COALESCE(
        pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'),
        false
    )
$$;

CREATE FUNCTION identity.identity_owner_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT current_user = pg_get_userbyid(nspowner)
      FROM pg_namespace
     WHERE nspname = 'identity'
$$;

CREATE FUNCTION identity.reject_immutable_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'identity log append-only relation cannot be rewritten'
        USING ERRCODE = '23514';
END
$$;

CREATE TABLE identity.log_heads (
    identity_id text PRIMARY KEY,
    protocol_major smallint NOT NULL,
    protocol_minor smallint NOT NULL,
    minimum_reader_major smallint NOT NULL,
    minimum_reader_minor smallint NOT NULL,
    head_sequence bigint NOT NULL,
    head_hash bytea NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT identity_log_heads_identity_id_shape
        CHECK (octet_length(identity_id) = 57 AND identity_id ~ '^dtxi1[a-z2-7]{52}$'),
    CONSTRAINT identity_log_heads_current_wire
        CHECK (
            protocol_major = 1 AND protocol_minor = 1
            AND minimum_reader_major = 1 AND minimum_reader_minor = 1
        ),
    CONSTRAINT identity_log_heads_sequence_safe
        CHECK (head_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT identity_log_heads_hash_size
        CHECK (octet_length(head_hash) = 32),
    CONSTRAINT identity_log_heads_state_valid
        CHECK (state IN ('active', 'tombstoned', 'forked')),
    CONSTRAINT identity_log_heads_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT identity_log_heads_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE TABLE identity.log_entries (
    identity_id text NOT NULL,
    sequence bigint NOT NULL,
    entry_hash bytea NOT NULL,
    previous_hash bytea,
    protocol_major smallint NOT NULL,
    protocol_minor smallint NOT NULL,
    minimum_reader_major smallint NOT NULL,
    minimum_reader_minor smallint NOT NULL,
    event_bytes bytea NOT NULL,
    recorded_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, sequence),
    CONSTRAINT identity_log_entries_hash_unique UNIQUE (entry_hash),
    CONSTRAINT identity_log_entries_identity_hash_unique UNIQUE (identity_id, entry_hash),
    CONSTRAINT identity_log_entries_head_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_log_entries_sequence_safe
        CHECK (sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT identity_log_entries_hash_size
        CHECK (octet_length(entry_hash) = 32),
    CONSTRAINT identity_log_entries_previous_shape
        CHECK (
            (sequence = 1 AND previous_hash IS NULL)
            OR (sequence > 1 AND octet_length(previous_hash) = 32)
        ),
    CONSTRAINT identity_log_entries_current_wire
        CHECK (
            protocol_major = 1 AND protocol_minor = 1
            AND minimum_reader_major = 1 AND minimum_reader_minor = 1
        ),
    CONSTRAINT identity_log_entries_event_bytes_bounded
        CHECK (octet_length(event_bytes) BETWEEN 1 AND 1048576),
    CONSTRAINT identity_log_entries_recorded_at_valid
        CHECK (recorded_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TABLE identity.command_receipts (
    identity_id text NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    request_digest bytea NOT NULL,
    state text NOT NULL,
    receipt_protocol_major smallint,
    receipt_protocol_minor smallint,
    receipt_minimum_reader_major smallint,
    receipt_minimum_reader_minor smallint,
    receipt_sequence bigint,
    receipt_head_hash bytea,
    receipt_bytes bytea,
    receipt_digest bytea,
    created_at_ms bigint NOT NULL,
    committed_at_ms bigint,
    PRIMARY KEY (identity_id, idempotency_key_hash),
    CONSTRAINT identity_command_receipts_head_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_command_receipts_key_hash_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT identity_command_receipts_request_digest_size
        CHECK (octet_length(request_digest) = 32),
    CONSTRAINT identity_command_receipts_state_valid
        CHECK (state IN ('pending', 'committed', 'forked')),
    CONSTRAINT identity_command_receipts_state_consistent
        CHECK (
            (
                state = 'pending'
                AND receipt_protocol_major IS NULL
                AND receipt_protocol_minor IS NULL
                AND receipt_minimum_reader_major IS NULL
                AND receipt_minimum_reader_minor IS NULL
                AND receipt_sequence IS NULL
                AND receipt_head_hash IS NULL
                AND receipt_bytes IS NULL
                AND receipt_digest IS NULL
                AND committed_at_ms IS NULL
            )
            OR (
                state IN ('committed', 'forked')
                AND receipt_protocol_major = 1
                AND receipt_protocol_minor = 1
                AND receipt_minimum_reader_major = 1
                AND receipt_minimum_reader_minor = 1
                AND receipt_sequence BETWEEN 1 AND 9007199254740991
                AND octet_length(receipt_head_hash) = 32
                AND octet_length(receipt_bytes) BETWEEN 1 AND 16384
                AND octet_length(receipt_digest) = 32
                AND committed_at_ms BETWEEN created_at_ms AND 253402300799999
            )
        ),
    CONSTRAINT identity_command_receipts_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

-- A verified competing candidate never enters the canonical sequence. It is
-- retained separately with the observed canonical head so later relay gossip
-- or manual recovery can audit the exact signed divergence.
CREATE TABLE identity.fork_evidence (
    identity_id text NOT NULL,
    candidate_entry_hash bytea NOT NULL,
    candidate_sequence bigint NOT NULL,
    candidate_previous_hash bytea,
    candidate_protocol_major smallint NOT NULL,
    candidate_protocol_minor smallint NOT NULL,
    candidate_minimum_reader_major smallint NOT NULL,
    candidate_minimum_reader_minor smallint NOT NULL,
    observed_head_sequence bigint NOT NULL,
    observed_head_hash bytea NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    event_bytes bytea NOT NULL,
    recorded_at_ms bigint NOT NULL,
    PRIMARY KEY (identity_id, candidate_entry_hash),
    CONSTRAINT identity_fork_evidence_command_unique
        UNIQUE (identity_id, idempotency_key_hash),
    CONSTRAINT identity_fork_evidence_head_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_fork_evidence_command_fk
        FOREIGN KEY (identity_id, idempotency_key_hash)
        REFERENCES identity.command_receipts (identity_id, idempotency_key_hash)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_fork_evidence_candidate_hash_size
        CHECK (octet_length(candidate_entry_hash) = 32),
    CONSTRAINT identity_fork_evidence_candidate_sequence_safe
        CHECK (candidate_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT identity_fork_evidence_candidate_previous_shape
        CHECK (
            (candidate_sequence = 1 AND candidate_previous_hash IS NULL)
            OR (candidate_sequence > 1 AND octet_length(candidate_previous_hash) = 32)
        ),
    CONSTRAINT identity_fork_evidence_candidate_wire
        CHECK (
            candidate_protocol_major = 1 AND candidate_protocol_minor = 1
            AND candidate_minimum_reader_major = 1
            AND candidate_minimum_reader_minor = 1
        ),
    CONSTRAINT identity_fork_evidence_observed_sequence_safe
        CHECK (observed_head_sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT identity_fork_evidence_observed_hash_size
        CHECK (octet_length(observed_head_hash) = 32),
    CONSTRAINT identity_fork_evidence_key_hash_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT identity_fork_evidence_event_bytes_bounded
        CHECK (octet_length(event_bytes) BETWEEN 1 AND 1048576),
    CONSTRAINT identity_fork_evidence_recorded_at_valid
        CHECK (recorded_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TABLE identity.log_outbox (
    identity_id text NOT NULL,
    entry_hash bytea NOT NULL,
    topic text NOT NULL,
    available_at_ms bigint NOT NULL,
    attempt_count bigint NOT NULL DEFAULT 0,
    published_at_ms bigint,
    last_error_code text,
    PRIMARY KEY (identity_id, entry_hash),
    CONSTRAINT identity_log_outbox_entry_fk
        FOREIGN KEY (identity_id, entry_hash)
        REFERENCES identity.log_entries (identity_id, entry_hash)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_log_outbox_topic_valid
        CHECK (topic = 'identity_log_append'),
    CONSTRAINT identity_log_outbox_available_at_valid
        CHECK (available_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT identity_log_outbox_attempt_count_safe
        CHECK (attempt_count BETWEEN 0 AND 9007199254740991),
    CONSTRAINT identity_log_outbox_published_at_valid
        CHECK (
            published_at_ms IS NULL
            OR published_at_ms BETWEEN available_at_ms AND 253402300799999
        ),
    CONSTRAINT identity_log_outbox_error_code_valid
        CHECK (
            last_error_code IS NULL
            OR (
                octet_length(last_error_code) BETWEEN 1 AND 128
                AND last_error_code ~ '^[a-z0-9_.]+$'
                AND last_error_code !~ '(^|[.])[0-9_]'
                AND last_error_code !~ '(__|_($|[.])|[.]($|[.]))'
            )
        )
);

CREATE INDEX identity_log_outbox_dispatch_idx
    ON identity.log_outbox (available_at_ms, identity_id, entry_hash)
    WHERE published_at_ms IS NULL;

CREATE FUNCTION identity.enforce_log_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.identity_id IS DISTINCT FROM NEW.identity_id
       OR OLD.protocol_major IS DISTINCT FROM NEW.protocol_major
       OR OLD.protocol_minor IS DISTINCT FROM NEW.protocol_minor
       OR OLD.minimum_reader_major IS DISTINCT FROM NEW.minimum_reader_major
       OR OLD.minimum_reader_minor IS DISTINCT FROM NEW.minimum_reader_minor
       OR OLD.created_at_ms IS DISTINCT FROM NEW.created_at_ms THEN
        RAISE EXCEPTION 'identity log head immutable fields changed'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state IS DISTINCT FROM NEW.state THEN
        IF OLD.state <> 'active'
           OR OLD.head_sequence IS DISTINCT FROM NEW.head_sequence
           OR OLD.head_hash IS DISTINCT FROM NEW.head_hash
           OR OLD.updated_at_ms IS DISTINCT FROM NEW.updated_at_ms THEN
            RAISE EXCEPTION 'identity log state transition is not authorized'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.state = 'tombstoned' AND identity.identity_owner_authorized() THEN
            RETURN NEW;
        END IF;
        IF NEW.state = 'forked'
           AND (identity.identity_owner_authorized() OR identity.identity_runtime_authorized())
           AND EXISTS (
               SELECT 1
                 FROM identity.fork_evidence
                WHERE identity_id = OLD.identity_id
           ) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'identity log state transition is not authorized'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state <> 'active'
       OR NEW.head_sequence <> OLD.head_sequence + 1
       OR NEW.head_hash = OLD.head_hash
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'identity log head successor is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION identity.assert_log_chain(target_identity_id text)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    expected_sequence bigint;
    expected_hash bytea;
    entry_count bigint;
    first_sequence bigint;
    last_sequence bigint;
    actual_hash bytea;
BEGIN
    SELECT head_sequence, head_hash
      INTO expected_sequence, expected_hash
      FROM identity.log_heads
     WHERE identity_id = target_identity_id;
    IF expected_sequence IS NULL THEN
        RAISE EXCEPTION 'identity log entry has no head'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), min(sequence), max(sequence)
      INTO entry_count, first_sequence, last_sequence
      FROM identity.log_entries
     WHERE identity_id = target_identity_id;
    IF entry_count <> expected_sequence
       OR first_sequence <> 1
       OR last_sequence <> expected_sequence THEN
        RAISE EXCEPTION 'identity log sequence is not contiguous'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM identity.log_entries AS current_entry
          LEFT JOIN identity.log_entries AS previous_entry
            ON previous_entry.identity_id = current_entry.identity_id
           AND previous_entry.sequence = current_entry.sequence - 1
         WHERE current_entry.identity_id = target_identity_id
           AND (
                (current_entry.sequence = 1 AND current_entry.previous_hash IS NOT NULL)
                OR (
                    current_entry.sequence > 1
                    AND (
                        previous_entry.entry_hash IS NULL
                        OR current_entry.previous_hash IS DISTINCT FROM previous_entry.entry_hash
                    )
                )
           )
    ) THEN
        RAISE EXCEPTION 'identity log predecessor chain is invalid'
            USING ERRCODE = '23514';
    END IF;

    SELECT entry_hash
      INTO actual_hash
      FROM identity.log_entries
     WHERE identity_id = target_identity_id
       AND sequence = expected_sequence;
    IF actual_hash IS DISTINCT FROM expected_hash THEN
        RAISE EXCEPTION 'identity log head hash does not match entry'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION identity.enforce_log_head_chain()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM identity.assert_log_chain(NEW.identity_id);
    RETURN NULL;
END
$$;

CREATE FUNCTION identity.enforce_log_entry_chain()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM identity.assert_log_chain(
        CASE WHEN TG_OP = 'DELETE' THEN OLD.identity_id ELSE NEW.identity_id END
    );
    RETURN NULL;
END
$$;

CREATE FUNCTION identity.enforce_command_receipt_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' THEN
            RAISE EXCEPTION 'identity command receipt must enter pending'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'identity command receipt cannot be deleted'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state <> 'pending' OR NEW.state NOT IN ('committed', 'forked')
       OR OLD.identity_id IS DISTINCT FROM NEW.identity_id
       OR OLD.idempotency_key_hash IS DISTINCT FROM NEW.idempotency_key_hash
       OR OLD.request_digest IS DISTINCT FROM NEW.request_digest
       OR OLD.created_at_ms IS DISTINCT FROM NEW.created_at_ms THEN
        RAISE EXCEPTION 'identity command receipt transition is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION identity.enforce_completed_command_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM identity.command_receipts
         WHERE identity_id = NEW.identity_id
           AND idempotency_key_hash = NEW.idempotency_key_hash
           AND state = 'pending'
    ) THEN
        RAISE EXCEPTION 'identity command receipt must complete before commit'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER identity_log_heads_transition
BEFORE UPDATE ON identity.log_heads
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_log_head_transition();

CREATE TRIGGER identity_log_entries_append_only
BEFORE UPDATE OR DELETE ON identity.log_entries
FOR EACH ROW
EXECUTE FUNCTION identity.reject_immutable_mutation();

CREATE TRIGGER identity_fork_evidence_append_only
BEFORE UPDATE OR DELETE ON identity.fork_evidence
FOR EACH ROW
EXECUTE FUNCTION identity.reject_immutable_mutation();

CREATE TRIGGER identity_command_receipts_transition
BEFORE INSERT OR UPDATE OR DELETE ON identity.command_receipts
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_command_receipt_transition();

CREATE CONSTRAINT TRIGGER identity_log_heads_must_match_entries
AFTER INSERT OR UPDATE ON identity.log_heads
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_log_head_chain();

CREATE CONSTRAINT TRIGGER identity_log_entries_must_match_head
AFTER INSERT OR UPDATE OR DELETE ON identity.log_entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_log_entry_chain();

CREATE CONSTRAINT TRIGGER identity_command_receipts_must_complete
AFTER INSERT OR UPDATE ON identity.command_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_completed_command_receipt();

ALTER TABLE identity.log_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.log_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.log_heads
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER TABLE identity.log_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.log_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.log_entries
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER TABLE identity.command_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.command_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.command_receipts
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER TABLE identity.fork_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.fork_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.fork_evidence
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

ALTER TABLE identity.log_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.log_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_runtime_only ON identity.log_outbox
    USING (identity.identity_runtime_authorized() OR identity.identity_owner_authorized())
    WITH CHECK (identity.identity_runtime_authorized() OR identity.identity_owner_authorized());

REVOKE ALL ON SCHEMA identity FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA identity FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA identity FROM PUBLIC;
