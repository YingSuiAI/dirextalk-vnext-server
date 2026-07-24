CREATE TABLE agent.host_credential_authorization_credentials (
    tenant_id uuid NOT NULL,
    host_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    certificate_fingerprint bytea NOT NULL,
    not_before_unix_seconds bigint NOT NULL,
    not_after_unix_seconds bigint NOT NULL,
    first_authorization_revision bigint NOT NULL,
    registered_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, credential_id),
    CONSTRAINT host_auth_credentials_fingerprint_unique
        UNIQUE (tenant_id, certificate_fingerprint),
    CONSTRAINT host_auth_credentials_complete_key_unique
        UNIQUE (tenant_id, host_id, credential_id, certificate_fingerprint),
    CONSTRAINT host_auth_credentials_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_auth_credentials_registered_credential_fk
        FOREIGN KEY (tenant_id, host_id, credential_id)
        REFERENCES agent.host_credentials (tenant_id, host_id, credential_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_auth_credentials_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT host_auth_credentials_host_id_v7
        CHECK (system.is_uuid_v7(host_id)),
    CONSTRAINT host_auth_credentials_credential_id_v7
        CHECK (system.is_uuid_v7(credential_id)),
    CONSTRAINT host_auth_credentials_fingerprint_size
        CHECK (octet_length(certificate_fingerprint) = 32),
    CONSTRAINT host_auth_credentials_validity
        CHECK (
            not_before_unix_seconds BETWEEN 0 AND 253402300799
            AND not_after_unix_seconds BETWEEN 1 AND 253402300799
            AND not_before_unix_seconds < not_after_unix_seconds
        ),
    CONSTRAINT host_auth_credentials_first_revision_safe
        CHECK (first_authorization_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT host_auth_credentials_registered_at_valid
        CHECK (registered_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TRIGGER host_auth_credentials_append_only
BEFORE UPDATE OR DELETE ON agent.host_credential_authorization_credentials
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.host_credential_authorization_revisions (
    tenant_id uuid NOT NULL,
    authorization_revision bigint NOT NULL,
    credential_count bigint NOT NULL,
    current_count bigint NOT NULL,
    retired_count bigint NOT NULL,
    snapshot_digest bytea NOT NULL,
    recorded_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, authorization_revision),
    CONSTRAINT host_auth_revisions_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_auth_revisions_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT host_auth_revisions_revision_safe
        CHECK (authorization_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT host_auth_revisions_counts_valid
        CHECK (
            credential_count BETWEEN 0 AND 9007199254740991
            AND current_count BETWEEN 0 AND credential_count
            AND retired_count BETWEEN 0 AND credential_count
            AND current_count + retired_count = credential_count
        ),
    CONSTRAINT host_auth_revisions_digest_size
        CHECK (octet_length(snapshot_digest) = 32),
    CONSTRAINT host_auth_revisions_recorded_at_valid
        CHECK (recorded_at_ms BETWEEN -62135596800000 AND 253402300799999)
);

CREATE TRIGGER host_auth_revisions_append_only
BEFORE UPDATE OR DELETE ON agent.host_credential_authorization_revisions
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.host_credential_authorization_states (
    tenant_id uuid NOT NULL,
    authorization_revision bigint NOT NULL,
    host_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    certificate_fingerprint bytea NOT NULL,
    status text NOT NULL,
    revoked_at_unix_seconds bigint,
    PRIMARY KEY (tenant_id, authorization_revision, credential_id),
    CONSTRAINT host_auth_states_fingerprint_unique
        UNIQUE (tenant_id, authorization_revision, certificate_fingerprint),
    CONSTRAINT host_auth_states_revision_fk
        FOREIGN KEY (tenant_id, authorization_revision)
        REFERENCES agent.host_credential_authorization_revisions
            (tenant_id, authorization_revision)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_auth_states_credential_fk
        FOREIGN KEY (tenant_id, host_id, credential_id, certificate_fingerprint)
        REFERENCES agent.host_credential_authorization_credentials
            (tenant_id, host_id, credential_id, certificate_fingerprint)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_auth_states_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT host_auth_states_host_id_v7
        CHECK (system.is_uuid_v7(host_id)),
    CONSTRAINT host_auth_states_credential_id_v7
        CHECK (system.is_uuid_v7(credential_id)),
    CONSTRAINT host_auth_states_fingerprint_size
        CHECK (octet_length(certificate_fingerprint) = 32),
    CONSTRAINT host_auth_states_status_valid
        CHECK (status IN ('current', 'retired')),
    CONSTRAINT host_auth_states_revoked_at_valid
        CHECK (
            revoked_at_unix_seconds IS NULL
            OR revoked_at_unix_seconds BETWEEN 0 AND 253402300799
        )
);

CREATE UNIQUE INDEX host_auth_states_one_current_per_host_idx
    ON agent.host_credential_authorization_states
        (tenant_id, authorization_revision, host_id)
    WHERE status = 'current';

CREATE TRIGGER host_auth_states_append_only
BEFORE UPDATE OR DELETE ON agent.host_credential_authorization_states
FOR EACH ROW
EXECUTE FUNCTION agent.reject_immutable_mutation();

CREATE TABLE agent.host_credential_authorization_heads (
    tenant_id uuid PRIMARY KEY,
    current_revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT host_auth_heads_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES system.tenant_stream_heads (tenant_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_auth_heads_revision_fk
        FOREIGN KEY (tenant_id, current_revision)
        REFERENCES agent.host_credential_authorization_revisions
            (tenant_id, authorization_revision)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT host_auth_heads_tenant_id_v7
        CHECK (system.is_uuid_v7(tenant_id)),
    CONSTRAINT host_auth_heads_revision_safe
        CHECK (current_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT host_auth_heads_created_at_valid
        CHECK (created_at_ms BETWEEN -62135596800000 AND 253402300799999),
    CONSTRAINT host_auth_heads_updated_at_valid
        CHECK (updated_at_ms BETWEEN created_at_ms AND 253402300799999)
);

CREATE FUNCTION agent.enforce_host_auth_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Host credential authorization heads cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.current_revision <> 1 THEN
            RAISE EXCEPTION 'Host credential authorization must begin at revision one'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.current_revision <> OLD.current_revision + 1
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Host credential authorization head transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER host_auth_heads_transition
BEFORE INSERT OR UPDATE OR DELETE ON agent.host_credential_authorization_heads
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_host_auth_head_transition();

CREATE FUNCTION agent.enforce_host_auth_revision_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    head_revision bigint;
    high_water bigint;
    expected_revision bigint;
BEGIN
    PERFORM tenant_id
      FROM system.tenant_stream_heads
     WHERE tenant_id = NEW.tenant_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Host credential authorization tenant is unavailable'
            USING ERRCODE = '23503';
    END IF;

    SELECT current_revision
      INTO head_revision
      FROM agent.host_credential_authorization_heads
     WHERE tenant_id = NEW.tenant_id;
    SELECT max(authorization_revision)
      INTO high_water
      FROM agent.host_credential_authorization_revisions
     WHERE tenant_id = NEW.tenant_id;

    IF head_revision IS NULL THEN
        expected_revision := 1;
        IF high_water IS NOT NULL THEN
            RAISE EXCEPTION 'Host credential authorization history has no head'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        expected_revision := head_revision + 1;
        IF high_water IS DISTINCT FROM head_revision THEN
            RAISE EXCEPTION 'Host credential authorization history is not contiguous'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF NEW.authorization_revision <> expected_revision THEN
        RAISE EXCEPTION 'Host credential authorization revision is not the exact successor'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER host_auth_revision_insert
BEFORE INSERT ON agent.host_credential_authorization_revisions
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_host_auth_revision_insert();

CREATE FUNCTION agent.enforce_host_auth_state_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    head_revision bigint;
    expected_revision bigint;
BEGIN
    PERFORM tenant_id
      FROM system.tenant_stream_heads
     WHERE tenant_id = NEW.tenant_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Host credential authorization tenant is unavailable'
            USING ERRCODE = '23503';
    END IF;

    SELECT current_revision
      INTO head_revision
      FROM agent.host_credential_authorization_heads
     WHERE tenant_id = NEW.tenant_id;
    expected_revision := COALESCE(head_revision + 1, 1);

    IF NEW.authorization_revision <> expected_revision THEN
        RAISE EXCEPTION 'Host credential authorization state revision is already published'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM agent.host_credential_authorization_revisions
         WHERE tenant_id = NEW.tenant_id
           AND authorization_revision = NEW.authorization_revision
    ) THEN
        RAISE EXCEPTION 'Host credential authorization state has no revision'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER host_auth_state_insert
BEFORE INSERT ON agent.host_credential_authorization_states
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_host_auth_state_insert();

CREATE FUNCTION agent.enforce_host_auth_revision_published()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    stored_credential_count bigint;
    stored_current_count bigint;
    stored_retired_count bigint;
    actual_credential_count bigint;
    actual_current_count bigint;
    actual_retired_count bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM agent.host_credential_authorization_heads
         WHERE tenant_id = NEW.tenant_id
           AND current_revision >= NEW.authorization_revision
    ) THEN
        RAISE EXCEPTION 'Host credential authorization revision was not published'
            USING ERRCODE = '23514';
    END IF;

    SELECT credential_count, current_count, retired_count
      INTO stored_credential_count, stored_current_count, stored_retired_count
      FROM agent.host_credential_authorization_revisions
     WHERE tenant_id = NEW.tenant_id
       AND authorization_revision = NEW.authorization_revision;
    SELECT count(*),
           count(*) FILTER (WHERE status = 'current'),
           count(*) FILTER (WHERE status = 'retired')
      INTO actual_credential_count, actual_current_count, actual_retired_count
      FROM agent.host_credential_authorization_states
     WHERE tenant_id = NEW.tenant_id
       AND authorization_revision = NEW.authorization_revision;

    IF actual_credential_count IS DISTINCT FROM stored_credential_count
       OR actual_current_count IS DISTINCT FROM stored_current_count
       OR actual_retired_count IS DISTINCT FROM stored_retired_count THEN
        RAISE EXCEPTION 'Host credential authorization revision state is incomplete'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER host_auth_revision_published
AFTER INSERT ON agent.host_credential_authorization_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION agent.enforce_host_auth_revision_published();

ALTER TABLE agent.host_credential_authorization_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.host_credential_authorization_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.host_credential_authorization_credentials
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.host_credential_authorization_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.host_credential_authorization_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.host_credential_authorization_revisions
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.host_credential_authorization_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.host_credential_authorization_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.host_credential_authorization_states
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

ALTER TABLE agent.host_credential_authorization_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.host_credential_authorization_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.host_credential_authorization_heads
    USING (tenant_id = system.current_tenant_id())
    WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.host_credential_authorization_credentials FROM PUBLIC;
REVOKE ALL ON agent.host_credential_authorization_revisions FROM PUBLIC;
REVOKE ALL ON agent.host_credential_authorization_states FROM PUBLIC;
REVOKE ALL ON agent.host_credential_authorization_heads FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_host_auth_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_host_auth_revision_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_host_auth_state_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent.enforce_host_auth_revision_published() FROM PUBLIC;
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

