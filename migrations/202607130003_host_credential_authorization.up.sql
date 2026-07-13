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
