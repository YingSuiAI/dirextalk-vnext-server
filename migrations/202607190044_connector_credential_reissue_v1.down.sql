-- V44 introduces same-generation credential history that V43 cannot represent without deleting
-- audit facts. Refuse before any DDL whenever a reissue fact exists; an empty-data downgrade is
-- lossless and restores the exact V43 constraints and trigger functions below.
DO $preflight$
DECLARE
    intent_count bigint;
    credential_count bigint;
    revision_count bigint;
    operation_count bigint;
BEGIN
    SELECT count(*) INTO intent_count
      FROM agent.connector_credential_reissue_intents;
    SELECT count(*) INTO credential_count
      FROM agent.connector_control_credentials
     WHERE origin_kind = 'reissue';
    SELECT count(*) INTO revision_count
      FROM agent.connector_control_credential_revisions
     WHERE cause_kind IN ('reissue_started', 'reissue_promoted');
    SELECT count(*) INTO operation_count
      FROM agent.connector_control_operations
     WHERE operation_kind = 'credential_reissue';

    IF intent_count <> 0
       OR credential_count <> 0
       OR revision_count <> 0
       OR operation_count <> 0 THEN
        RAISE EXCEPTION
            'cannot downgrade connector credential reissue V1 while reissue history exists'
            USING
                ERRCODE = '55000',
                DETAIL = format(
                    'reissue intents=%s credentials=%s authorization revisions=%s operations=%s',
                    intent_count, credential_count, revision_count, operation_count
                ),
                HINT =
                    'Keep schema version 44 or later. Complete or abort any live recovery, archive the tenant-scoped audit history, and remove it only through an explicitly authorized recovery procedure before retrying the downgrade.';
    END IF;
END
$preflight$;

DROP TABLE agent.connector_credential_reissue_intents;
DROP FUNCTION agent.enforce_connector_credential_reissue_transition();

ALTER TABLE agent.connector_control_credentials
    DROP CONSTRAINT connector_control_credentials_origin_valid,
    ADD CONSTRAINT connector_control_credentials_origin_valid CHECK (
        (origin_kind = 'enrollment'
            AND enrollment_intent_id IS NOT NULL
            AND predecessor_credential_id IS NULL)
        OR (origin_kind = 'rotation'
            AND enrollment_intent_id IS NULL
            AND predecessor_credential_id IS NOT NULL)
    ),
    ADD CONSTRAINT connector_control_credentials_generation_unique
        UNIQUE (tenant_id, connector_id, connector_generation),
    ADD CONSTRAINT connector_control_credentials_revision_unique
        UNIQUE (tenant_id, connector_id, credential_revision);

ALTER TABLE agent.connector_control_operations
    DROP CONSTRAINT connector_control_operations_kind_valid,
    ADD CONSTRAINT connector_control_operations_kind_valid CHECK (
        operation_kind IN (
            'enrollment', 'apply_config', 'rotate_credential', 'close_stream',
            'deliver_agent_provisioning', 'revoke_agent_provisioning',
            'prepare_agent_route_recipient', 'deliver_agent_route_bootstrap'
        )
    );

ALTER TABLE agent.connector_control_credential_revisions
    DROP CONSTRAINT connector_credential_revisions_cause_valid,
    ADD CONSTRAINT connector_credential_revisions_cause_valid CHECK (
        cause_kind IN ('enrollment', 'rotation_started', 'rotation_promoted', 'revoked')
    );

CREATE OR REPLACE FUNCTION agent.enforce_connector_control_credential_insert()
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

CREATE OR REPLACE FUNCTION agent.enforce_connector_control_operation_published()
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

CREATE OR REPLACE FUNCTION agent.enforce_connector_enrollment_consumed()
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

CREATE OR REPLACE FUNCTION agent.enforce_connector_credential_revision_insert()
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
