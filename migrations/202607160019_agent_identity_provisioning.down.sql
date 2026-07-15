DROP TABLE IF EXISTS agent.agent_installation_revocations;
DROP TABLE IF EXISTS agent.agent_provisioning_outbox;
ALTER TABLE agent.agent_provisioning_recipients DROP CONSTRAINT IF EXISTS agent_provisioning_recipients_delivery_fk;
DROP TABLE IF EXISTS agent.agent_provisioning_deliveries;
DROP TABLE IF EXISTS agent.agent_provisioning_recipients;
DROP TABLE IF EXISTS agent.agent_identity_approvals;

ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (
        CASE WHEN COALESCE(pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'), false)
            THEN has_function_privilege(current_user, 'identity.identity_group_reader_authorized()'::regprocedure, 'EXECUTE')
            ELSE COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
              OR COALESCE(pg_has_role(current_user, to_regrole('dtx_mailbox_runtime'), 'MEMBER'), false)
              OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity') END
    )
    WITH CHECK (COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
        OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity'));
ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (
        CASE WHEN COALESCE(pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'), false)
            THEN has_function_privilege(current_user, 'identity.identity_group_reader_authorized()'::regprocedure, 'EXECUTE')
            ELSE COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
              OR COALESCE(pg_has_role(current_user, to_regrole('dtx_mailbox_runtime'), 'MEMBER'), false)
              OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity') END
    )
    WITH CHECK (COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
        OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity'));
ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (
        CASE WHEN COALESCE(pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'), false)
            THEN has_function_privilege(current_user, 'identity.identity_group_reader_authorized()'::regprocedure, 'EXECUTE')
            ELSE COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
              OR COALESCE(pg_has_role(current_user, to_regrole('dtx_mailbox_runtime'), 'MEMBER'), false)
              OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity') END
    )
    WITH CHECK (COALESCE(pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'), false)
        OR current_user = (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='identity'));
DO $revoke$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        REVOKE EXECUTE ON FUNCTION identity.identity_agent_reader_authorized() FROM dtx_agent_runtime;
        REVOKE SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries FROM dtx_agent_runtime;
        REVOKE USAGE ON SCHEMA identity FROM dtx_agent_runtime;
    END IF;
END
$revoke$;
DROP FUNCTION identity.identity_agent_reader_authorized();
ALTER TABLE agent.agent_devices DROP CONSTRAINT IF EXISTS agent_devices_identity_device_unique;
ALTER TABLE agent.agent_devices DROP CONSTRAINT IF EXISTS agent_devices_identity_device_id_v7;
ALTER TABLE agent.agent_devices DROP COLUMN IF EXISTS identity_device_id;
ALTER TABLE agent.installations DROP CONSTRAINT IF EXISTS installations_agent_identity_unique;
ALTER TABLE agent.installations DROP CONSTRAINT IF EXISTS installations_agent_identity_id_valid;
ALTER TABLE agent.installations DROP COLUMN IF EXISTS agent_identity_id;

CREATE OR REPLACE FUNCTION agent.enforce_installation_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Agent installations cannot be deleted' USING ERRCODE = '55000'; END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
       OR NEW.agent_id IS DISTINCT FROM OLD.agent_id OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
       OR NEW.execution_mode IS DISTINCT FROM OLD.execution_mode OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.aggregate_revision <> OLD.aggregate_revision + 1 OR NEW.descriptor_version < OLD.descriptor_version
       OR NEW.policy_revision < OLD.policy_revision OR OLD.desired_state = 'revoked'
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Agent installation transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION agent.enforce_agent_device_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Agent Devices cannot be deleted' USING ERRCODE = '55000'; END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.agent_device_id IS DISTINCT FROM OLD.agent_device_id
       OR NEW.installation_id IS DISTINCT FROM OLD.installation_id OR NEW.credential_fingerprint IS DISTINCT FROM OLD.credential_fingerprint
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms OR NEW.aggregate_revision <> OLD.aggregate_revision + 1
       OR OLD.state = 'revoked' OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'invalid Agent Device transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
