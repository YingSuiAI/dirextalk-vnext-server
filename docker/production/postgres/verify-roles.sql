DO $verify$
DECLARE
    role_name text;
    expected_membership text;
    expected_inherit boolean;
    actual_memberships text[];
BEGIN
    FOR role_name, expected_membership, expected_inherit IN
        VALUES
            ('dtx_identity_node','dtx_identity_runtime',true),
            ('dtx_group_node','dtx_group_runtime',true),
            ('dtx_mailbox_node','dtx_mailbox_runtime',true),
            ('dtx_push_registration','dtx_push_registration_runtime',true),
            ('dtx_push_identity_auth','dtx_push_identity_auth_runtime',true),
            ('dtx_realtime_sync_gateway','dtx_realtime_sync_runtime',true),
            ('dtx_push_broker','dtx_push_broker_runtime',true),
            ('dtx_public_feed_node','dtx_public_feed_runtime',false),
            ('dtx_indexer_node','dtx_public_feed_runtime',false),
            ('dtx_agent_control','dtx_agent_runtime',true)
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = role_name AND rolcanlogin
                AND rolinherit = expected_inherit AND NOT rolsuper AND NOT rolbypassrls
                AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication
        ) THEN
            RAISE EXCEPTION 'managed login role attributes are not normalized: %', role_name;
        END IF;
        SELECT coalesce(array_agg(granted.rolname ORDER BY granted.rolname), ARRAY[]::name[])
          INTO actual_memberships
          FROM pg_auth_members edges
          JOIN pg_roles granted ON granted.oid = edges.roleid
          JOIN pg_roles member ON member.oid = edges.member
         WHERE member.rolname = role_name;
        IF actual_memberships IS DISTINCT FROM ARRAY[expected_membership]::text[] THEN
            RAISE EXCEPTION 'managed login role membership is not exact: %', role_name;
        END IF;
    END LOOP;

    FOR role_name IN
        SELECT DISTINCT membership FROM (VALUES
            ('dtx_identity_runtime'), ('dtx_group_runtime'), ('dtx_mailbox_runtime'),
            ('dtx_push_registration_runtime'), ('dtx_push_identity_auth_runtime'),
            ('dtx_realtime_sync_runtime'), ('dtx_push_broker_runtime'),
            ('dtx_public_feed_runtime'), ('dtx_agent_runtime')) AS memberships(membership)
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = role_name AND NOT rolcanlogin
                AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls
                AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication
        ) OR EXISTS (
            SELECT 1 FROM pg_auth_members edges
            JOIN pg_roles member ON member.oid = edges.member
            WHERE member.rolname = role_name
        ) THEN
            RAISE EXCEPTION 'membership role attributes or memberships are not exact: %', role_name;
        END IF;
    END LOOP;

    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
         WHERE rolname = 'dtx_agent_peer_admin'
           AND NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls
           AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication
    ) OR EXISTS (
        SELECT 1
          FROM pg_auth_members edges
          JOIN pg_roles member ON member.oid = edges.member
         WHERE member.rolname = 'dtx_agent_peer_admin'
    ) THEN
        RAISE EXCEPTION 'Agent peer admin role attributes or memberships are not exact';
    END IF;

    IF NOT has_schema_privilege('dtx_agent_peer_admin', 'agent', 'USAGE')
       OR has_schema_privilege('dtx_agent_peer_admin', 'agent', 'CREATE')
       OR EXISTS (
            SELECT 1 FROM pg_namespace namespace
             WHERE namespace.nspname IN ('system', 'agent', 'identity', 'groups', 'directory')
               AND namespace.nspname <> 'agent'
               AND has_schema_privilege('dtx_agent_peer_admin', namespace.oid, 'USAGE')
       )
       OR EXISTS (
            SELECT 1 FROM pg_namespace namespace
             WHERE namespace.nspname IN ('system', 'agent', 'identity', 'groups', 'directory')
               AND has_schema_privilege('dtx_agent_peer_admin', namespace.oid, 'CREATE')
       )
       OR NOT has_function_privilege(
            'dtx_agent_peer_admin',
            'agent.register_mcp_credential_digest(uuid,uuid,bytea,uuid,uuid,uuid,text,uuid,text,bigint,bigint)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'dtx_agent_peer_admin',
            'agent.revoke_mcp_credential_digest(uuid,uuid,bytea,bigint)',
            'EXECUTE'
       )
       OR EXISTS (
            SELECT 1 FROM pg_proc procedure
            JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
             WHERE namespace.nspname IN ('system', 'agent', 'identity', 'groups', 'directory')
               AND has_function_privilege('dtx_agent_peer_admin', procedure.oid, 'EXECUTE')
               AND procedure.oid NOT IN (
                   'agent.register_mcp_credential_digest(uuid,uuid,bytea,uuid,uuid,uuid,text,uuid,text,bigint,bigint)'::regprocedure,
                   'agent.revoke_mcp_credential_digest(uuid,uuid,bytea,bigint)'::regprocedure
               )
       )
       OR EXISTS (
            SELECT 1 FROM pg_class relation
            JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
             WHERE namespace.nspname IN ('system', 'agent', 'identity', 'groups', 'directory')
               AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
               AND (
                   has_table_privilege('dtx_agent_peer_admin', relation.oid, 'SELECT')
                   OR has_table_privilege('dtx_agent_peer_admin', relation.oid, 'INSERT')
                   OR has_table_privilege('dtx_agent_peer_admin', relation.oid, 'UPDATE')
                   OR has_table_privilege('dtx_agent_peer_admin', relation.oid, 'DELETE')
                   OR has_table_privilege('dtx_agent_peer_admin', relation.oid, 'TRUNCATE')
                   OR has_table_privilege('dtx_agent_peer_admin', relation.oid, 'REFERENCES')
                   OR has_table_privilege('dtx_agent_peer_admin', relation.oid, 'TRIGGER')
               )
       )
    THEN
        RAISE EXCEPTION 'Agent peer admin privilege boundary check failed';
    END IF;

    IF NOT has_schema_privilege('dtx_agent_control', 'agent', 'USAGE')
       OR NOT has_table_privilege('dtx_agent_control', 'agent.connector_control_operations', 'SELECT')
       OR NOT has_table_privilege('dtx_agent_control', 'agent.connector_control_operations', 'INSERT')
       OR NOT has_table_privilege('dtx_agent_control', 'agent.connector_bootstrap_issuances', 'SELECT')
       OR NOT has_table_privilege('dtx_agent_control', 'agent.connector_bootstrap_issuances', 'INSERT')
       OR NOT has_table_privilege('dtx_agent_control', 'system.schema_versions', 'SELECT')
       OR has_schema_privilege('dtx_agent_control', 'agent', 'CREATE')
       OR has_table_privilege('dtx_agent_control', 'agent.connector_control_operations', 'TRUNCATE')
       OR has_table_privilege('dtx_agent_control', 'agent.connector_bootstrap_issuances', 'UPDATE')
       OR has_table_privilege('dtx_agent_control', 'directory.index_registrations', 'UPDATE')
    THEN
        RAISE EXCEPTION 'Agent Control readiness or negative privilege check failed';
    END IF;

    IF NOT has_schema_privilege('dtx_indexer_node', 'directory', 'USAGE')
       OR NOT has_function_privilege('dtx_indexer_node', 'system.is_uuid_v7(uuid)', 'EXECUTE')
       OR NOT has_function_privilege('dtx_public_feed_node', 'system.is_uuid_v7(uuid)', 'EXECUTE')
       OR has_function_privilege('dtx_indexer_node', 'system.current_tenant_id()', 'EXECUTE')
       OR has_function_privilege('dtx_public_feed_node', 'system.current_tenant_id()', 'EXECUTE')
       OR has_function_privilege('dtx_indexer_node', 'system.is_stable_code(text,integer)', 'EXECUTE')
       OR has_function_privilege('dtx_public_feed_node', 'system.is_stable_code(text,integer)', 'EXECUTE')
       OR NOT has_table_privilege('dtx_indexer_node', 'directory.index_registrations', 'SELECT')
       OR NOT has_table_privilege('dtx_indexer_node', 'directory.index_registrations', 'INSERT')
       OR NOT has_table_privilege('dtx_indexer_node', 'directory.index_registrations', 'UPDATE')
       OR NOT has_table_privilege('dtx_indexer_node', 'directory.index_cache_generations', 'SELECT')
       OR NOT has_table_privilege('dtx_indexer_node', 'directory.index_cache_generations', 'INSERT')
       OR NOT has_table_privilege('dtx_indexer_node', 'directory.index_cache_generations', 'UPDATE')
       OR has_table_privilege('dtx_public_feed_node', 'directory.index_registrations', 'UPDATE')
       OR has_table_privilege('dtx_indexer_node', 'directory.public_subjects', 'UPDATE')
    THEN
        RAISE EXCEPTION 'feed/indexer readiness or direct-grant boundary check failed';
    END IF;
END
$verify$;
