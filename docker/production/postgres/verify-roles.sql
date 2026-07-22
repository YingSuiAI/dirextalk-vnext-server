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

    IF NOT has_schema_privilege('dtx_agent_control', 'agent', 'USAGE')
       OR NOT has_table_privilege('dtx_agent_control', 'agent.connector_control_operations', 'SELECT')
       OR NOT has_table_privilege('dtx_agent_control', 'agent.connector_control_operations', 'INSERT')
       OR NOT has_table_privilege('dtx_agent_control', 'system.schema_versions', 'SELECT')
       OR has_schema_privilege('dtx_agent_control', 'agent', 'CREATE')
       OR has_table_privilege('dtx_agent_control', 'agent.connector_control_operations', 'TRUNCATE')
       OR has_table_privilege('dtx_agent_control', 'directory.index_registrations', 'UPDATE')
    THEN
        RAISE EXCEPTION 'Agent Control readiness or negative privilege check failed';
    END IF;

    IF has_table_privilege('dtx_public_feed_node', 'directory.index_registrations', 'UPDATE')
       OR has_table_privilege('dtx_indexer_node', 'directory.public_subjects', 'UPDATE')
    THEN
        RAISE EXCEPTION 'feed/indexer direct-grant boundary widened';
    END IF;
END
$verify$;
