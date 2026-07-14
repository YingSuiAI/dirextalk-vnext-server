mod support;

use dtx_storage::{MigrationRunner, StorageError};
use support::PostgresHarness;
use uuid::Uuid;

const INITIAL_MIGRATION_VERSION: i64 = 202_607_130_001;
const AGENT_CONTROL_MIGRATION_VERSION: i64 = 202_607_130_002;
const HOST_AUTHORIZATION_MIGRATION_VERSION: i64 = 202_607_130_003;
const CONNECTOR_CONTROL_MIGRATION_VERSION: i64 = 202_607_130_004;
const AGENT_ROUTER_MIGRATION_VERSION: i64 = 202_607_130_005;
const HOST_PROVISIONING_MIGRATION_VERSION: i64 = 202_607_140_006;
const IDENTITY_LOG_MIGRATION_VERSION: i64 = 202_607_140_007;
const GROUP_MEMBERSHIP_MIGRATION_VERSION: i64 = 202_607_140_008;
const IDENTITY_BOOTSTRAP_CLAIMS_MIGRATION_VERSION: i64 = 202_607_140_009;
const DEVICE_SESSIONS_MIGRATION_VERSION: i64 = 202_607_140_010;
const DEVICE_ENROLLMENT_CHALLENGES_MIGRATION_VERSION: i64 = 202_607_140_011;
const KEY_PACKAGES_MIGRATION_VERSION: i64 = 202_607_150_012;
const EXPECTED_MIGRATION_COUNT: i64 = 12;
const INITIAL_DOWN: &str =
    include_str!("../../../migrations/202607130001_persistence_kernel.down.sql");
const AGENT_CONTROL_DOWN: &str =
    include_str!("../../../migrations/202607130002_agent_control_domain.down.sql");
const HOST_AUTHORIZATION_DOWN: &str =
    include_str!("../../../migrations/202607130003_host_credential_authorization.down.sql");
const CONNECTOR_CONTROL_DOWN: &str =
    include_str!("../../../migrations/202607130004_connector_control.down.sql");
const AGENT_ROUTER_DOWN: &str =
    include_str!("../../../migrations/202607130005_agent_router.down.sql");
const HOST_PROVISIONING_DOWN: &str =
    include_str!("../../../migrations/202607140006_host_provisioning.down.sql");
const IDENTITY_LOG_DOWN: &str =
    include_str!("../../../migrations/202607140007_identity_log_persistence.down.sql");
const GROUP_MEMBERSHIP_DOWN: &str =
    include_str!("../../../migrations/202607140008_group_membership_saga.down.sql");
const IDENTITY_BOOTSTRAP_CLAIMS_DOWN: &str =
    include_str!("../../../migrations/202607140009_identity_bootstrap_idempotency_claims.down.sql");
const DEVICE_SESSIONS_DOWN: &str =
    include_str!("../../../migrations/202607140010_device_sessions.down.sql");
const DEVICE_ENROLLMENT_CHALLENGES_DOWN: &str =
    include_str!("../../../migrations/202607140011_device_enrollment_challenges.down.sql");
const KEY_PACKAGES_DOWN: &str =
    include_str!("../../../migrations/202607150012_key_packages.down.sql");

#[tokio::test]
async fn applying_forward_migrations_twice_is_a_no_op() -> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;

    MigrationRunner::new().run(harness.admin_pool()).await?;

    let applied: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public._sqlx_migrations WHERE success = true")
            .fetch_one(harness.admin_pool())
            .await?;
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM system.schema_versions")
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(applied, EXPECTED_MIGRATION_COUNT);
    assert_eq!(visible, applied);
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one reversible migration test keeps the full ordered schema teardown auditable"
)]
async fn all_schemas_can_run_up_down_up_on_an_empty_database()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;

    sqlx::query(
        "DELETE FROM public._sqlx_migrations
          WHERE version IN ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(INITIAL_MIGRATION_VERSION)
    .bind(AGENT_CONTROL_MIGRATION_VERSION)
    .bind(HOST_AUTHORIZATION_MIGRATION_VERSION)
    .bind(CONNECTOR_CONTROL_MIGRATION_VERSION)
    .bind(AGENT_ROUTER_MIGRATION_VERSION)
    .bind(HOST_PROVISIONING_MIGRATION_VERSION)
    .bind(IDENTITY_LOG_MIGRATION_VERSION)
    .bind(GROUP_MEMBERSHIP_MIGRATION_VERSION)
    .bind(IDENTITY_BOOTSTRAP_CLAIMS_MIGRATION_VERSION)
    .bind(DEVICE_SESSIONS_MIGRATION_VERSION)
    .bind(DEVICE_ENROLLMENT_CHALLENGES_MIGRATION_VERSION)
    .bind(KEY_PACKAGES_MIGRATION_VERSION)
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql(KEY_PACKAGES_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(DEVICE_ENROLLMENT_CHALLENGES_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(DEVICE_SESSIONS_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(IDENTITY_BOOTSTRAP_CLAIMS_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(GROUP_MEMBERSHIP_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(IDENTITY_LOG_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(HOST_PROVISIONING_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_ROUTER_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(CONNECTOR_CONTROL_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(HOST_AUTHORIZATION_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_CONTROL_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(INITIAL_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let system_schema_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'system')")
            .fetch_one(harness.admin_pool())
            .await?;
    assert!(!system_schema_exists);
    let agent_schema_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'agent')")
            .fetch_one(harness.admin_pool())
            .await?;
    let identity_schema_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'identity')")
            .fetch_one(harness.admin_pool())
            .await?;
    let groups_schema_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'groups')")
            .fetch_one(harness.admin_pool())
            .await?;
    assert!(!agent_schema_exists);
    assert!(!identity_schema_exists);
    assert!(!groups_schema_exists);

    MigrationRunner::new().run(harness.admin_pool()).await?;

    let applied: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public._sqlx_migrations WHERE success = true")
            .fetch_one(harness.admin_pool())
            .await?;
    assert_eq!(applied, EXPECTED_MIGRATION_COUNT);
    let deferred_fence_triggers: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM pg_trigger
          WHERE tgname IN (
                    'connector_control_stream_fence',
                    'connector_instance_control_stream_fence'
                )
            AND tgconstraint <> 0
            AND tgdeferrable
            AND tginitdeferred",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(deferred_fence_triggers, 2);
    let identity_chain_triggers: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM pg_trigger
          WHERE tgname IN (
                    'identity_log_heads_must_match_entries',
                    'identity_log_entries_must_match_head',
                    'identity_command_receipts_must_complete'
                )
            AND tgconstraint <> 0
            AND tgdeferrable
            AND tginitdeferred",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(identity_chain_triggers, 3);
    Ok(())
}

#[tokio::test]
async fn runtime_role_is_non_owner_rls_bound_and_has_no_ddl()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let _runtime_store = harness.runtime_store(1).await?;
    let role_flags: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole
           FROM pg_roles
          WHERE rolname = 'dtx_runtime_test'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(role_flags, (false, false, false, false));

    let tenant_table_counts: (i64, i64) = sqlx::query_as(
        "SELECT count(*),
                count(*) FILTER (
                    WHERE c.relrowsecurity
                      AND c.relforcerowsecurity
                      AND pg_get_userbyid(c.relowner) <> 'dtx_runtime_test'
                )
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname IN ('system', 'agent')
            AND c.relkind = 'r'
            AND EXISTS (
                SELECT 1 FROM pg_attribute a
                 WHERE a.attrelid = c.oid
                   AND a.attname = 'tenant_id'
                   AND NOT a.attisdropped
            )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(tenant_table_counts.0 > 6, "agent tenant tables must exist");
    assert_eq!(tenant_table_counts.1, tenant_table_counts.0);

    let tenant_policies: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM pg_policies
          WHERE schemaname IN ('system', 'agent')
            AND policyname = 'tenant_isolation'
            AND qual LIKE '%current_tenant_id%'
            AND with_check LIKE '%current_tenant_id%'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(tenant_policies, tenant_table_counts.0);

    let dangerous_table_grants: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM information_schema.table_privileges
          WHERE grantee = 'dtx_runtime_test'
            AND table_schema IN ('system', 'agent')
            AND privilege_type IN ('DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(dangerous_table_grants, 0);
    assert_append_only_tables_have_no_update(&harness).await?;

    assert!(
        sqlx::query("CREATE TABLE system.runtime_must_not_create (id integer)")
            .execute(harness.runtime_pool())
            .await
            .is_err()
    );
    assert!(
        sqlx::query("CREATE TABLE agent.runtime_must_not_create (id integer)")
            .execute(harness.runtime_pool())
            .await
            .is_err()
    );
    assert!(
        sqlx::query("CREATE TABLE public.runtime_must_not_create (id integer)")
            .execute(harness.runtime_pool())
            .await
            .is_err()
    );

    assert_object_owner_membership_is_rejected(&harness).await?;
    assert_schema_creator_membership_is_rejected(&harness).await?;
    assert_predefined_role_membership_is_rejected(&harness).await?;
    Ok(())
}

async fn assert_append_only_tables_have_no_update(
    harness: &PostgresHarness,
) -> Result<(), Box<dyn std::error::Error>> {
    for table in [
        "agent.agent_definitions",
        "agent.connector_revisions",
        "agent.connector_conformance",
        "agent.conversation_grant_ids",
        "agent.conversation_grant_versions",
        "agent.conversation_grant_permissions",
        "agent.conversation_grant_cloud_connections",
        "agent.host_credential_authorization_credentials",
        "agent.host_credential_authorization_revisions",
        "agent.host_credential_authorization_states",
        "agent.connector_control_operations",
        "agent.connector_control_credentials",
        "agent.connector_control_credential_revisions",
        "agent.connector_control_credential_rotations",
        "agent.connector_runtime_claims",
        "agent.connector_control_commands",
        "agent.host_provisioning_operations",
        "identity.log_entries",
        "identity.fork_evidence",
        "identity.device_sessions",
        "identity.device_session_idempotency_claims",
        "identity.device_session_receipts",
        "identity.key_package_publish_claims",
        "identity.key_package_claims",
        "identity.key_package_claim_receipts",
    ] {
        let can_update: bool =
            sqlx::query_scalar("SELECT has_table_privilege('dtx_runtime_test', $1, 'UPDATE')")
                .bind(table)
                .fetch_one(harness.admin_pool())
                .await?;
        assert!(!can_update, "append-only table {table} exposed UPDATE");
    }
    Ok(())
}

async fn assert_object_owner_membership_is_rejected(
    harness: &PostgresHarness,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::raw_sql(
        "CREATE ROLE dtx_unsafe_system_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
         CREATE TABLE system.unsafe_parent_owned (id integer);
         ALTER TABLE system.unsafe_parent_owned OWNER TO dtx_unsafe_system_owner;
         GRANT dtx_unsafe_system_owner TO dtx_runtime_test;",
    )
    .execute(harness.admin_pool())
    .await?;
    let system_owner = harness
        .runtime_store(1)
        .await
        .expect_err("membership in a system object owner must be rejected");
    assert!(matches!(system_owner, StorageError::UnsafeRuntimeRole));

    sqlx::raw_sql(
        "REVOKE dtx_unsafe_system_owner FROM dtx_runtime_test;
         ALTER TABLE system.unsafe_parent_owned OWNER TO CURRENT_USER;
         DROP TABLE system.unsafe_parent_owned;
         DROP ROLE dtx_unsafe_system_owner;

         CREATE ROLE dtx_unsafe_agent_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
         CREATE TABLE agent.unsafe_parent_owned (id integer);
         ALTER TABLE agent.unsafe_parent_owned OWNER TO dtx_unsafe_agent_owner;
         GRANT dtx_unsafe_agent_owner TO dtx_runtime_test;",
    )
    .execute(harness.admin_pool())
    .await?;
    let agent_owner = harness
        .runtime_store(1)
        .await
        .expect_err("membership in an agent object owner must be rejected");
    assert!(matches!(agent_owner, StorageError::UnsafeRuntimeRole));
    sqlx::raw_sql(
        "REVOKE dtx_unsafe_agent_owner FROM dtx_runtime_test;
         ALTER TABLE agent.unsafe_parent_owned OWNER TO CURRENT_USER;
         DROP TABLE agent.unsafe_parent_owned;
         DROP ROLE dtx_unsafe_agent_owner;",
    )
    .execute(harness.admin_pool())
    .await?;
    harness.runtime_store(1).await?;
    Ok(())
}

async fn assert_schema_creator_membership_is_rejected(
    harness: &PostgresHarness,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::raw_sql(
        "CREATE ROLE dtx_unsafe_system_creator NOLOGIN NOSUPERUSER NOBYPASSRLS;
         GRANT CREATE ON SCHEMA system TO dtx_unsafe_system_creator;
         GRANT dtx_unsafe_system_creator TO dtx_runtime_test;",
    )
    .execute(harness.admin_pool())
    .await?;
    let system_creator = harness
        .runtime_store(1)
        .await
        .expect_err("membership in a system schema creator must be rejected");
    assert!(matches!(system_creator, StorageError::UnsafeRuntimeRole));
    sqlx::raw_sql(
        "REVOKE dtx_unsafe_system_creator FROM dtx_runtime_test;
         REVOKE CREATE ON SCHEMA system FROM dtx_unsafe_system_creator;
         DROP ROLE dtx_unsafe_system_creator;

         CREATE ROLE dtx_unsafe_agent_creator NOLOGIN NOSUPERUSER NOBYPASSRLS;
         GRANT CREATE ON SCHEMA agent TO dtx_unsafe_agent_creator;
         GRANT dtx_unsafe_agent_creator TO dtx_runtime_test;",
    )
    .execute(harness.admin_pool())
    .await?;
    let agent_creator = harness
        .runtime_store(1)
        .await
        .expect_err("membership in an agent schema creator must be rejected");
    assert!(matches!(agent_creator, StorageError::UnsafeRuntimeRole));
    sqlx::raw_sql(
        "REVOKE dtx_unsafe_agent_creator FROM dtx_runtime_test;
         REVOKE CREATE ON SCHEMA agent FROM dtx_unsafe_agent_creator;
         DROP ROLE dtx_unsafe_agent_creator;",
    )
    .execute(harness.admin_pool())
    .await?;
    harness.runtime_store(1).await?;
    Ok(())
}

async fn assert_predefined_role_membership_is_rejected(
    harness: &PostgresHarness,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query("GRANT pg_read_server_files TO dtx_runtime_test")
        .execute(harness.admin_pool())
        .await?;
    let predefined_role = harness
        .runtime_store(1)
        .await
        .expect_err("dangerous predefined role membership must be rejected");
    assert!(matches!(predefined_role, StorageError::UnsafeRuntimeRole));
    sqlx::query("REVOKE pg_read_server_files FROM dtx_runtime_test")
        .execute(harness.admin_pool())
        .await?;
    harness.runtime_store(1).await?;
    Ok(())
}

#[tokio::test]
async fn tenant_context_is_transaction_local_and_cross_tenant_rows_are_hidden()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let tenant_a = Uuid::parse_str("01890f3a-9d8b-7cc5-98c4-dc0c0c07398f")?;
    let tenant_b = Uuid::parse_str("01890f3a-9d8c-7cc5-98c4-dc0c0c07398f")?;

    let mut transaction = harness.runtime_pool().begin().await?;
    PostgresHarness::set_tenant(&mut transaction, tenant_a).await?;
    sqlx::query(
        "INSERT INTO system.tenant_stream_heads
             (tenant_id, last_sequence)
         VALUES ($1, 0)",
    )
    .bind(tenant_a)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let without_context: i64 =
        sqlx::query_scalar("SELECT count(*) FROM system.tenant_stream_heads")
            .fetch_one(harness.runtime_pool())
            .await?;
    assert_eq!(without_context, 0);

    let mut transaction = harness.runtime_pool().begin().await?;
    PostgresHarness::set_tenant(&mut transaction, tenant_b).await?;
    let cross_tenant: i64 = sqlx::query_scalar("SELECT count(*) FROM system.tenant_stream_heads")
        .fetch_one(&mut *transaction)
        .await?;
    assert_eq!(cross_tenant, 0);
    let error = sqlx::query(
        "INSERT INTO system.tenant_stream_heads
             (tenant_id, last_sequence)
         VALUES ($1, 0)",
    )
    .bind(tenant_a)
    .execute(&mut *transaction)
    .await
    .expect_err("RLS must reject writes for a different tenant");
    assert!(error.as_database_error().is_some());
    transaction.rollback().await?;

    assert_inbox_state_machine(&harness, tenant_a).await?;
    Ok(())
}

async fn assert_inbox_state_machine(
    harness: &PostgresHarness,
    tenant_a: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let direct_completed_command = Uuid::parse_str("01890f3a-9d8f-7cc5-98c4-dc0c0c07398f")?;
    let mut transaction = harness.runtime_pool().begin().await?;
    PostgresHarness::set_tenant(&mut transaction, tenant_a).await?;
    let direct_completed = sqlx::query(
        "INSERT INTO system.inbox_dedup (
             tenant_id, consumer, idempotency_key_hash, request_hash, command_id,
             state, result_bytes, result_hash, created_at_ms, completed_at_ms
         ) VALUES (
             $1, 'command.test', $2, $3, $4,
             'completed', $5, $6, 1721234567890, 1721234567891
         )",
    )
    .bind(tenant_a)
    .bind(vec![7_u8; 32])
    .bind(vec![8_u8; 32])
    .bind(direct_completed_command)
    .bind(Vec::<u8>::new())
    .bind(vec![9_u8; 32])
    .execute(&mut *transaction)
    .await;
    assert!(
        direct_completed.is_err(),
        "runtime commands must enter the inbox as pending"
    );
    transaction.rollback().await?;

    let pending_command = Uuid::parse_str("01890f3a-9d8d-7cc5-98c4-dc0c0c07398f")?;
    let mut transaction = harness.runtime_pool().begin().await?;
    PostgresHarness::set_tenant(&mut transaction, tenant_a).await?;
    sqlx::query(
        "INSERT INTO system.inbox_dedup (
             tenant_id, consumer, idempotency_key_hash, request_hash,
             command_id, state, created_at_ms
         ) VALUES ($1, 'command.test', $2, $3, $4, 'pending', 1721234567890)",
    )
    .bind(tenant_a)
    .bind(vec![1_u8; 32])
    .bind(vec![2_u8; 32])
    .bind(pending_command)
    .execute(&mut *transaction)
    .await?;
    assert!(
        transaction.commit().await.is_err(),
        "the deferred constraint must reject a committed pending command"
    );

    let completed_command = Uuid::parse_str("01890f3a-9d8e-7cc5-98c4-dc0c0c07398f")?;
    let mut transaction = harness.runtime_pool().begin().await?;
    PostgresHarness::set_tenant(&mut transaction, tenant_a).await?;
    sqlx::query(
        "INSERT INTO system.inbox_dedup (
             tenant_id, consumer, idempotency_key_hash, request_hash,
             command_id, state, created_at_ms
         ) VALUES ($1, 'command.test', $2, $3, $4, 'pending', 1721234567890)",
    )
    .bind(tenant_a)
    .bind(vec![3_u8; 32])
    .bind(vec![4_u8; 32])
    .bind(completed_command)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE system.inbox_dedup
            SET state = 'completed', result_bytes = $4, result_hash = $5,
                completed_at_ms = 1721234567891
          WHERE tenant_id = $1 AND consumer = 'command.test'
            AND idempotency_key_hash = $2 AND command_id = $3",
    )
    .bind(tenant_a)
    .bind(vec![3_u8; 32])
    .bind(completed_command)
    .bind(Vec::<u8>::new())
    .bind(vec![5_u8; 32])
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let mut transaction = harness.runtime_pool().begin().await?;
    PostgresHarness::set_tenant(&mut transaction, tenant_a).await?;
    let immutable_result = sqlx::query(
        "UPDATE system.inbox_dedup SET result_bytes = $2
          WHERE tenant_id = $1 AND command_id = $3",
    )
    .bind(tenant_a)
    .bind(b"rewritten".as_slice())
    .bind(completed_command)
    .execute(&mut *transaction)
    .await;
    assert!(
        immutable_result.is_err(),
        "a completed inbox result must be immutable"
    );
    transaction.rollback().await?;
    Ok(())
}
