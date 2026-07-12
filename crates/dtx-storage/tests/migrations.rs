mod support;

use dtx_storage::{MigrationRunner, StorageError};
use support::PostgresHarness;
use uuid::Uuid;

const INITIAL_MIGRATION_VERSION: i64 = 202_607_130_001;
const INITIAL_DOWN: &str =
    include_str!("../../../migrations/202607130001_persistence_kernel.down.sql");

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
    assert_eq!(applied, 1);
    assert_eq!(visible, applied);
    Ok(())
}

#[tokio::test]
async fn initial_schema_can_run_up_down_up_on_an_empty_database()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;

    sqlx::query("DELETE FROM public._sqlx_migrations WHERE version = $1")
        .bind(INITIAL_MIGRATION_VERSION)
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

    MigrationRunner::new().run(harness.admin_pool()).await?;

    let applied: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public._sqlx_migrations WHERE success = true")
            .fetch_one(harness.admin_pool())
            .await?;
    assert_eq!(applied, 1);
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

    let protected_tables: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'system'
            AND c.relname IN (
              'tenant_stream_heads', 'durable_events', 'outbox_events',
              'inbox_dedup', 'audit_events', 'projection_cursors'
            )
            AND c.relrowsecurity
            AND c.relforcerowsecurity
            AND pg_get_userbyid(c.relowner) <> 'dtx_runtime_test'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(protected_tables, 6);

    let tenant_policies: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM pg_policies
          WHERE schemaname = 'system'
            AND policyname = 'tenant_isolation'
            AND qual LIKE '%current_tenant_id%'
            AND with_check LIKE '%current_tenant_id%'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(tenant_policies, 6);

    let can_delete_outbox: bool = sqlx::query_scalar(
        "SELECT has_table_privilege(
            'dtx_runtime_test', 'system.outbox_events', 'DELETE'
        )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    let can_delete_inbox: bool = sqlx::query_scalar(
        "SELECT has_table_privilege(
            'dtx_runtime_test', 'system.inbox_dedup', 'DELETE'
        )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!can_delete_outbox);
    assert!(!can_delete_inbox);

    assert!(
        sqlx::query("CREATE TABLE system.runtime_must_not_create (id integer)")
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

    harness.runtime_store(1).await?;
    sqlx::raw_sql(
        "CREATE ROLE dtx_unsafe_parent NOLOGIN NOSUPERUSER NOBYPASSRLS;
         CREATE TABLE system.unsafe_parent_owned (id integer);
         ALTER TABLE system.unsafe_parent_owned OWNER TO dtx_unsafe_parent;
         GRANT dtx_unsafe_parent TO dtx_runtime_test;",
    )
    .execute(harness.admin_pool())
    .await?;
    let unsafe_role = harness
        .runtime_store(1)
        .await
        .expect_err("membership in a system object owner must be rejected");
    assert!(matches!(unsafe_role, StorageError::UnsafeRuntimeRole));

    sqlx::raw_sql(
        "REVOKE dtx_unsafe_parent FROM dtx_runtime_test;
         ALTER TABLE system.unsafe_parent_owned OWNER TO dtx_test_admin;
         DROP TABLE system.unsafe_parent_owned;
         DROP ROLE dtx_unsafe_parent;",
    )
    .execute(harness.admin_pool())
    .await?;
    harness.runtime_store(1).await?;
    sqlx::query("GRANT pg_read_server_files TO dtx_runtime_test")
        .execute(harness.admin_pool())
        .await?;
    let predefined_role = harness
        .runtime_store(1)
        .await
        .expect_err("dangerous predefined role membership must be rejected");
    assert!(matches!(predefined_role, StorageError::UnsafeRuntimeRole));
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
