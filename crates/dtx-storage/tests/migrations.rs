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
const MAILBOXES_MIGRATION_VERSION: i64 = 202_607_150_013;
const GROUP_DEVICE_SESSION_READER_MIGRATION_VERSION: i64 = 202_607_160_014;
const GROUP_CONTROL_COMMANDS_MIGRATION_VERSION: i64 = 202_607_160_015;
const AGENT_RUN_EXECUTION_MIGRATION_VERSION: i64 = 202_607_160_016;
const AGENT_RUN_CANCELLATION_MIGRATION_VERSION: i64 = 202_607_160_017;
const MLS_COMMIT_SEQUENCER_MIGRATION_VERSION: i64 = 202_607_160_018;
const AGENT_IDENTITY_PROVISIONING_MIGRATION_VERSION: i64 = 202_607_160_019;
const PUBLIC_FEED_MIGRATION_VERSION: i64 = 202_607_160_020;
const INDEXER_MIGRATION_VERSION: i64 = 202_607_160_021;
const INDEXER_DESCRIPTOR_HEADS_MIGRATION_VERSION: i64 = 202_607_160_022;
const CONTACT_DELIVERY_MIGRATION_VERSION: i64 = 202_607_160_023;
const OPAQUE_ATTACHMENTS_MIGRATION_VERSION: i64 = 202_607_160_024;
const GROUP_MEMBERSHIP_DISCOVERY_MIGRATION_VERSION: i64 = 202_607_160_025;
const PEER_ADMISSION_V30_MIGRATION_VERSION: i64 = 202_607_160_026;
const CONVERSATION_GRANT_OWNER_API_MIGRATION_VERSION: i64 = 202_607_160_027;
const CONVERSATION_GRANT_OWNER_RUNTIME_PRIVILEGES_MIGRATION_VERSION: i64 = 202_607_160_028;
const AGENT_ROUTE_RUN_INGRESS_MIGRATION_VERSION: i64 = 202_607_160_029;
const AGENT_ROUTE_BOOTSTRAP_V1_MIGRATION_VERSION: i64 = 202_607_160_030;
const CONNECTOR_BINDING_STATE_OWNER_API_MIGRATION_VERSION: i64 = 202_607_160_031;
const HERMES_ACP_ADAPTER_MIGRATION_VERSION: i64 = 202_607_160_032;
const FEDERATED_KEY_PACKAGE_CLAIMS_MIGRATION_VERSION: i64 = 202_607_160_033;
const PUBLIC_CACHE_GENERATIONS_MIGRATION_VERSION: i64 = 202_607_160_034;
const EXPECTED_MIGRATION_COUNT: i64 = 34;
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
const MAILBOXES_DOWN: &str = include_str!("../../../migrations/202607150013_mailboxes.down.sql");
const GROUP_DEVICE_SESSION_READER_DOWN: &str =
    include_str!("../../../migrations/202607160014_group_device_session_reader.down.sql");
const GROUP_CONTROL_COMMANDS_DOWN: &str =
    include_str!("../../../migrations/202607160015_group_control_commands.down.sql");
const AGENT_RUN_EXECUTION_DOWN: &str =
    include_str!("../../../migrations/202607160016_agent_run_execution.down.sql");
const AGENT_RUN_CANCELLATION_DOWN: &str =
    include_str!("../../../migrations/202607160017_agent_run_cancellation.down.sql");
const MLS_COMMIT_SEQUENCER_DOWN: &str =
    include_str!("../../../migrations/202607160018_mls_commit_sequencer.down.sql");
const AGENT_IDENTITY_PROVISIONING_DOWN: &str =
    include_str!("../../../migrations/202607160019_agent_identity_provisioning.down.sql");
const PUBLIC_FEED_DOWN: &str =
    include_str!("../../../migrations/202607160020_public_feed.down.sql");
const INDEXER_DOWN: &str = include_str!("../../../migrations/202607160021_indexer.down.sql");
const INDEXER_DESCRIPTOR_HEADS_DOWN: &str =
    include_str!("../../../migrations/202607160022_indexer_descriptor_heads.down.sql");
const CONTACT_DELIVERY_DOWN: &str =
    include_str!("../../../migrations/202607160023_contact_delivery.down.sql");
const OPAQUE_ATTACHMENTS_DOWN: &str =
    include_str!("../../../migrations/202607160024_opaque_attachments.down.sql");
const GROUP_MEMBERSHIP_DISCOVERY_DOWN: &str =
    include_str!("../../../migrations/202607160025_group_membership_discovery.down.sql");
const PEER_ADMISSION_V30_DOWN: &str =
    include_str!("../../../migrations/202607160026_peer_admission_v30.down.sql");
const CONVERSATION_GRANT_OWNER_API_DOWN: &str =
    include_str!("../../../migrations/202607160027_conversation_grant_owner_api.down.sql");
const CONVERSATION_GRANT_OWNER_RUNTIME_PRIVILEGES_DOWN: &str = include_str!(
    "../../../migrations/202607160028_conversation_grant_owner_runtime_privileges.down.sql"
);
const AGENT_ROUTE_RUN_INGRESS_DOWN: &str =
    include_str!("../../../migrations/202607160029_agent_route_run_ingress.down.sql");
const AGENT_ROUTE_BOOTSTRAP_V1_DOWN: &str =
    include_str!("../../../migrations/202607160030_agent_route_bootstrap_v1.down.sql");
const CONNECTOR_BINDING_STATE_OWNER_API_DOWN: &str =
    include_str!("../../../migrations/202607160031_connector_binding_state_owner_api.down.sql");
const HERMES_ACP_ADAPTER_DOWN: &str =
    include_str!("../../../migrations/202607160032_hermes_acp_adapter.down.sql");
const FEDERATED_KEY_PACKAGE_CLAIMS_DOWN: &str =
    include_str!("../../../migrations/202607160033_federated_key_package_claims.down.sql");
const PUBLIC_CACHE_GENERATIONS_DOWN: &str =
    include_str!("../../../migrations/202607160034_public_cache_generations.down.sql");
const PUBLIC_CACHE_GENERATIONS_UP: &str =
    include_str!("../../../migrations/202607160034_public_cache_generations.up.sql");

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
async fn public_cache_generation_migration_backfills_visible_indexers_only()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(PUBLIC_CACHE_GENERATIONS_DOWN)
        .execute(harness.admin_pool())
        .await?;

    let tenant = Uuid::now_v7();
    let visible_indexer = Uuid::now_v7();
    let rejected_indexer = Uuid::now_v7();
    for (subject, status, updated_at) in [
        ("dtxc1published", 2_i16, 10_i64),
        ("dtxc1revoked", 5_i16, 20_i64),
    ] {
        sqlx::query(
            "INSERT INTO directory.index_registrations(tenant_id,registration_id,indexer_id,subject_id,subject_kind,status,descriptor_sequence,descriptor_hash,descriptor_exact_cbor,created_at_ms,updated_at_ms) VALUES($1,$2,$3,$4,1,$5,1,$6,$7,$8,$8)",
        )
        .bind(tenant)
        .bind(Uuid::now_v7())
        .bind(visible_indexer)
        .bind(subject)
        .bind(status)
        .bind([u8::try_from(status)?; 32].as_slice())
        .bind([u8::try_from(status)?].as_slice())
        .bind(updated_at)
        .execute(harness.admin_pool())
        .await?;
    }
    sqlx::query(
        "INSERT INTO directory.index_registrations(tenant_id,registration_id,indexer_id,subject_id,subject_kind,status,descriptor_sequence,descriptor_hash,descriptor_exact_cbor,created_at_ms,updated_at_ms) VALUES($1,$2,$3,'dtxc1rejected',1,3,1,$4,$5,30,30)",
    )
    .bind(tenant)
    .bind(Uuid::now_v7())
    .bind(rejected_indexer)
    .bind([3_u8; 32].as_slice())
    .bind([3_u8].as_slice())
    .execute(harness.admin_pool())
    .await?;

    sqlx::raw_sql(PUBLIC_CACHE_GENERATIONS_UP)
        .execute(harness.admin_pool())
        .await?;
    let rows: Vec<(Uuid, i64, i64)> = sqlx::query_as(
        "SELECT indexer_id,generation,updated_at_ms FROM directory.index_cache_generations WHERE tenant_id=$1 ORDER BY indexer_id",
    )
    .bind(tenant)
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(rows, vec![(visible_indexer, 1, 20)]);
    let security: (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity,relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='directory' AND c.relname='index_cache_generations'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(security, (true, true));
    let public_grants: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.table_privileges WHERE table_schema='directory' AND table_name='index_cache_generations' AND grantee='PUBLIC'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(public_grants, 0);
    Ok(())
}

#[tokio::test]
async fn hermes_adapter_down_migration_refuses_to_orphan_durable_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let tenant_id = Uuid::now_v7();
    let host_id = Uuid::now_v7();
    let connector_id = Uuid::now_v7();
    let mut transaction = harness.admin_pool().begin().await?;
    sqlx::query("INSERT INTO system.tenant_stream_heads (tenant_id, last_sequence) VALUES ($1, 0)")
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO agent.hosts (
             tenant_id, host_id, owner_id, lifecycle, desired_revision,
             observed_revision, aggregate_revision, created_at_ms, updated_at_ms
         ) VALUES ($1, $2, $3, 'active', 1, 1, 1, 0, 0)",
    )
    .bind(tenant_id)
    .bind(host_id)
    .bind("dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la")
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.connector_instances (
             tenant_id, connector_id, host_id, adapter_kind, generation,
             desired_state, observed_state, max_concurrency, spec_revision,
             created_at_ms, updated_at_ms
         ) VALUES ($1, $2, $3, 'hermes_acp', 1, 'running', 'enrolling', 1, 1, 0, 0)",
    )
    .bind(tenant_id)
    .bind(connector_id)
    .bind(host_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.connector_revisions (
             tenant_id, connector_id, spec_revision, generation, adapter_kind,
             desired_state, max_concurrency, recorded_at_ms
         ) VALUES ($1, $2, 1, 1, 'hermes_acp', 'running', 1, 0)",
    )
    .bind(tenant_id)
    .bind(connector_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let error = sqlx::raw_sql(HERMES_ACP_ADAPTER_DOWN)
        .execute(harness.admin_pool())
        .await
        .expect_err("rollback must fail while Hermes rows exist");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database| database.code()),
        Some(std::borrow::Cow::Borrowed("55000")),
    );
    let hermes_constraints: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM pg_constraint
          WHERE conname IN (
                    'connector_instances_adapter_kind_valid',
                    'connector_revisions_adapter_kind_valid',
                    'connector_conformance_adapter_kind_valid'
                )
            AND pg_get_constraintdef(oid) LIKE '%hermes_acp%'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(hermes_constraints, 3);
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
          WHERE version IN ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34)",
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
    .bind(MAILBOXES_MIGRATION_VERSION)
    .bind(GROUP_DEVICE_SESSION_READER_MIGRATION_VERSION)
    .bind(GROUP_CONTROL_COMMANDS_MIGRATION_VERSION)
    .bind(AGENT_RUN_EXECUTION_MIGRATION_VERSION)
    .bind(AGENT_RUN_CANCELLATION_MIGRATION_VERSION)
    .bind(MLS_COMMIT_SEQUENCER_MIGRATION_VERSION)
    .bind(AGENT_IDENTITY_PROVISIONING_MIGRATION_VERSION)
    .bind(PUBLIC_FEED_MIGRATION_VERSION)
    .bind(INDEXER_MIGRATION_VERSION)
    .bind(INDEXER_DESCRIPTOR_HEADS_MIGRATION_VERSION)
    .bind(CONTACT_DELIVERY_MIGRATION_VERSION)
    .bind(OPAQUE_ATTACHMENTS_MIGRATION_VERSION)
    .bind(GROUP_MEMBERSHIP_DISCOVERY_MIGRATION_VERSION)
    .bind(PEER_ADMISSION_V30_MIGRATION_VERSION)
    .bind(CONVERSATION_GRANT_OWNER_API_MIGRATION_VERSION)
    .bind(CONVERSATION_GRANT_OWNER_RUNTIME_PRIVILEGES_MIGRATION_VERSION)
    .bind(AGENT_ROUTE_RUN_INGRESS_MIGRATION_VERSION)
    .bind(AGENT_ROUTE_BOOTSTRAP_V1_MIGRATION_VERSION)
    .bind(CONNECTOR_BINDING_STATE_OWNER_API_MIGRATION_VERSION)
    .bind(HERMES_ACP_ADAPTER_MIGRATION_VERSION)
    .bind(FEDERATED_KEY_PACKAGE_CLAIMS_MIGRATION_VERSION)
    .bind(PUBLIC_CACHE_GENERATIONS_MIGRATION_VERSION)
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql(PUBLIC_CACHE_GENERATIONS_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(FEDERATED_KEY_PACKAGE_CLAIMS_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(HERMES_ACP_ADAPTER_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(CONNECTOR_BINDING_STATE_OWNER_API_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_ROUTE_BOOTSTRAP_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_ROUTE_RUN_INGRESS_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(CONVERSATION_GRANT_OWNER_RUNTIME_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(CONVERSATION_GRANT_OWNER_API_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(PEER_ADMISSION_V30_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(GROUP_MEMBERSHIP_DISCOVERY_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(OPAQUE_ATTACHMENTS_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(CONTACT_DELIVERY_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(INDEXER_DESCRIPTOR_HEADS_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(INDEXER_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(PUBLIC_FEED_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_IDENTITY_PROVISIONING_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(MLS_COMMIT_SEQUENCER_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_RUN_CANCELLATION_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_RUN_EXECUTION_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(GROUP_CONTROL_COMMANDS_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(GROUP_DEVICE_SESSION_READER_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(MAILBOXES_DOWN)
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
    let messaging_schema_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'messaging')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!messaging_schema_exists);
    let directory_schema_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'directory')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!directory_schema_exists);

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

    let direct_group_table_grants: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM information_schema.table_privileges
          WHERE grantee = 'dtx_runtime_test'
            AND table_schema = 'groups'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(direct_group_table_grants, 0);
    let private_owner_assertion_available: bool = sqlx::query_scalar(
        "SELECT has_function_privilege(
                    'dtx_runtime_test',
                    'groups.private_conversation_owner_authorized(uuid,uuid,text)'::regprocedure,
                    'EXECUTE'
                )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(private_owner_assertion_available);
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
