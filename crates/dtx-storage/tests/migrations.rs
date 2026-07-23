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
const AGENT_RUN_RUNTIME_PRIVILEGES_MIGRATION_VERSION: i64 = 202_607_170_035;
const GROUP_MEMBER_REMOVAL_V32_MIGRATION_VERSION: i64 = 202_607_170_036;
const MCP_REFERENCE_QUERIES_MIGRATION_VERSION: i64 = 202_607_170_037;
const AGENT_MCP_CREDENTIALS_MIGRATION_VERSION: i64 = 202_607_170_038;
const AGENT_ACCEPTANCE_FINALIZE_PRIVILEGES_MIGRATION_VERSION: i64 = 202_607_170_039;
const AGENT_ACCEPTANCE_PREPARE_PRIVILEGES_MIGRATION_VERSION: i64 = 202_607_180_040;
const AGENT_ACCEPTANCE_TENANT_STREAM_PRIVILEGES_MIGRATION_VERSION: i64 = 202_607_180_041;
const AGENT_ACCEPTANCE_TENANT_STREAM_SELECT_MIGRATION_VERSION: i64 = 202_607_180_042;
const PUBLIC_DISCUSSION_V1_MIGRATION_VERSION: i64 = 202_607_190_043;
const CONNECTOR_CREDENTIAL_REISSUE_V1_MIGRATION_VERSION: i64 = 202_607_190_044;
const REALTIME_SYNC_MULTIDEVICE_MAILBOX_V1_MIGRATION_VERSION: i64 = 202_607_200_045;
const ACCOUNT_RECOVERY_REALTIME_OUTBOX_V1_MIGRATION_VERSION: i64 = 202_607_200_046;
const REALTIME_SYNC_CONTINUITY_V2_MIGRATION_VERSION: i64 = 202_607_200_047;
const HISTORY_RECOVERY_V1_MIGRATION_VERSION: i64 = 202_607_200_048;
const REALTIME_SYNC_RETENTION_SAFETY_V1_MIGRATION_VERSION: i64 = 202_607_200_049;
const MAILBOX_RETAINED_QUOTA_GC_V1_MIGRATION_VERSION: i64 = 202_607_200_050;
const FEDERATED_MLS_V5_AUTHORIZATION_V1_MIGRATION_VERSION: i64 = 202_607_200_051;
const RECOVERY_SCOPE_CATALOG_V1_MIGRATION_VERSION: i64 = 202_607_210_052;
const OPAQUE_PUSH_V1_MIGRATION_VERSION: i64 = 202_607_220_053;
const CONNECTOR_BOOTSTRAP_ISSUANCE_V1_MIGRATION_VERSION: i64 = 202_607_220_054;
const AGENT_IDENTITY_READER_RLS_FIX_MIGRATION_VERSION: i64 = 202_607_230_055;
const EXPECTED_MIGRATION_COUNT: i64 = 56;
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
const AGENT_RUN_RUNTIME_PRIVILEGES_DOWN: &str =
    include_str!("../../../migrations/202607170035_agent_run_runtime_privileges.down.sql");
const AGENT_RUN_RUNTIME_PRIVILEGES_UP: &str =
    include_str!("../../../migrations/202607170035_agent_run_runtime_privileges.up.sql");
const GROUP_MEMBER_REMOVAL_V32_DOWN: &str =
    include_str!("../../../migrations/202607170036_group_member_removal_v32.down.sql");
const MCP_REFERENCE_QUERIES_DOWN: &str =
    include_str!("../../../migrations/202607170037_mcp_reference_queries.down.sql");
const AGENT_MCP_CREDENTIALS_DOWN: &str =
    include_str!("../../../migrations/202607170038_agent_mcp_credentials.down.sql");
const AGENT_ACCEPTANCE_FINALIZE_PRIVILEGES_DOWN: &str =
    include_str!("../../../migrations/202607170039_agent_acceptance_finalize_privileges.down.sql");
const AGENT_ACCEPTANCE_FINALIZE_PRIVILEGES_UP: &str =
    include_str!("../../../migrations/202607170039_agent_acceptance_finalize_privileges.up.sql");
const AGENT_ACCEPTANCE_PREPARE_PRIVILEGES_DOWN: &str =
    include_str!("../../../migrations/202607180040_agent_acceptance_prepare_privileges.down.sql");
const AGENT_ACCEPTANCE_PREPARE_PRIVILEGES_UP: &str =
    include_str!("../../../migrations/202607180040_agent_acceptance_prepare_privileges.up.sql");
const AGENT_ACCEPTANCE_TENANT_STREAM_PRIVILEGES_DOWN: &str = include_str!(
    "../../../migrations/202607180041_agent_acceptance_tenant_stream_privileges.down.sql"
);
const AGENT_ACCEPTANCE_TENANT_STREAM_PRIVILEGES_UP: &str = include_str!(
    "../../../migrations/202607180041_agent_acceptance_tenant_stream_privileges.up.sql"
);
const AGENT_ACCEPTANCE_TENANT_STREAM_SELECT_DOWN: &str =
    include_str!("../../../migrations/202607180042_agent_acceptance_tenant_stream_select.down.sql");
const AGENT_ACCEPTANCE_TENANT_STREAM_SELECT_UP: &str =
    include_str!("../../../migrations/202607180042_agent_acceptance_tenant_stream_select.up.sql");
const PUBLIC_DISCUSSION_V1_DOWN: &str =
    include_str!("../../../migrations/202607190043_public_discussion_v1.down.sql");
const CONNECTOR_CREDENTIAL_REISSUE_V1_DOWN: &str =
    include_str!("../../../migrations/202607190044_connector_credential_reissue_v1.down.sql");
const CONNECTOR_CREDENTIAL_REISSUE_V1_UP: &str =
    include_str!("../../../migrations/202607190044_connector_credential_reissue_v1.up.sql");
const REALTIME_SYNC_MULTIDEVICE_MAILBOX_V1_DOWN: &str =
    include_str!("../../../migrations/202607200045_realtime_sync_multidevice_mailbox_v1.down.sql");
const REALTIME_SYNC_MULTIDEVICE_MAILBOX_V1_UP: &str =
    include_str!("../../../migrations/202607200045_realtime_sync_multidevice_mailbox_v1.up.sql");
const ACCOUNT_RECOVERY_REALTIME_OUTBOX_V1_DOWN: &str =
    include_str!("../../../migrations/202607200046_account_recovery_realtime_outbox_v1.down.sql");
const ACCOUNT_RECOVERY_REALTIME_OUTBOX_V1_UP: &str =
    include_str!("../../../migrations/202607200046_account_recovery_realtime_outbox_v1.up.sql");
const REALTIME_SYNC_CONTINUITY_V2_DOWN: &str =
    include_str!("../../../migrations/202607200047_realtime_sync_continuity_v2.down.sql");
const REALTIME_SYNC_CONTINUITY_V2_UP: &str =
    include_str!("../../../migrations/202607200047_realtime_sync_continuity_v2.up.sql");
const HISTORY_RECOVERY_V1_DOWN: &str =
    include_str!("../../../migrations/202607200048_history_recovery_v1.down.sql");
const HISTORY_RECOVERY_V1_UP: &str =
    include_str!("../../../migrations/202607200048_history_recovery_v1.up.sql");
const REALTIME_SYNC_RETENTION_SAFETY_V1_DOWN: &str =
    include_str!("../../../migrations/202607200049_realtime_sync_retention_safety_v1.down.sql");
const MAILBOX_RETAINED_QUOTA_GC_V1_DOWN: &str =
    include_str!("../../../migrations/202607200050_mailbox_retained_quota_gc_v1.down.sql");
const MAILBOX_RETAINED_QUOTA_GC_V1_UP: &str =
    include_str!("../../../migrations/202607200050_mailbox_retained_quota_gc_v1.up.sql");
const FEDERATED_MLS_V5_AUTHORIZATION_V1_DOWN: &str =
    include_str!("../../../migrations/202607200051_federated_mls_v5_authorization_v1.down.sql");
const FEDERATED_MLS_V5_AUTHORIZATION_V1_UP: &str =
    include_str!("../../../migrations/202607200051_federated_mls_v5_authorization_v1.up.sql");
const RECOVERY_SCOPE_CATALOG_V1_DOWN: &str =
    include_str!("../../../migrations/202607210052_recovery_scope_catalog_v1.down.sql");
const RECOVERY_SCOPE_CATALOG_V1_UP: &str =
    include_str!("../../../migrations/202607210052_recovery_scope_catalog_v1.up.sql");
const OPAQUE_PUSH_V1_DOWN: &str =
    include_str!("../../../migrations/202607220053_opaque_push_v1.down.sql");
const OPAQUE_PUSH_V1_UP: &str =
    include_str!("../../../migrations/202607220053_opaque_push_v1.up.sql");
const CONNECTOR_BOOTSTRAP_ISSUANCE_V1_DOWN: &str =
    include_str!("../../../migrations/202607220054_connector_bootstrap_issuance_v1.down.sql");
const CONNECTOR_BOOTSTRAP_ISSUANCE_V1_UP: &str =
    include_str!("../../../migrations/202607220054_connector_bootstrap_issuance_v1.up.sql");
const AGENT_IDENTITY_READER_RLS_FIX_DOWN: &str =
    include_str!("../../../migrations/202607230055_agent_identity_reader_rls_fix.down.sql");
const AGENT_IDENTITY_READER_RLS_FIX_UP: &str =
    include_str!("../../../migrations/202607230055_agent_identity_reader_rls_fix.up.sql");
const LOCAL_RUNTIME_GRANTS: &str =
    include_str!("../../../docker/local/postgres/20-local-runtime-grants.sql");

#[tokio::test]
async fn opaque_push_v43_schema_and_least_privilege_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let contract: (bool, bool, bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT to_regclass('messaging.opaque_push_registrations') IS NOT NULL,
           to_regclass('messaging.opaque_push_idempotency_claims') IS NOT NULL,
           to_regclass('messaging.opaque_push_deliveries') IS NOT NULL,
           to_regprocedure('messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid)') IS NOT NULL,
           to_regprocedure('messaging.claim_opaque_push_deliveries(uuid,integer)') IS NOT NULL,
           NOT has_table_privilege('dtx_mailbox_runtime','messaging.opaque_push_registrations','SELECT'),
           NOT has_table_privilege('dtx_realtime_sync_runtime','messaging.opaque_push_deliveries','SELECT'),
           NOT has_table_privilege('dtx_push_broker_runtime','messaging.mailbox_envelopes','SELECT'),
           NOT has_table_privilege('dtx_push_broker_runtime','messaging.opaque_push_registrations','SELECT'),
           has_function_privilege('dtx_push_broker_runtime','messaging.claim_opaque_push_deliveries(uuid,integer)','EXECUTE')",
    ).fetch_one(harness.admin_pool()).await?;
    assert_eq!(
        contract,
        (true, true, true, true, true, true, true, true, true, true)
    );
    let broker_registration_read =
        sqlx::query("SELECT 1 FROM messaging.opaque_push_registrations LIMIT 1")
            .fetch_one(harness.push_broker_pool())
            .await
            .expect_err("broker must not read registration table");
    assert_eq!(
        sqlstate(&broker_registration_read).as_deref(),
        Some("42501")
    );
    let broker_envelope_read = sqlx::query("SELECT 1 FROM messaging.mailbox_envelopes LIMIT 1")
        .fetch_one(harness.push_broker_pool())
        .await
        .expect_err("broker must not read mailbox envelopes");
    assert_eq!(sqlstate(&broker_envelope_read).as_deref(), Some("42501"));
    assert!(OPAQUE_PUSH_V1_UP.contains("expires_at_ms=created_at_ms+60000"));
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_empty_down_up_preserves_contract() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(OPAQUE_PUSH_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('messaging.opaque_push_deliveries') IS NULL"
        )
        .fetch_one(harness.admin_pool())
        .await?
    );
    sqlx::raw_sql(OPAQUE_PUSH_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    assert!(sqlx::query_scalar::<_, bool>("SELECT to_regprocedure('messaging.claim_opaque_push_deliveries(uuid,integer)') IS NOT NULL")
        .fetch_one(harness.admin_pool()).await?);
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_down_refuses_authoritative_facts() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = PostgresHarness::start().await?;
    let migration: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public._sqlx_migrations WHERE version=$1 AND success",
    )
    .bind(OPAQUE_PUSH_V1_MIGRATION_VERSION)
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(migration, 1);
    sqlx::query("INSERT INTO messaging.opaque_push_idempotency_claims(device_id,method,path,idempotency_key,if_match_revision,request_digest,receipt_bytes,created_at_ms) VALUES('0197f2e0-0000-7000-8000-000000000001','PUT','/v43/push',decode('01','hex'),0,decode(repeat('00',32),'hex'),decode('01','hex'),0)")
        .execute(harness.admin_pool()).await?;
    let error = sqlx::raw_sql(OPAQUE_PUSH_V1_DOWN)
        .execute(harness.admin_pool())
        .await
        .expect_err("facts must block rollback");
    assert!(
        error
            .to_string()
            .contains("cannot downgrade opaque push V1")
    );
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_down_lock_fences_inflight_writer() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = PostgresHarness::start().await?;
    let mut writer = harness.admin_pool().begin().await?;
    sqlx::query("INSERT INTO messaging.opaque_push_idempotency_claims(device_id,method,path,idempotency_key,if_match_revision,request_digest,receipt_bytes,created_at_ms) VALUES('0197f2e0-0000-7000-8000-000000000001','PUT','/v43/push',decode('02','hex'),0,decode(repeat('00',32),'hex'),decode('01','hex'),0)")
        .execute(&mut *writer).await?;
    let down = sqlx::raw_sql(OPAQUE_PUSH_V1_DOWN).execute(harness.admin_pool());
    tokio::pin!(down);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut down)
            .await
            .is_err()
    );
    writer.commit().await?;
    let error = down
        .await
        .expect_err("downgrade must observe committed fact");
    assert_eq!(sqlstate(&error).as_deref(), Some("55000"));
    Ok(())
}

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
async fn agent_identity_reader_rls_fix_restores_read_only_agent_branch_and_exact_down_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(
        "DO $role$
         BEGIN
             IF to_regrole('dtx_agent_runtime') IS NULL THEN
                 CREATE ROLE dtx_agent_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS
                     NOCREATEDB NOCREATEROLE NOREPLICATION;
             END IF;
         END
         $role$;",
    )
    .execute(harness.admin_pool())
    .await?;
    // Migration 019 established these grants before this forward-only policy
    // repair.  The harness creates the production role after initial migration
    // application, so model the already-deployed role surface explicitly.
    sqlx::raw_sql(
        "GRANT USAGE ON SCHEMA identity TO dtx_agent_runtime;
         GRANT EXECUTE ON FUNCTION identity.identity_agent_reader_authorized()
             TO dtx_agent_runtime;
         GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
             TO dtx_agent_runtime;",
    )
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql(AGENT_IDENTITY_READER_RLS_FIX_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_IDENTITY_READER_RLS_FIX_UP)
        .execute(harness.admin_pool())
        .await?;
    let seeded_session = insert_group_reader_identity_fixture(
        &harness,
        "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la",
    )
    .await?;

    let privileges: (bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT has_function_privilege('dtx_agent_runtime', 'identity.identity_agent_reader_authorized()', 'EXECUTE'),
                has_table_privilege('dtx_agent_runtime', 'identity.log_heads', 'SELECT'),
                has_table_privilege('dtx_agent_runtime', 'identity.log_entries', 'SELECT'),
                has_table_privilege('dtx_agent_runtime', 'identity.device_sessions', 'SELECT'),
                NOT has_table_privilege('dtx_agent_runtime', 'identity.log_heads', 'INSERT'),
                NOT has_table_privilege('dtx_agent_runtime', 'identity.log_entries', 'UPDATE'),
                NOT has_table_privilege('dtx_agent_runtime', 'identity.device_sessions', 'DELETE')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(privileges, (true, true, true, true, true, true, true));

    let mut agent_role = harness.admin_pool().begin().await?;
    sqlx::query("SET LOCAL ROLE dtx_agent_runtime")
        .execute(&mut *agent_role)
        .await?;
    let authorized: bool = sqlx::query_scalar("SELECT identity.identity_agent_reader_authorized()")
        .fetch_one(&mut *agent_role)
        .await?;
    assert!(authorized);
    let visible_session: Option<Uuid> =
        sqlx::query_scalar("SELECT session_id FROM identity.device_sessions WHERE session_id=$1")
            .bind(seeded_session)
            .fetch_optional(&mut *agent_role)
            .await?;
    assert_eq!(visible_session, Some(seeded_session));
    let write =
        sqlx::query("UPDATE identity.device_sessions SET expires_at_ms=199 WHERE session_id=$1")
            .bind(seeded_session)
            .execute(&mut *agent_role)
            .await
            .expect_err("Agent runtime must not write identity device sessions");
    assert_eq!(sqlstate(&write).as_deref(), Some("42501"));
    agent_role.rollback().await?;

    let policy: (String, String) = sqlx::query_as(
        "SELECT qual, with_check
           FROM pg_policies
          WHERE schemaname='identity'
            AND tablename='device_sessions'
            AND policyname='identity_runtime_only'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(policy.0.contains("dtx_agent_runtime"));
    assert!(policy.0.contains("identity_agent_reader_authorized"));
    assert!(policy.0.contains("dtx_group_runtime"));
    assert!(policy.0.contains("dtx_realtime_sync_runtime"));
    assert!(!policy.1.contains("dtx_agent_runtime"));

    sqlx::raw_sql(AGENT_IDENTITY_READER_RLS_FIX_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let restored: (String, String) = sqlx::query_as(
        "SELECT qual, with_check
           FROM pg_policies
          WHERE schemaname='identity'
            AND tablename='device_sessions'
            AND policyname='identity_runtime_only'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!restored.0.contains("dtx_agent_runtime"));
    assert!(restored.0.contains("dtx_group_runtime"));
    assert!(restored.0.contains("dtx_realtime_sync_runtime"));
    assert_eq!(restored.1, policy.1);
    Ok(())
}

#[tokio::test]
async fn realtime_sync_multidevice_mailbox_empty_down_up_preserves_v14()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('messaging.mailboxes') IS NOT NULL
            AND to_regclass('realtime.journal') IS NOT NULL",
        )
        .fetch_one(harness.admin_pool())
        .await?
    );

    sqlx::raw_sql(FEDERATED_MLS_V5_AUTHORIZATION_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(HISTORY_RECOVERY_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(REALTIME_SYNC_CONTINUITY_V2_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(ACCOUNT_RECOVERY_REALTIME_OUTBOX_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(REALTIME_SYNC_MULTIDEVICE_MAILBOX_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('messaging.mailboxes') IS NOT NULL
            AND to_regclass('realtime.journal') IS NULL
            AND to_regclass('messaging.identity_delivery_journal') IS NULL",
        )
        .fetch_one(harness.admin_pool())
        .await?
    );

    sqlx::raw_sql(REALTIME_SYNC_MULTIDEVICE_MAILBOX_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(ACCOUNT_RECOVERY_REALTIME_OUTBOX_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(REALTIME_SYNC_CONTINUITY_V2_UP)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(HISTORY_RECOVERY_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(FEDERATED_MLS_V5_AUTHORIZATION_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('messaging.mailboxes') IS NOT NULL
            AND to_regclass('realtime.journal') IS NOT NULL
            AND to_regclass('messaging.device_delivery_state') IS NOT NULL",
        )
        .fetch_one(harness.admin_pool())
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn account_recovery_outbox_empty_down_up_preserves_v45()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(ACCOUNT_RECOVERY_REALTIME_OUTBOX_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('realtime.journal') IS NOT NULL
                AND to_regclass('realtime.account_read_cursor_claims') IS NULL
                AND to_regprocedure('realtime.claim_outbox(uuid,uuid,bigint,bigint,integer)') IS NULL",
        )
        .fetch_one(harness.admin_pool())
        .await?
    );
    sqlx::raw_sql(ACCOUNT_RECOVERY_REALTIME_OUTBOX_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('realtime.journal') IS NOT NULL
                AND to_regclass('realtime.account_read_cursor_claims') IS NOT NULL
                AND to_regprocedure('realtime.claim_outbox(uuid,uuid,bigint,bigint,integer)') IS NOT NULL",
        )
        .fetch_one(harness.admin_pool())
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn realtime_sync_continuity_empty_down_up_preserves_v46()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(REALTIME_SYNC_CONTINUITY_V2_DOWN)
        .execute(harness.admin_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('realtime.account_read_cursor_claims') IS NOT NULL
                AND to_regprocedure('realtime.append_identity_invalidation(text,text,bytea)') IS NULL",
        )
        .fetch_one(harness.admin_pool())
        .await?
    );
    sqlx::raw_sql(REALTIME_SYNC_CONTINUITY_V2_UP)
        .execute(harness.admin_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('realtime.account_read_cursor_claims') IS NOT NULL
                AND to_regprocedure('realtime.append_identity_invalidation(text,text,bytea)') IS NOT NULL",
        )
        .fetch_one(harness.admin_pool())
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn history_recovery_empty_down_up_preserves_v39() -> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(FEDERATED_MLS_V5_AUTHORIZATION_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(HISTORY_RECOVERY_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('messaging.history_recovery_offers') IS NULL
                AND to_regprocedure('identity.history_recovery_request_authorized(text,uuid,bytea,uuid,bigint)') IS NULL
                AND (SELECT count(*) FROM pg_policy
                      WHERE polrelid IN (
                          'identity.log_heads'::regclass,
                          'identity.log_entries'::regclass,
                          'identity.device_sessions'::regclass
                      )
                        AND polname='identity_runtime_only'
                        AND position('identity_group_reader_authorized'
                                     IN pg_get_expr(polqual,polrelid))=0)=3
                AND EXISTS(SELECT 1 FROM pg_constraint
                  WHERE conname='groups_mls_commit_intents_protocol_version_valid'
                    AND position('4' IN pg_get_constraintdef(oid))>0
                    AND position('5' IN pg_get_constraintdef(oid))=0)",
        )
        .fetch_one(harness.admin_pool())
        .await?
    );
    sqlx::raw_sql(HISTORY_RECOVERY_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(FEDERATED_MLS_V5_AUTHORIZATION_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('messaging.history_recovery_offers') IS NOT NULL
                AND to_regprocedure('identity.history_recovery_request_authorized(text,uuid,bytea,uuid,bigint)') IS NOT NULL
                AND to_regprocedure('identity.scoped_key_package_claim_authorized(text,uuid,bytea,bytea,bytea,uuid)') IS NOT NULL
                AND (SELECT count(*) FROM pg_policy
                      WHERE polrelid IN (
                          'identity.log_heads'::regclass,
                          'identity.log_entries'::regclass,
                          'identity.device_sessions'::regclass
                      )
                        AND polname='identity_runtime_only'
                        AND position('identity_group_reader_authorized'
                                     IN pg_get_expr(polqual,polrelid))>0)=3
                AND EXISTS(
                    SELECT 1 FROM pg_constraint
                     WHERE conrelid='messaging.history_recovery_offers'::regclass
                       AND contype='f' AND confdeltype='c'
                       AND pg_get_constraintdef(oid) LIKE '%mailbox_envelopes%'
                )",
        )
        .fetch_one(harness.admin_pool())
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn federated_mls_v5_projection_is_identity_runtime_only_and_reversible()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let function = "identity.mls_v5_recovery_authorization_projection(text,uuid,uuid,uuid,bytea,bytea,bytea,bytea,bigint)";
    let privileges: (bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT to_regprocedure($1) IS NOT NULL,
                has_function_privilege('dtx_identity_runtime',$1,'EXECUTE'),
                has_function_privilege('dtx_group_runtime',$1,'EXECUTE'),
                has_table_privilege('dtx_group_runtime','identity.device_enrollment_challenges','SELECT'),
                has_table_privilege('dtx_group_runtime','messaging.history_recovery_offers','SELECT')",
    )
    .bind(function)
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(privileges, (true, true, false, false, false));

    sqlx::raw_sql(FEDERATED_MLS_V5_AUTHORIZATION_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT to_regprocedure($1) IS NULL")
            .bind(function)
            .fetch_one(harness.admin_pool())
            .await?
    );
    sqlx::raw_sql(FEDERATED_MLS_V5_AUTHORIZATION_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regprocedure($1) IS NOT NULL
                AND has_function_privilege('dtx_identity_runtime',$1,'EXECUTE')
                AND NOT has_function_privilege('dtx_group_runtime',$1,'EXECUTE')",
        )
        .bind(function)
        .fetch_one(harness.admin_pool())
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn recovery_scope_catalog_acl_is_identity_runtime_only_and_reversible()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let acl: (bool, bool, bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT has_table_privilege('dtx_identity_runtime','identity.recovery_scope_catalogs','SELECT,INSERT'), has_table_privilege('dtx_identity_runtime','identity.recovery_scope_catalog_preparations','SELECT,INSERT'), NOT has_table_privilege('dtx_identity_runtime','identity.recovery_scope_catalog_preparations','UPDATE'), has_column_privilege('dtx_identity_runtime','identity.recovery_scope_catalog_preparations','provider_response_bytes','UPDATE'), has_function_privilege('dtx_identity_runtime','messaging.is_uuid_v7(uuid)','EXECUTE'), has_table_privilege('dtx_group_runtime','identity.recovery_scope_catalogs','SELECT'), has_table_privilege('dtx_mailbox_runtime','identity.recovery_scope_catalogs','SELECT'), (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='identity.recovery_scope_catalogs'::regclass), (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='identity.recovery_scope_catalog_preparations'::regclass), (SELECT count(*)=2 AND bool_and(position('identity_runtime_authorized' IN pg_get_expr(polqual,polrelid))>0) FROM pg_policy WHERE polrelid IN ('identity.recovery_scope_catalogs'::regclass,'identity.recovery_scope_catalog_preparations'::regclass))",
    ).fetch_one(harness.admin_pool()).await?;
    assert_eq!(
        acl,
        (true, true, true, true, true, false, false, true, true, true)
    );
    let trigger_rejected = sqlx::query(
        "UPDATE identity.recovery_scope_catalog_preparations SET candidate_nonce=$1 WHERE false",
    )
    .bind(vec![0_u8; 32])
    .execute(harness.identity_runtime_pool())
    .await
    .expect_err("runtime must not have update privilege on signed preparation bindings");
    assert_eq!(
        trigger_rejected
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("42501"))
    );
    sqlx::raw_sql(RECOVERY_SCOPE_CATALOG_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    assert!(sqlx::query_scalar::<_, bool>("SELECT to_regclass('identity.recovery_scope_catalogs') IS NULL AND to_regclass('identity.recovery_scope_catalog_preparations') IS NULL").fetch_one(harness.admin_pool()).await?);
    sqlx::raw_sql(RECOVERY_SCOPE_CATALOG_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_authorize_and_finish_ports_fence_claims()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    register_push(&h, &f, Uuid::now_v7(), 0, 1).await?;
    let delivery = Uuid::now_v7();
    enqueue_push(&h, &f, delivery, 0).await?;
    let claim = Uuid::now_v7();
    sqlx::query("SELECT delivery_id FROM messaging.claim_opaque_push_deliveries($1,1)")
        .bind(claim)
        .fetch_one(h.push_broker_pool())
        .await?;
    let permit: (i64, i64) = sqlx::query_as("SELECT registration_revision,expires_at_ms FROM messaging.authorize_opaque_push_send($1,$2)").bind(delivery).bind(claim).fetch_one(h.push_broker_pool()).await?;
    assert_eq!(permit.0, 1);
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT messaging.finish_opaque_push_accepted($1,$2)")
            .bind(delivery)
            .bind(claim)
            .fetch_one(h.push_broker_pool())
            .await?
    );
    let replay: Option<(i64, i64)> = sqlx::query_as("SELECT registration_revision,expires_at_ms FROM messaging.authorize_opaque_push_send($1,$2)").bind(delivery).bind(claim).fetch_optional(h.push_broker_pool()).await?;
    assert!(replay.is_none());
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_broker_functions_recheck_runtime_membership()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    sqlx::query("GRANT EXECUTE ON FUNCTION messaging.finish_opaque_push_accepted(uuid,uuid) TO dtx_realtime_sync_runtime").execute(h.admin_pool()).await?;
    let error =
        sqlx::query_scalar::<_, bool>("SELECT messaging.finish_opaque_push_accepted($1,$2)")
            .bind(Uuid::now_v7())
            .bind(Uuid::now_v7())
            .fetch_one(h.realtime_sync_runtime_pool())
            .await
            .expect_err("non-broker call must be denied");
    assert_eq!(sqlstate(&error).as_deref(), Some("42501"));
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_invalid_token_requires_live_exact_claim_and_reserved_class()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let reg = Uuid::now_v7();
    register_push(&h, &f, reg, 0, 2).await?;
    let delivery = Uuid::now_v7();
    enqueue_push(&h, &f, delivery, 0).await?;
    let claim = Uuid::now_v7();
    sqlx::query("UPDATE messaging.opaque_push_deliveries SET state='claimed',claim_token=$2,claim_expires_at_ms=0 WHERE delivery_id=$1").bind(delivery).bind(claim).execute(h.admin_pool()).await?;
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT messaging.finish_opaque_push_invalid_token($1,$2,1)"
        )
        .bind(delivery)
        .bind(claim)
        .fetch_one(h.push_broker_pool())
        .await?
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT state FROM messaging.opaque_push_registrations WHERE registration_id=$1"
        )
        .bind(reg)
        .fetch_one(h.admin_pool())
        .await?,
        "active"
    );
    let error = sqlx::query_scalar::<_, bool>(
        "SELECT messaging.finish_opaque_push_permanent_failure($1,$2,'invalid_token')",
    )
    .bind(delivery)
    .bind(claim)
    .fetch_one(h.push_broker_pool())
    .await
    .expect_err("invalid_token is reserved");
    assert!(matches!(
        sqlstate(&error).as_deref(),
        Some("42501") | Some("22023")
    ));
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_authorize_post_lock_clock_rejects_expired_claims()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let reg = Uuid::now_v7();
    register_push(&h, &f, reg, 0, 3).await?;
    let delivery = Uuid::now_v7();
    enqueue_push(&h, &f, delivery, 0).await?;
    let claim = Uuid::now_v7();
    sqlx::query("SELECT delivery_id FROM messaging.claim_opaque_push_deliveries($1,1)")
        .bind(claim)
        .fetch_one(h.push_broker_pool())
        .await?;
    sqlx::query("UPDATE messaging.opaque_push_deliveries SET created_at_ms=-60000,expires_at_ms=0 WHERE delivery_id=$1")
        .bind(delivery)
        .execute(h.admin_pool())
        .await?;
    let permit: Option<(i64,i64)> = sqlx::query_as("SELECT registration_revision,expires_at_ms FROM messaging.authorize_opaque_push_send($1,$2)").bind(delivery).bind(claim).fetch_optional(h.push_broker_pool()).await?;
    assert!(permit.is_none());
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT state FROM messaging.opaque_push_deliveries WHERE delivery_id=$1"
        )
        .bind(delivery)
        .fetch_one(h.admin_pool())
        .await?,
        "expired"
    );
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_authorize_vs_revoke_completes_without_deadlock()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    register_push(&h, &f, Uuid::now_v7(), 0, 4).await?;
    let delivery = Uuid::now_v7();
    enqueue_push(&h, &f, delivery, 0).await?;
    let claim = Uuid::now_v7();
    sqlx::query("SELECT delivery_id FROM messaging.claim_opaque_push_deliveries($1,1)")
        .bind(claim)
        .fetch_one(h.push_broker_pool())
        .await?;
    let revoke_pool = h.push_registration_pool().clone();
    let revoke_session = f.session_id;
    let revoke = tokio::spawn(async move {
        sqlx::query_scalar::<_, Vec<u8>>("SELECT messaging.opaque_push_commit_delete($1,$2,'DELETE','/v43/push',$3,1::bigint,$4,1::smallint,1::smallint,1::smallint,1::smallint,'active',1::bigint,$5)").bind(revoke_session).bind(vec![3_u8;32]).bind(vec![5_u8]).bind(vec![5_u8;32]).bind(vec![1_u8;32]).fetch_one(&revoke_pool).await
    });
    let auth_pool = h.push_broker_pool().clone();
    let authorize = tokio::spawn(async move {
        sqlx::query_as::<_,(i64,i64)>("SELECT registration_revision,expires_at_ms FROM messaging.authorize_opaque_push_send($1,$2)").bind(delivery).bind(claim).fetch_optional(&auth_pool).await
    });
    let joined = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        (revoke.await, authorize.await)
    })
    .await?;
    let _ = joined.0?;
    let _ = joined.1??;
    let state:(String,String)=sqlx::query_as("SELECT d.state,r.state FROM messaging.opaque_push_deliveries d JOIN messaging.opaque_push_registrations r ON r.registration_id=d.registration_id WHERE d.delivery_id=$1").bind(delivery).fetch_one(h.admin_pool()).await?;
    assert_eq!(state.1, "revoked");
    assert_ne!(state.0, "delivered");
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_enqueue_vs_invalid_token_is_provider_fenced()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let reg = Uuid::now_v7();
    register_push(&h, &f, reg, 0, 6).await?;
    let first = Uuid::now_v7();
    enqueue_push(&h, &f, first, 0).await?;
    let claim = Uuid::now_v7();
    sqlx::query("SELECT delivery_id FROM messaging.claim_opaque_push_deliveries($1,1)")
        .bind(claim)
        .fetch_one(h.push_broker_pool())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT messaging.finish_opaque_push_invalid_token($1,$2,1)")
            .bind(first)
            .bind(claim)
            .fetch_one(h.push_broker_pool())
            .await?
    );
    let second = Uuid::now_v7();
    assert_eq!(enqueue_push(&h, &f, second, 0).await?, 0);
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_invalid_token_terminalizes_all_pinned_rows_only()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let reg = Uuid::now_v7();
    register_push(&h, &f, reg, 0, 7).await?;
    let second_env = Uuid::now_v7();
    sqlx::query("INSERT INTO messaging.mailbox_envelopes(mailbox_id,envelope_id,delivery_sequence,opaque_ciphertext,request_digest,receipt_bytes,receipt_hash,expires_at_ms,created_at_ms) VALUES($1,$2,2,decode('09','hex'),decode(repeat('09',32),'hex'),decode('09','hex'),decode(repeat('09',32),'hex'),253402300799999,0)").bind(f.mailbox_id).bind(second_env).execute(h.admin_pool()).await?;
    let first = Uuid::now_v7();
    enqueue_push(&h, &f, first, 0).await?;
    let second = Uuid::now_v7();
    sqlx::query_scalar::<_, i64>("SELECT messaging.enqueue_opaque_push_intent($1,$2,$3)")
        .bind(second)
        .bind(f.mailbox_id)
        .bind(second_env)
        .fetch_one(h.mailbox_runtime_pool())
        .await?;
    let claim = Uuid::now_v7();
    let claimed: Vec<(Uuid,)> =
        sqlx::query_as("SELECT delivery_id FROM messaging.claim_opaque_push_deliveries($1,2)")
            .bind(claim)
            .fetch_all(h.push_broker_pool())
            .await?;
    assert_eq!(claimed.len(), 2);
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT messaging.finish_opaque_push_invalid_token($1,$2,1)")
            .bind(claimed[0].0)
            .bind(claim)
            .fetch_one(h.push_broker_pool())
            .await?
    );
    let states:Vec<String>=sqlx::query_scalar("SELECT state FROM messaging.opaque_push_deliveries WHERE registration_id=$1 ORDER BY delivery_id").bind(reg).fetch_all(h.admin_pool()).await?;
    assert_eq!(states, vec!["permanent_failure", "permanent_failure"]);
    register_push(&h, &f, reg, 1, 8).await?;
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_finish_transient_bounds_and_near_expiry_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let registration = Uuid::now_v7();
    register_push(&h, &f, registration, 0, 0x26).await?;
    let delivery = Uuid::now_v7();
    enqueue_push(&h, &f, delivery, 0).await?;
    let claim = Uuid::now_v7();
    sqlx::query("SELECT delivery_id FROM messaging.claim_opaque_push_deliveries($1,1)")
        .bind(claim)
        .fetch_one(h.push_broker_pool())
        .await?;
    for retry in [0, 61] {
        let error = sqlx::query_scalar::<_, bool>(
            "SELECT messaging.finish_opaque_push_transient($1,$2,$3,'transient')",
        )
        .bind(delivery)
        .bind(claim)
        .bind(retry)
        .fetch_one(h.push_broker_pool())
        .await
        .expect_err("retry bound must reject");
        assert_eq!(sqlstate(&error).as_deref(), Some("22023"));
    }
    let transient: (String, i64, Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT * FROM messaging.finish_opaque_push_transient($1,$2,1,'transient')")
            .bind(delivery)
            .bind(claim)
            .fetch_one(h.push_broker_pool())
            .await?;
    assert_eq!(transient.0, "scheduled");
    let retry_at: (i64, i64) = sqlx::query_as("SELECT retry_at_ms,expires_at_ms FROM messaging.opaque_push_deliveries WHERE delivery_id=$1").bind(delivery).fetch_one(h.admin_pool()).await?;
    assert!(retry_at.0 > 0 && retry_at.0 < retry_at.1);
    sqlx::query("UPDATE messaging.opaque_push_deliveries SET retry_at_ms=0 WHERE delivery_id=$1")
        .bind(delivery)
        .execute(h.admin_pool())
        .await?;
    let claim2 = Uuid::now_v7();
    sqlx::query("SELECT delivery_id FROM messaging.claim_opaque_push_deliveries($1,1)")
        .bind(claim2)
        .fetch_one(h.push_broker_pool())
        .await?;
    let transient_again: (String, i64, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT * FROM messaging.finish_opaque_push_transient($1,$2,60,'transient')",
    )
    .bind(delivery)
    .bind(claim2)
    .fetch_one(h.push_broker_pool())
    .await?;
    assert_eq!(transient_again.0, "scheduled");
    let near_claim = Uuid::now_v7();
    sqlx::query("UPDATE messaging.opaque_push_deliveries SET created_at_ms=(floor(extract(epoch FROM clock_timestamp())*1000)::bigint)-100,expires_at_ms=(floor(extract(epoch FROM clock_timestamp())*1000)::bigint)+59900,retry_at_ms=0 WHERE delivery_id=$1").bind(delivery).execute(h.admin_pool()).await?;
    sqlx::query("UPDATE messaging.opaque_push_deliveries SET state='claimed',claim_token=$2,claim_expires_at_ms=(floor(extract(epoch FROM clock_timestamp())*1000)::bigint)+30000 WHERE delivery_id=$1").bind(delivery).bind(near_claim).execute(h.admin_pool()).await?;
    sqlx::query("UPDATE messaging.opaque_push_deliveries SET created_at_ms=(floor(extract(epoch FROM clock_timestamp())*1000)::bigint)-60000,expires_at_ms=(floor(extract(epoch FROM clock_timestamp())*1000)::bigint) WHERE delivery_id=$1").bind(delivery).execute(h.admin_pool()).await?;
    let expired: (String, i64, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT * FROM messaging.finish_opaque_push_transient($1,$2,60,'transient')",
    )
    .bind(delivery)
    .bind(near_claim)
    .fetch_one(h.push_broker_pool())
    .await?;
    assert_eq!(expired.0, "fence_lost");
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT state FROM messaging.opaque_push_deliveries WHERE delivery_id=$1"
        )
        .bind(delivery)
        .fetch_one(h.admin_pool())
        .await?,
        "expired"
    );
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_role_topology_acl_is_exact_and_restored()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(LOCAL_RUNTIME_GRANTS.contains(
        "GRANT EXECUTE ON FUNCTION messaging.enqueue_opaque_push_intent(uuid, uuid, uuid)\n    TO dtx_mailbox_runtime;"
    ));
    let h = PostgresHarness::start().await?;
    let acl: (bool,bool,bool,bool,bool,bool,bool,bool,bool,bool,bool,bool) = sqlx::query_as("SELECT has_function_privilege('dtx_push_registration_runtime','messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid)','EXECUTE'),has_function_privilege('dtx_push_registration_runtime','messaging.opaque_push_commit_put(uuid,bytea,uuid,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea,bytea,bytea,bytea,text,bytea)','EXECUTE'),has_function_privilege('dtx_push_registration_runtime','messaging.opaque_push_commit_delete(uuid,bytea,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea)','EXECUTE'),NOT has_function_privilege('dtx_mailbox_runtime','messaging.opaque_push_commit_put(uuid,bytea,uuid,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea,bytea,bytea,bytea,text,bytea)','EXECUTE'),has_function_privilege('dtx_mailbox_runtime','messaging.enqueue_opaque_push_intent(uuid,uuid,uuid)','EXECUTE'),has_function_privilege('dtx_push_broker_runtime','messaging.claim_opaque_push_deliveries(uuid,integer)','EXECUTE'),has_function_privilege('dtx_push_broker_runtime','messaging.authorize_opaque_push_send(uuid,uuid)','EXECUTE'),has_function_privilege('dtx_push_broker_runtime','messaging.finish_opaque_push_accepted(uuid,uuid)','EXECUTE'),has_function_privilege('dtx_push_broker_runtime','messaging.finish_opaque_push_permanent_failure(uuid,uuid,text)','EXECUTE'),has_function_privilege('dtx_push_broker_runtime','messaging.finish_opaque_push_transient(uuid,uuid,integer,text)','EXECUTE'),has_function_privilege('dtx_push_broker_runtime','messaging.finish_opaque_push_invalid_token(uuid,uuid,bigint)','EXECUTE'),NOT has_table_privilege('dtx_push_broker_runtime','messaging.opaque_push_registrations','SELECT')").fetch_one(h.admin_pool()).await?;
    assert_eq!(
        acl,
        (
            true, true, true, true, true, true, true, true, true, true, true, true
        )
    );
    sqlx::raw_sql(OPAQUE_PUSH_V1_DOWN)
        .execute(h.admin_pool())
        .await?;
    sqlx::raw_sql(OPAQUE_PUSH_V1_UP)
        .execute(h.admin_pool())
        .await?;
    let restored: (bool,bool,bool,bool) = sqlx::query_as("SELECT has_function_privilege('dtx_push_registration_runtime','messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid)','EXECUTE'),has_function_privilege('dtx_mailbox_runtime','messaging.enqueue_opaque_push_intent(uuid,uuid,uuid)','EXECUTE'),has_function_privilege('dtx_push_broker_runtime','messaging.claim_opaque_push_deliveries(uuid,integer)','EXECUTE'),NOT has_table_privilege('dtx_push_broker_runtime','messaging.opaque_push_registrations','SELECT')").fetch_one(h.admin_pool()).await?;
    assert_eq!(restored, (true, true, true, true));
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_prune_waits_for_commit_session_fence()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let registration = Uuid::now_v7();
    let mut age = h.admin_pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *age)
        .await?;
    let expiry: i64 = sqlx::query_scalar(
        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 100",
    )
    .fetch_one(&mut *age)
    .await?;
    sqlx::query("UPDATE identity.device_sessions SET expires_at_ms=$2 WHERE session_id=$1")
        .bind(f.session_id)
        .bind(expiry)
        .execute(&mut *age)
        .await?;
    age.commit().await?;
    let mut head_lock = h.admin_pool().begin().await?;
    sqlx::query("SELECT 1 FROM identity.log_heads WHERE identity_id=$1 FOR UPDATE")
        .bind(&f.identity_id)
        .execute(&mut *head_lock)
        .await?;
    let mut conn = h.push_registration_pool().acquire().await?;
    let commit_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *conn)
        .await?;
    let session = f.session_id;
    let commit = tokio::spawn(async move {
        sqlx::query_scalar::<_, Vec<u8>>("SELECT messaging.opaque_push_commit_put($1,$2,$3,'PUT','/v43/push',$4,0::bigint,$5,1::smallint,1::smallint,1::smallint,1::smallint,'active',1::bigint,$6,decode(repeat('aa',17),'hex'),decode(repeat('01',24),'hex'),decode('bb','hex'),'kms-v1',decode('cc','hex'))").bind(session).bind(vec![3_u8;32]).bind(registration).bind(vec![0x61_u8]).bind(vec![0x61_u8;32]).bind(vec![1_u8;32]).fetch_one(&mut *conn).await
    });
    let mut waiting = false;
    for _ in 0..100 {
        let pids: Vec<i32> = sqlx::query_scalar("SELECT pg_blocking_pids($1)")
            .bind(commit_pid)
            .fetch_one(h.admin_pool())
            .await?;
        if pids.iter().any(|pid| *pid != 0) {
            waiting = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(waiting);
    let mut prune_conn = h.identity_runtime_pool().acquire().await?;
    let prune_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *prune_conn)
        .await?;
    let prune = tokio::spawn(async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT identity.prune_expired_device_sessions(253402300799999,100)",
        )
        .fetch_one(&mut *prune_conn)
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    let prune_blockers: Vec<i32> = sqlx::query_scalar("SELECT pg_blocking_pids($1)")
        .bind(prune_pid)
        .fetch_one(h.admin_pool())
        .await?;
    let prune_finished = prune.is_finished();
    let session_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM identity.device_sessions WHERE session_id=$1)",
    )
    .bind(f.session_id)
    .fetch_one(h.admin_pool())
    .await?;
    assert!(prune_blockers.is_empty());
    assert!(prune_finished && session_exists);
    head_lock.commit().await?;
    let _ = commit.await?;
    let _ = prune.await??;
    let removed: i64 =
        sqlx::query_scalar("SELECT identity.prune_expired_device_sessions(253402300799999,100)")
            .fetch_one(h.identity_runtime_pool())
            .await?;
    assert!(removed >= 1);
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM identity.device_sessions WHERE session_id=$1)"
        )
        .bind(f.session_id)
        .fetch_one(h.admin_pool())
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn connector_bootstrap_issuance_v1_is_reversible_when_empty()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(CONNECTOR_BOOTSTRAP_ISSUANCE_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let removed: (bool, bool) = sqlx::query_as(
        "SELECT to_regclass('agent.connector_bootstrap_issuances') IS NULL,
                to_regprocedure('agent.enforce_connector_bootstrap_issuance_fence()') IS NULL",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(removed, (true, true));
    sqlx::raw_sql(CONNECTOR_BOOTSTRAP_ISSUANCE_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    let restored: (bool, bool) = sqlx::query_as(
        "SELECT to_regclass('agent.connector_bootstrap_issuances') IS NOT NULL,
                to_regprocedure('agent.enforce_connector_bootstrap_issuance_fence()') IS NOT NULL",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(restored, (true, true));
    Ok(())
}

#[tokio::test]
async fn connector_bootstrap_issuance_down_refuses_populated_state_before_ddl()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let mut connection = harness.admin_pool().acquire().await?;
    sqlx::raw_sql(
        "SET session_replication_role=replica;
         INSERT INTO agent.connector_bootstrap_issuances (
             tenant_id, operation_id, connector_id, host_id,
             enrollment_request_id, enrollment_intent_id,
             connector_generation, spec_revision, request_digest, plan_digest,
             handoff_digest, enrollment_token_digest, mcp_bearer_digest,
             handoff_path, plan_path, request_json, plan_json, state,
             expires_at_ms, created_at_ms
         ) VALUES (
             '0197f1f0-0000-7000-8000-000000000001',
             '0197f1f0-0000-7000-8000-000000000005',
             '0197f1f0-0000-7000-8000-000000000003',
             '0197f1f0-0000-7000-8000-000000000002',
             '0197f1f0-0000-7000-8000-000000000006',
             '0197f1f0-0000-7000-8000-000000000007',
             1, 1,
             decode(repeat('11',32),'hex'), decode(repeat('22',32),'hex'),
             decode(repeat('33',32),'hex'), decode(repeat('44',32),'hex'),
             decode(repeat('55',32),'hex'),
             '/root/bootstrap/issuance.handoff.json',
             '/root/bootstrap/issuance.plan.json',
             '{}'::jsonb, '{}'::jsonb, 'ready', 4000000000, 3999400000
         );
         SET session_replication_role=origin;",
    )
    .execute(&mut *connection)
    .await?;

    let error = sqlx::raw_sql(CONNECTOR_BOOTSTRAP_ISSUANCE_V1_DOWN)
        .execute(&mut *connection)
        .await
        .expect_err("populated immutable issuance table must refuse downgrade");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database| database.code())
            .as_deref(),
        Some("55000")
    );
    let preserved: (bool, bool, i64) = sqlx::query_as(
        "SELECT to_regclass('agent.connector_bootstrap_issuances') IS NOT NULL,
                to_regprocedure('agent.enforce_connector_bootstrap_issuance_fence()') IS NOT NULL,
                count(*) FROM agent.connector_bootstrap_issuances",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(preserved, (true, true, 1));
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the retention regression needs linked Catalog and unlinked enrollment fixtures"
)]
async fn recovery_scope_catalog_retains_linked_enrollment_challenges_without_blocking_prune()
-> Result<(), Box<dyn std::error::Error>> {
    const IDENTITY_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";
    let harness = PostgresHarness::start().await?;
    let authority_device_id = Uuid::now_v7();
    let linked_challenge_id = Uuid::now_v7();
    let unrelated_challenge_id = Uuid::now_v7();
    let candidate_device_id = Uuid::now_v7();

    let mut identity_transaction = harness.admin_pool().begin().await?;
    sqlx::query(
        "INSERT INTO identity.log_heads(
             identity_id,protocol_major,protocol_minor,minimum_reader_major,
             minimum_reader_minor,head_sequence,head_hash,state,created_at_ms,updated_at_ms
         ) VALUES($1,1,1,1,1,1,$2,'active',0,0)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![1_u8; 32])
    .execute(&mut *identity_transaction)
    .await?;
    sqlx::query(
        "INSERT INTO identity.log_entries(
             identity_id,sequence,entry_hash,previous_hash,protocol_major,
             protocol_minor,minimum_reader_major,minimum_reader_minor,event_bytes,recorded_at_ms
         ) VALUES($1,1,$2,NULL,1,1,1,1,$3,0)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![1_u8; 32])
    .bind(vec![1_u8])
    .execute(&mut *identity_transaction)
    .await?;
    identity_transaction.commit().await?;
    sqlx::query(
        "INSERT INTO identity.recovery_scope_catalogs(
             identity_id,generation,previous_head_digest,leaf_count,merkle_root,
             ciphertext_digest,observed_head_sequence,observed_head_hash,
             authority_device_id,authority_signing_key,issued_at_ms,expires_at_ms,
             signature,head_bytes,head_digest,encrypted_catalog,upload_digest,
             idempotency_key_hash,created_at_ms
         ) VALUES($1,1,NULL,1,$2,$3,1,$4,$5,$6,10,20,$7,$8,$9,$10,$11,$12,10)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![2_u8; 32])
    .bind(vec![3_u8; 32])
    .bind(vec![1_u8; 32])
    .bind(authority_device_id)
    .bind(vec![4_u8; 32])
    .bind(vec![5_u8; 64])
    .bind(vec![6_u8])
    .bind(vec![7_u8; 32])
    .bind(vec![8_u8])
    .bind(vec![9_u8; 32])
    .bind(vec![10_u8; 32])
    .execute(harness.admin_pool())
    .await?;
    for (challenge_id, retention_until_ms, idempotency_byte) in [
        (linked_challenge_id, 10_i64, 11_u8),
        (unrelated_challenge_id, 20_i64, 12_u8),
    ] {
        sqlx::query(
            "INSERT INTO identity.device_enrollment_challenges(
                 challenge_id,creation_idempotency_key_hash,identity_id,target_device_id,
                 target_device_signing_key,target_device_encryption_key,capability_hash,
                 request_digest,state,created_at_ms,expires_at_ms,retention_until_ms
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'open',0,$9,$9)",
        )
        .bind(challenge_id)
        .bind(vec![idempotency_byte; 32])
        .bind(IDENTITY_ID)
        .bind(candidate_device_id)
        .bind(vec![13_u8; 32])
        .bind(vec![14_u8; 32])
        .bind(vec![15_u8; 32])
        .bind(vec![16_u8; 32])
        .bind(retention_until_ms)
        .execute(harness.admin_pool())
        .await?;
    }
    sqlx::query(
        "INSERT INTO identity.recovery_scope_catalog_preparations(
             request_id,identity_id,candidate_device_id,candidate_signing_key,
             candidate_recipient_key,observed_head_sequence,observed_head_hash,
             candidate_nonce,issued_at_ms,expires_at_ms,response_capability_hash,
             enrollment_capability_hash,candidate_signature,preparation_bytes,
             preparation_digest,catalog_generation,catalog_head_digest,
             authority_device_id,authority_signing_key,idempotency_key_hash,created_at_ms
         ) VALUES($1,$2,$3,$4,$5,1,$6,$7,10,20,$8,$9,$10,$11,$12,1,$13,$14,$15,$16,10)",
    )
    .bind(linked_challenge_id)
    .bind(IDENTITY_ID)
    .bind(candidate_device_id)
    .bind(vec![13_u8; 32])
    .bind(vec![14_u8; 32])
    .bind(vec![1_u8; 32])
    .bind(vec![17_u8; 32])
    .bind(vec![18_u8; 32])
    .bind(vec![15_u8; 32])
    .bind(vec![19_u8; 64])
    .bind(vec![20_u8])
    .bind(vec![21_u8; 32])
    .bind(vec![7_u8; 32])
    .bind(authority_device_id)
    .bind(vec![4_u8; 32])
    .bind(vec![22_u8; 32])
    .execute(harness.admin_pool())
    .await?;

    let removed: i64 =
        sqlx::query_scalar("SELECT identity.prune_expired_device_enrollment_challenges($1, $2)")
            .bind(100_i64)
            .bind(1_i32)
            .fetch_one(harness.identity_runtime_pool())
            .await?;
    assert_eq!(removed, 1);
    let remaining: (bool, bool) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM identity.device_enrollment_challenges WHERE challenge_id=$1),
                EXISTS(SELECT 1 FROM identity.device_enrollment_challenges WHERE challenge_id=$2)",
    )
    .bind(linked_challenge_id)
    .bind(unrelated_challenge_id)
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(remaining, (true, false));

    sqlx::query("DELETE FROM identity.recovery_scope_catalog_preparations")
        .execute(harness.admin_pool())
        .await?;
    sqlx::query("DELETE FROM identity.recovery_scope_catalogs")
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(RECOVERY_SCOPE_CATALOG_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let restored_definition: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef(
             'identity.prune_expired_device_enrollment_challenges(bigint,integer)'::regprocedure
         )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!restored_definition.contains("recovery_scope_catalog_preparations"));
    let removed_after_down: i64 =
        sqlx::query_scalar("SELECT identity.prune_expired_device_enrollment_challenges($1, $2)")
            .bind(100_i64)
            .bind(1_i32)
            .fetch_one(harness.identity_runtime_pool())
            .await?;
    assert_eq!(removed_after_down, 1);
    sqlx::raw_sql(RECOVERY_SCOPE_CATALOG_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT to_regclass('identity.recovery_scope_catalog_preparations') IS NOT NULL
            AND position(
                'recovery_scope_catalog_preparations' IN pg_get_functiondef(
                    'identity.prune_expired_device_enrollment_challenges(bigint,integer)'::regprocedure
                )
            ) > 0",
    )
    .fetch_one(harness.admin_pool())
    .await?);
    Ok(())
}

#[tokio::test]
async fn recovery_scope_catalog_down_waits_for_concurrent_insert_and_preserves_the_fact()
-> Result<(), Box<dyn std::error::Error>> {
    const IDENTITY_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";
    let harness = PostgresHarness::start().await?;
    let mut identity_transaction = harness.admin_pool().begin().await?;
    sqlx::query(
        "INSERT INTO identity.log_heads(
             identity_id,protocol_major,protocol_minor,minimum_reader_major,
             minimum_reader_minor,head_sequence,head_hash,state,created_at_ms,updated_at_ms
         ) VALUES($1,1,1,1,1,1,$2,'active',0,0)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![1_u8; 32])
    .execute(&mut *identity_transaction)
    .await?;
    sqlx::query(
        "INSERT INTO identity.log_entries(
             identity_id,sequence,entry_hash,previous_hash,protocol_major,
             protocol_minor,minimum_reader_major,minimum_reader_minor,event_bytes,recorded_at_ms
         ) VALUES($1,1,$2,NULL,1,1,1,1,$3,0)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![1_u8; 32])
    .bind(vec![1_u8])
    .execute(&mut *identity_transaction)
    .await?;
    identity_transaction.commit().await?;

    let mut writer = harness.admin_pool().begin().await?;
    sqlx::query(
        "INSERT INTO identity.recovery_scope_catalogs(
             identity_id,generation,previous_head_digest,leaf_count,merkle_root,
             ciphertext_digest,observed_head_sequence,observed_head_hash,
             authority_device_id,authority_signing_key,issued_at_ms,expires_at_ms,
             signature,head_bytes,head_digest,encrypted_catalog,upload_digest,
             idempotency_key_hash,created_at_ms
         ) VALUES($1,1,NULL,1,$2,$3,1,$4,$5,$6,10,20,$7,$8,$9,$10,$11,$12,10)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![2_u8; 32])
    .bind(vec![3_u8; 32])
    .bind(vec![1_u8; 32])
    .bind(Uuid::now_v7())
    .bind(vec![4_u8; 32])
    .bind(vec![5_u8; 64])
    .bind(vec![6_u8])
    .bind(vec![7_u8; 32])
    .bind(vec![8_u8])
    .bind(vec![9_u8; 32])
    .bind(vec![10_u8; 32])
    .execute(&mut *writer)
    .await?;

    let mut downgrade_connection = harness.admin_pool().acquire().await?;
    let downgrade_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *downgrade_connection)
        .await?;
    let downgrade = tokio::spawn(async move {
        sqlx::raw_sql(RECOVERY_SCOPE_CATALOG_V1_DOWN)
            .execute(&mut *downgrade_connection)
            .await
    });
    let blocked_mode = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let requested_mode: Option<String> = sqlx::query_scalar(
                "SELECT mode
                   FROM pg_locks
                  WHERE pid=$1
                    AND locktype='relation'
                    AND relation='identity.recovery_scope_catalogs'::regclass
                    AND NOT granted
                  ORDER BY mode
                  LIMIT 1",
            )
            .bind(downgrade_pid)
            .fetch_optional(harness.admin_pool())
            .await?;
            if let Some(mode) = requested_mode {
                break Ok::<String, sqlx::Error>(mode);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;

    writer.commit().await?;
    let downgrade_error = downgrade
        .await?
        .expect_err("a concurrently committed catalog fact must refuse the downgrade");
    assert_eq!(blocked_mode, "ShareRowExclusiveLock");
    assert_eq!(
        downgrade_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("55000")),
    );
    let unchanged: (bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT to_regclass('identity.recovery_scope_catalogs') IS NOT NULL,
                to_regclass('identity.recovery_scope_catalog_preparations') IS NOT NULL,
                to_regprocedure('identity.enforce_recovery_scope_catalog_preparation_transition()') IS NOT NULL,
                EXISTS(SELECT 1 FROM pg_trigger
                        WHERE tgname='identity_recovery_scope_catalog_preparation_transition'
                          AND NOT tgisinternal),
                has_table_privilege(
                    'dtx_identity_runtime','identity.recovery_scope_catalogs','SELECT,INSERT')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(unchanged, (true, true, true, true, true));
    let preserved_facts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.recovery_scope_catalogs")
            .fetch_one(harness.admin_pool())
            .await?;
    assert_eq!(preserved_facts, 1);
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one migration test proves populated-down refusal and both immutable transitions"
)]
async fn recovery_scope_catalog_down_refuses_populated_state_before_ddl()
-> Result<(), Box<dyn std::error::Error>> {
    const IDENTITY_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";
    let harness = PostgresHarness::start().await?;
    let authority_device_id = Uuid::now_v7();
    let challenge_id = Uuid::now_v7();
    let candidate_device_id = Uuid::now_v7();
    let mut identity_transaction = harness.admin_pool().begin().await?;
    sqlx::query(
        "INSERT INTO identity.log_heads(
             identity_id,protocol_major,protocol_minor,minimum_reader_major,
             minimum_reader_minor,head_sequence,head_hash,state,created_at_ms,updated_at_ms
         ) VALUES($1,1,1,1,1,1,$2,'active',0,0)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![1_u8; 32])
    .execute(&mut *identity_transaction)
    .await?;
    sqlx::query(
        "INSERT INTO identity.log_entries(
             identity_id,sequence,entry_hash,previous_hash,protocol_major,
             protocol_minor,minimum_reader_major,minimum_reader_minor,event_bytes,recorded_at_ms
         ) VALUES($1,1,$2,NULL,1,1,1,1,$3,0)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![1_u8; 32])
    .bind(vec![1_u8])
    .execute(&mut *identity_transaction)
    .await?;
    identity_transaction.commit().await?;
    sqlx::query(
        "INSERT INTO identity.recovery_scope_catalogs(
             identity_id,generation,previous_head_digest,leaf_count,merkle_root,
             ciphertext_digest,observed_head_sequence,observed_head_hash,
             authority_device_id,authority_signing_key,issued_at_ms,expires_at_ms,
             signature,head_bytes,head_digest,encrypted_catalog,upload_digest,
             idempotency_key_hash,created_at_ms
         ) VALUES($1,1,NULL,1,$2,$3,1,$4,$5,$6,10,20,$7,$8,$9,$10,$11,$12,10)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![2_u8; 32])
    .bind(vec![3_u8; 32])
    .bind(vec![1_u8; 32])
    .bind(authority_device_id)
    .bind(vec![4_u8; 32])
    .bind(vec![5_u8; 64])
    .bind(vec![6_u8])
    .bind(vec![7_u8; 32])
    .bind(vec![8_u8])
    .bind(vec![9_u8; 32])
    .bind(vec![10_u8; 32])
    .execute(harness.admin_pool())
    .await?;
    sqlx::query(
        "INSERT INTO identity.device_enrollment_challenges(
             challenge_id,creation_idempotency_key_hash,identity_id,target_device_id,
             target_device_signing_key,target_device_encryption_key,capability_hash,
             request_digest,state,created_at_ms,expires_at_ms,retention_until_ms
         ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'open',10,20,20)",
    )
    .bind(challenge_id)
    .bind(vec![11_u8; 32])
    .bind(IDENTITY_ID)
    .bind(candidate_device_id)
    .bind(vec![12_u8; 32])
    .bind(vec![13_u8; 32])
    .bind(vec![14_u8; 32])
    .bind(vec![15_u8; 32])
    .execute(harness.admin_pool())
    .await?;
    sqlx::query(
        "INSERT INTO identity.recovery_scope_catalog_preparations(
             request_id,identity_id,candidate_device_id,candidate_signing_key,
             candidate_recipient_key,observed_head_sequence,observed_head_hash,
             candidate_nonce,issued_at_ms,expires_at_ms,response_capability_hash,
             enrollment_capability_hash,candidate_signature,preparation_bytes,
             preparation_digest,catalog_generation,catalog_head_digest,
             authority_device_id,authority_signing_key,idempotency_key_hash,created_at_ms
         ) VALUES($1,$2,$3,$4,$5,1,$6,$7,10,20,$8,$9,$10,$11,$12,1,$13,$14,$15,$16,10)",
    )
    .bind(challenge_id)
    .bind(IDENTITY_ID)
    .bind(candidate_device_id)
    .bind(vec![12_u8; 32])
    .bind(vec![13_u8; 32])
    .bind(vec![1_u8; 32])
    .bind(vec![16_u8; 32])
    .bind(vec![17_u8; 32])
    .bind(vec![14_u8; 32])
    .bind(vec![18_u8; 64])
    .bind(vec![19_u8])
    .bind(vec![20_u8; 32])
    .bind(vec![7_u8; 32])
    .bind(authority_device_id)
    .bind(vec![4_u8; 32])
    .bind(vec![21_u8; 32])
    .execute(harness.admin_pool())
    .await?;

    let immutable_error = sqlx::query(
        "UPDATE identity.recovery_scope_catalog_preparations
            SET candidate_nonce=$2 WHERE request_id=$1",
    )
    .bind(challenge_id)
    .bind(vec![22_u8; 32])
    .execute(harness.admin_pool())
    .await
    .expect_err("signed preparation binding must be immutable even to the owner");
    assert_eq!(
        immutable_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("23514")),
    );

    sqlx::query(
        "UPDATE identity.recovery_scope_catalog_preparations SET
             provider_response_bytes=$2,provider_response_digest=$3,
             provider_device_id=$4,provider_signing_key=$5,
             provider_ciphertext_digest=$6,provider_expires_at_ms=19,
             provider_idempotency_key_hash=$7,provider_recorded_at_ms=11
         WHERE request_id=$1",
    )
    .bind(challenge_id)
    .bind(vec![23_u8])
    .bind(vec![24_u8; 32])
    .bind(Uuid::now_v7())
    .bind(vec![25_u8; 32])
    .bind(vec![26_u8; 32])
    .bind(vec![27_u8; 32])
    .execute(harness.admin_pool())
    .await?;
    let response_mutation_error = sqlx::query(
        "UPDATE identity.recovery_scope_catalog_preparations
            SET provider_response_bytes=$2 WHERE request_id=$1",
    )
    .bind(challenge_id)
    .bind(vec![28_u8])
    .execute(harness.admin_pool())
    .await
    .expect_err("provider response must be immutable after its one transition");
    assert_eq!(
        response_mutation_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("23514")),
    );

    let error = sqlx::raw_sql(RECOVERY_SCOPE_CATALOG_V1_DOWN)
        .execute(harness.admin_pool())
        .await
        .expect_err("populated V41 downgrade must fail before DDL");
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("55000")),
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('identity.recovery_scope_catalogs') IS NOT NULL
                AND to_regclass('identity.recovery_scope_catalog_preparations') IS NOT NULL",
        )
        .fetch_one(harness.admin_pool())
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn history_recovery_group_identity_reader_is_narrow() -> Result<(), Box<dyn std::error::Error>>
{
    const IDENTITY_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

    let harness = PostgresHarness::start().await?;
    let session_id = insert_group_reader_identity_fixture(&harness, IDENTITY_ID).await?;

    let visible_projection: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM identity.log_heads WHERE identity_id=$1)
            AND EXISTS(SELECT 1 FROM identity.log_entries WHERE identity_id=$1)
            AND EXISTS(SELECT 1 FROM identity.device_sessions
                        WHERE identity_id=$1 AND session_id=$2)",
    )
    .bind(IDENTITY_ID)
    .bind(session_id)
    .fetch_one(harness.group_runtime_pool())
    .await?;
    assert!(visible_projection);

    let exact_acl: bool = sqlx::query_scalar(
        "SELECT identity.identity_group_reader_authorized()
            AND NOT has_function_privilege(
                current_user,'identity.identity_runtime_authorized()'::regprocedure,'EXECUTE')
            AND NOT has_function_privilege(
                current_user,'identity.identity_owner_authorized()'::regprocedure,'EXECUTE')
            AND NOT has_function_privilege(
                current_user,'identity.identity_mailbox_reader_authorized()'::regprocedure,'EXECUTE')
            AND NOT has_function_privilege(
                current_user,'identity.identity_realtime_reader_authorized()'::regprocedure,'EXECUTE')
            AND NOT has_table_privilege(
                current_user,'identity.device_enrollment_challenges','SELECT')
            AND NOT has_table_privilege(current_user,'identity.key_packages','SELECT')",
    )
    .fetch_one(harness.group_runtime_pool())
    .await?;
    assert!(exact_acl);

    let broader_helper_error =
        sqlx::query_scalar::<_, bool>("SELECT identity.identity_runtime_authorized()")
            .fetch_one(harness.group_runtime_pool())
            .await
            .expect_err("group runtime must not execute the identity-writer authorizer");
    assert_eq!(
        broader_helper_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("42501")),
    );

    let unrelated_error =
        sqlx::query_scalar::<_, bool>("SELECT identity.identity_group_reader_authorized()")
            .fetch_one(harness.mailbox_runtime_pool())
            .await
            .expect_err("unrelated runtime must not execute the group identity reader");
    assert_eq!(
        unrelated_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("42501")),
    );

    let public_execute: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM pg_proc AS procedure
               CROSS JOIN LATERAL aclexplode(
                   COALESCE(procedure.proacl,acldefault('f',procedure.proowner))
               ) AS privilege
              WHERE procedure.oid='identity.identity_group_reader_authorized()'::regprocedure
                AND privilege.grantee=0
                AND privilege.privilege_type='EXECUTE'
         )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!public_execute);
    Ok(())
}

async fn insert_group_reader_identity_fixture(
    harness: &PostgresHarness,
    identity_id: &str,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let device_id = Uuid::now_v7();
    let challenge_id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
    let mut transaction = harness.admin_pool().begin().await?;
    sqlx::query(
        "INSERT INTO identity.log_heads(
             identity_id,protocol_major,protocol_minor,minimum_reader_major,
             minimum_reader_minor,head_sequence,head_hash,state,created_at_ms,updated_at_ms
         ) VALUES($1,1,1,1,1,1,$2,'active',0,0)",
    )
    .bind(identity_id)
    .bind(vec![1_u8; 32])
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO identity.log_entries(
             identity_id,sequence,entry_hash,previous_hash,protocol_major,
             protocol_minor,minimum_reader_major,minimum_reader_minor,event_bytes,recorded_at_ms
         ) VALUES($1,1,$2,NULL,1,1,1,1,$3,0)",
    )
    .bind(identity_id)
    .bind(vec![1_u8; 32])
    .bind(vec![1_u8])
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO identity.device_session_challenges(
             challenge_id,identity_id,device_id,nonce_hash,audience,state,
             created_at_ms,expires_at_ms,session_expires_at_ms
         ) VALUES($1,$2,$3,$4,'https://group.test','open',0,100,200)",
    )
    .bind(challenge_id)
    .bind(identity_id)
    .bind(device_id)
    .bind(vec![2_u8; 32])
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO identity.device_sessions(
             session_id,identity_id,device_id,challenge_id,session_secret_hash,
             issued_head_sequence,issued_head_hash,issued_at_ms,expires_at_ms
         ) VALUES($1,$2,$3,$4,$5,1,$6,0,200)",
    )
    .bind(session_id)
    .bind(identity_id)
    .bind(device_id)
    .bind(challenge_id)
    .bind(vec![3_u8; 32])
    .bind(vec![1_u8; 32])
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(session_id)
}

#[tokio::test]
async fn history_recovery_down_refuses_v40_facts_before_ddl()
-> Result<(), Box<dyn std::error::Error>> {
    const IDENTITY_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

    let harness = PostgresHarness::start().await?;
    let mut transaction = harness.admin_pool().begin().await?;
    sqlx::query(
        "INSERT INTO identity.log_heads(
             identity_id,protocol_major,protocol_minor,minimum_reader_major,
             minimum_reader_minor,head_sequence,head_hash,state,created_at_ms,updated_at_ms
         ) VALUES($1,1,1,1,1,1,$2,'active',0,0)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![1_u8; 32])
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO identity.log_entries(
             identity_id,sequence,entry_hash,previous_hash,protocol_major,
             protocol_minor,minimum_reader_major,minimum_reader_minor,event_bytes,recorded_at_ms
         ) VALUES($1,1,$2,NULL,1,1,1,1,$3,0)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![1_u8; 32])
    .bind(vec![1_u8])
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO identity.device_enrollment_challenges(
             challenge_id,creation_idempotency_key_hash,identity_id,target_device_id,
             target_device_signing_key,target_device_encryption_key,capability_hash,
             request_digest,state,created_at_ms,expires_at_ms,retention_until_ms,
             protocol_version,recovery_request_bytes,recovery_request_digest,
             observed_head_sequence,observed_head_hash,recovery_mode,request_issued_at_ms,
             recipient_encryption_key,candidate_request_signature
         ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'open',0,100,100,2,$9,$10,1,$11,
                  'all_current_memberships',0,$6,$12)",
    )
    .bind(Uuid::now_v7())
    .bind(vec![2_u8; 32])
    .bind(IDENTITY_ID)
    .bind(Uuid::now_v7())
    .bind(vec![3_u8; 32])
    .bind(vec![4_u8; 32])
    .bind(vec![5_u8; 32])
    .bind(vec![6_u8; 32])
    .bind(vec![7_u8])
    .bind(vec![8_u8; 32])
    .bind(vec![9_u8; 32])
    .bind(vec![10_u8; 64])
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    sqlx::raw_sql(FEDERATED_MLS_V5_AUTHORIZATION_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let error = sqlx::raw_sql(HISTORY_RECOVERY_V1_DOWN)
        .execute(harness.admin_pool())
        .await
        .expect_err("rollback must preserve V40 history recovery facts");
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("55000")),
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('messaging.history_recovery_offers') IS NOT NULL
                AND EXISTS(SELECT 1 FROM identity.device_enrollment_challenges
                           WHERE protocol_version=2)
                AND (SELECT count(*) FROM pg_policy
                      WHERE polrelid IN (
                          'identity.log_heads'::regclass,
                          'identity.log_entries'::regclass,
                          'identity.device_sessions'::regclass
                      )
                        AND polname='identity_runtime_only'
                        AND position('identity_group_reader_authorized'
                                     IN pg_get_expr(polqual,polrelid))>0)=3",
        )
        .fetch_one(harness.admin_pool())
        .await?
    );
    sqlx::raw_sql(FEDERATED_MLS_V5_AUTHORIZATION_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    Ok(())
}

#[tokio::test]
async fn connector_credential_reissue_empty_down_restores_the_v43_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(CONNECTOR_CREDENTIAL_REISSUE_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;

    let intent_table_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass('agent.connector_credential_reissue_intents') IS NOT NULL",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!intent_table_exists);

    let operation_constraint: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid)
           FROM pg_constraint
          WHERE conrelid='agent.connector_control_operations'::regclass
            AND conname='connector_control_operations_kind_valid'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    for preserved_kind in [
        "deliver_agent_provisioning",
        "revoke_agent_provisioning",
        "prepare_agent_route_recipient",
        "deliver_agent_route_bootstrap",
    ] {
        assert!(operation_constraint.contains(preserved_kind));
    }
    assert!(!operation_constraint.contains("credential_reissue"));

    let restored_constraints: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid)
           FROM pg_constraint
          WHERE (conrelid='agent.connector_control_credentials'::regclass
                 AND conname IN (
                    'connector_control_credentials_origin_valid',
                    'connector_control_credentials_generation_unique',
                    'connector_control_credentials_revision_unique'
                 ))
             OR (conrelid='agent.connector_control_credential_revisions'::regclass
                 AND conname='connector_credential_revisions_cause_valid')
          ORDER BY conname",
    )
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(restored_constraints.len(), 4);
    assert!(
        restored_constraints
            .iter()
            .all(|(_, definition)| !definition.contains("reissue"))
    );

    let operation_function: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef(
             'agent.enforce_connector_control_operation_published()'::regprocedure
         )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    let credential_function: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef(
             'agent.enforce_connector_control_credential_insert()'::regprocedure
         )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    let consumed_function: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef(
             'agent.enforce_connector_enrollment_consumed()'::regprocedure
         )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    let revision_function: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef(
             'agent.enforce_connector_credential_revision_insert()'::regprocedure
         )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!operation_function.contains("credential_reissue"));
    assert!(!credential_function.contains("reissue"));
    assert!(!consumed_function.contains("reissue"));
    assert!(!revision_function.contains("reissue"));
    assert!(
        revision_function.contains("selected_credential_origin"),
        "the complete V43 initial-authorization validation must be restored",
    );
    Ok(())
}

#[tokio::test]
async fn connector_credential_reissue_forward_upgrade_preserves_v43_operations()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let mut connection = harness.admin_pool().acquire().await?;
    sqlx::raw_sql(CONNECTOR_CREDENTIAL_REISSUE_V1_DOWN)
        .execute(&mut *connection)
        .await?;

    let tenant_id = Uuid::now_v7();
    let connector_id = Uuid::now_v7();
    sqlx::query("SET session_replication_role='replica'")
        .execute(&mut *connection)
        .await?;
    for operation_kind in [
        "deliver_agent_provisioning",
        "revoke_agent_provisioning",
        "prepare_agent_route_recipient",
        "deliver_agent_route_bootstrap",
    ] {
        sqlx::query(
            "INSERT INTO agent.connector_control_operations (
                tenant_id, operation_id, connector_id, operation_kind, created_at_ms
             ) VALUES ($1,$2,$3,$4,1)",
        )
        .bind(tenant_id)
        .bind(Uuid::now_v7())
        .bind(connector_id)
        .bind(operation_kind)
        .execute(&mut *connection)
        .await?;
    }
    sqlx::query("SET session_replication_role='origin'")
        .execute(&mut *connection)
        .await?;

    sqlx::raw_sql(CONNECTOR_CREDENTIAL_REISSUE_V1_UP)
        .execute(&mut *connection)
        .await?;
    let preserved: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM agent.connector_control_operations
          WHERE tenant_id=$1
            AND operation_kind IN (
                'deliver_agent_provisioning', 'revoke_agent_provisioning',
                'prepare_agent_route_recipient', 'deliver_agent_route_bootstrap'
            )",
    )
    .bind(tenant_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(preserved, 4);
    Ok(())
}

#[tokio::test]
async fn public_discussion_tables_force_tenant_rls_and_keep_histories_append_only()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(
        "CREATE ROLE dtx_public_feed_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS
            NOCREATEDB NOCREATEROLE NOREPLICATION",
    )
    .execute(harness.admin_pool())
    .await?;
    MigrationRunner::new().run(harness.admin_pool()).await?;

    let protected: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM pg_class relation
           JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
           JOIN (VALUES
             ('feed_idempotency_receipts'), ('discussion_policy_heads'),
             ('discussion_policy_versions'), ('discussion_idempotency_receipts'),
             ('discussion_event_ids'), ('feed_comment_threads'),
             ('feed_comment_entries'), ('feed_reaction_entries'),
             ('feed_reaction_projections'), ('discussion_rate_limits')
           ) AS expected(name) ON expected.name=relation.relname
          WHERE namespace.nspname='directory'
            AND relation.relrowsecurity AND relation.relforcerowsecurity",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(protected, 10);

    let delete_grants: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM (VALUES
             ('directory.feed_idempotency_receipts'),
             ('directory.discussion_policy_heads'),
             ('directory.discussion_policy_versions'),
             ('directory.discussion_idempotency_receipts'),
             ('directory.discussion_event_ids'),
             ('directory.feed_comment_threads'),
             ('directory.feed_comment_entries'),
             ('directory.feed_reaction_entries'),
             ('directory.feed_reaction_projections'),
             ('directory.discussion_rate_limits')
           ) AS relation(name)
          WHERE has_table_privilege('dtx_public_feed_runtime', relation.name, 'DELETE')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(delete_grants, 0);

    let append_only_triggers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_trigger
          WHERE tgname IN (
            'feed_idempotency_receipts_append_only',
            'discussion_policy_versions_append_only',
            'discussion_idempotency_receipts_append_only',
            'discussion_event_ids_append_only',
            'feed_comment_entries_append_only',
            'feed_reaction_entries_append_only'
          ) AND NOT tgisinternal",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(append_only_triggers, 6);
    Ok(())
}

type PublicReferenceFact = (i16, String, Option<i64>, Option<Vec<u8>>);

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one migration boundary keeps private-room filtering and public reference projection coherent"
)]
async fn mcp_reference_queries_filter_private_rooms_and_return_public_facts()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    MigrationRunner::new().run(harness.admin_pool()).await?;
    let tenant_id = Uuid::now_v7();
    let visible_identity = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la".to_owned();
    let foreign_identity = "dtxi155pujebuvamvkmouxx6okeiijjuzjxxw4ktjahrjy6z27frlobiq".to_owned();
    let other_group_member = "dtxi1sff4d5opynr3adqmxu4c66uz5zchoj6eb7i7ndbkzr6oet2vwm5q".to_owned();
    let owned_room = Uuid::now_v7();
    let joined_room = Uuid::now_v7();
    let foreign_room = Uuid::now_v7();
    for (room, owner) in [
        (owned_room, &visible_identity),
        (joined_room, &foreign_identity),
        (foreign_room, &foreign_identity),
    ] {
        sqlx::query(
            "INSERT INTO groups.policy_heads(
                 tenant_id, scope_kind, scope_id, owner_identity_id,
                 policy_revision, created_at_ms, updated_at_ms
             ) VALUES($1, 'private_conversation', $2, $3, 1, 1, 1)",
        )
        .bind(tenant_id)
        .bind(room.to_string())
        .bind(owner)
        .execute(harness.admin_pool())
        .await?;
    }
    sqlx::query(
        "INSERT INTO groups.members(
             tenant_id, scope_kind, scope_id, identity_id, admitted_at_ms
         ) VALUES
             ($1, 'private_conversation', $2, $3, 1),
             ($1, 'private_conversation', $2, $4, 1)",
    )
    .bind(tenant_id)
    .bind(joined_room.to_string())
    .bind(&visible_identity)
    .bind(&other_group_member)
    .execute(harness.admin_pool())
    .await?;
    let channel_id = format!("dtxc1c{}", "a".repeat(51));
    sqlx::query(
        "INSERT INTO directory.public_subjects(
             tenant_id, subject_id, subject_kind, publisher_identity_id,
             publisher_signing_key, descriptor_head_sequence, descriptor_head_hash,
             descriptor_expires_at_ms
         ) VALUES($1, $2, 1, $3, $4, 1, $5, 2_000_000_000_000)",
    )
    .bind(tenant_id)
    .bind(&channel_id)
    .bind(&visible_identity)
    .bind(vec![42_u8; 32])
    .bind(vec![43_u8; 32])
    .execute(harness.admin_pool())
    .await?;
    sqlx::query(
        "INSERT INTO directory.feed_entries(
             tenant_id, subject_id, sequence, entry_hash, published_at_ms,
             exact_cbor, tombstone
         ) VALUES($1, $2, 7, $3, 1, $4, false)",
    )
    .bind(tenant_id)
    .bind(&channel_id)
    .bind(vec![44_u8; 32])
    .bind(vec![1_u8])
    .execute(harness.admin_pool())
    .await?;

    let mut transaction = harness.runtime_pool().begin().await?;
    sqlx::query("SELECT set_config('dtx.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let visible: Vec<String> = sqlx::query_scalar(
        "SELECT scope_id
           FROM groups.mcp_visible_private_conversations($1, $2, '', 32)",
    )
    .bind(tenant_id)
    .bind(&visible_identity)
    .fetch_all(&mut *transaction)
    .await?;
    assert_eq!(visible.len(), 2);
    assert!(visible.contains(&owned_room.to_string()));
    assert!(visible.contains(&joined_room.to_string()));
    assert!(!visible.contains(&foreign_room.to_string()));

    let group_member_visible: Vec<String> = sqlx::query_scalar(
        "SELECT scope_id
           FROM groups.mcp_visible_private_conversations($1, $2, '', 32)",
    )
    .bind(tenant_id)
    .bind(&other_group_member)
    .fetch_all(&mut *transaction)
    .await?;
    assert_eq!(group_member_visible, vec![joined_room.to_string()]);

    let one: Vec<String> = sqlx::query_scalar(
        "SELECT scope_id
           FROM groups.mcp_visible_private_conversations($1, $2, $3, 32)",
    )
    .bind(tenant_id)
    .bind(&visible_identity)
    .bind(joined_room.to_string())
    .fetch_all(&mut *transaction)
    .await?;
    assert_eq!(one, vec![joined_room.to_string()]);
    let none: Vec<String> = sqlx::query_scalar(
        "SELECT scope_id
           FROM groups.mcp_visible_private_conversations($1, $2, 'no-match', 32)",
    )
    .bind(tenant_id)
    .bind(&visible_identity)
    .fetch_all(&mut *transaction)
    .await?;
    assert!(none.is_empty());
    let public_facts: Vec<PublicReferenceFact> = sqlx::query_as(
        "SELECT reference_kind, subject_id, sequence, exact_cbor
           FROM directory.mcp_public_reference_facts($1, 6, 256, 1)",
    )
    .bind(tenant_id)
    .fetch_all(&mut *transaction)
    .await?;
    assert_eq!(
        public_facts,
        vec![
            (2, channel_id.clone(), None, None),
            (3, channel_id, Some(7), Some(vec![1_u8])),
        ]
    );
    transaction.rollback().await?;
    Ok(())
}

struct OpaquePushFixture {
    identity_id: String,
    device_id: Uuid,
    session_id: Uuid,
    mailbox_id: Uuid,
    envelope_id: Uuid,
}

async fn opaque_push_fixture(
    harness: &PostgresHarness,
) -> Result<OpaquePushFixture, Box<dyn std::error::Error>> {
    let f = OpaquePushFixture {
        identity_id: "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la".to_owned(),
        device_id: Uuid::now_v7(),
        session_id: Uuid::now_v7(),
        mailbox_id: Uuid::now_v7(),
        envelope_id: Uuid::now_v7(),
    };
    let challenge = Uuid::now_v7();
    let mut tx = harness.admin_pool().begin().await?;
    sqlx::query("INSERT INTO identity.log_heads(identity_id,protocol_major,protocol_minor,minimum_reader_major,minimum_reader_minor,head_sequence,head_hash,state,created_at_ms,updated_at_ms) VALUES($1,1,1,1,1,1,$2,'active',0,0)").bind(&f.identity_id).bind(vec![1_u8;32]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO identity.log_entries(identity_id,sequence,entry_hash,previous_hash,protocol_major,protocol_minor,minimum_reader_major,minimum_reader_minor,event_bytes,recorded_at_ms) VALUES($1,1,$2,NULL,1,1,1,1,$3,0)").bind(&f.identity_id).bind(vec![1_u8;32]).bind(vec![1_u8]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO identity.device_session_challenges(challenge_id,identity_id,device_id,nonce_hash,audience,state,created_at_ms,expires_at_ms,session_expires_at_ms) VALUES($1,$2,$3,$4,'https://push.test','open',0,100000,253402300799999)").bind(challenge).bind(&f.identity_id).bind(f.device_id).bind(vec![2_u8;32]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO identity.device_sessions(session_id,identity_id,device_id,challenge_id,session_secret_hash,issued_head_sequence,issued_head_hash,issued_at_ms,expires_at_ms) VALUES($1,$2,$3,$4,$5,1,$6,1,253402300799999)").bind(f.session_id).bind(&f.identity_id).bind(f.device_id).bind(challenge).bind(vec![3_u8;32]).bind(vec![1_u8;32]).execute(&mut *tx).await?;
    sqlx::query("UPDATE identity.device_session_challenges SET state='consumed',consumed_at_ms=1,session_id=$2 WHERE challenge_id=$1").bind(challenge).bind(f.session_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO messaging.mailboxes(mailbox_id,owner_identity_id,owner_device_id,write_capability_hash,expires_at_ms,created_at_ms) VALUES($1,$2,$3,$4,253402300799999,0)").bind(f.mailbox_id).bind(&f.identity_id).bind(f.device_id).bind(vec![4_u8;32]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO messaging.mailbox_envelopes(mailbox_id,envelope_id,delivery_sequence,opaque_ciphertext,request_digest,receipt_bytes,receipt_hash,expires_at_ms,created_at_ms) VALUES($1,$2,1,$3,$4,$5,$6,253402300799999,0)").bind(f.mailbox_id).bind(f.envelope_id).bind(vec![9_u8]).bind(vec![5_u8;32]).bind(vec![6_u8]).bind(vec![7_u8;32]).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(f)
}

async fn register_push(
    harness: &PostgresHarness,
    fixture: &OpaquePushFixture,
    registration_id: Uuid,
    expected_revision: i64,
    key: u8,
) -> Result<Vec<u8>, sqlx::Error> {
    sqlx::query_scalar("SELECT messaging.opaque_push_commit_put($1,$2,$3,'PUT','/v43/push',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)")
        .bind(fixture.session_id)
        .bind(vec![3_u8; 32])
        .bind(registration_id)
        .bind(vec![key])
        .bind(expected_revision)
        .bind(vec![key; 32])
        .bind(1_i16)
        .bind(1_i16)
        .bind(1_i16)
        .bind(1_i16)
        .bind("active")
        .bind(1_i64)
        .bind(vec![1_u8; 32])
        .bind(vec![0xaa_u8; 17])
        .bind(vec![1_u8; 24])
        .bind(vec![0xbb_u8])
        .bind("kms-v1")
        .bind(vec![0xcc_u8])
        .fetch_one(harness.push_registration_pool())
        .await
}

async fn enqueue_push(
    harness: &PostgresHarness,
    fixture: &OpaquePushFixture,
    delivery_id: Uuid,
    _now_ms: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT messaging.enqueue_opaque_push_intent($1,$2,$3)")
        .bind(delivery_id)
        .bind(fixture.mailbox_id)
        .bind(fixture.envelope_id)
        .fetch_one(harness.mailbox_runtime_pool())
        .await
}

async fn revoke_push(
    harness: &PostgresHarness,
    fixture: &OpaquePushFixture,
    expected_revision: i64,
    key: u8,
) -> Result<Vec<u8>, sqlx::Error> {
    sqlx::query_scalar("SELECT messaging.opaque_push_commit_delete($1,$2,'DELETE','/v43/push',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
        .bind(fixture.session_id)
        .bind(vec![3_u8; 32])
        .bind(vec![key])
        .bind(expected_revision)
        .bind(vec![key; 32])
        .bind(1_i16)
        .bind(1_i16)
        .bind(1_i16)
        .bind(1_i16)
        .bind("active")
        .bind(1_i64)
        .bind(vec![1_u8; 32])
        .fetch_one(harness.push_registration_pool())
        .await
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.into_owned())
}

#[tokio::test]
async fn opaque_push_v43_put_delete_receipts_and_authorization_behave_as_frozen()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let reg = Uuid::now_v7();
    let call = |expected: i64, key: u8| register_push(&h, &f, reg, expected, key);
    let first = call(0, 11).await?;
    let canonical: Vec<u8> =
        sqlx::query_scalar("SELECT messaging.opaque_push_canonical_receipt(1,'active')")
            .fetch_one(h.admin_pool())
            .await?;
    assert_eq!(first, canonical);
    assert_eq!(
        sqlstate(&call(1, 11).await.expect_err("wrong expectation")).as_deref(),
        Some("23505")
    );
    let changed_path = sqlx::query_scalar::<_, Vec<u8>>("SELECT messaging.opaque_push_commit_put($1,$2,$3,'PUT','/v43/other',$4,0::bigint,$5,1::smallint,1::smallint,1::smallint,1::smallint,'active',1::bigint,$6,decode(repeat('aa',17),'hex'),decode(repeat('01',24),'hex'),decode('bb','hex'),'kms-v1',decode('cc','hex'))")
        .bind(f.session_id).bind(vec![3_u8;32]).bind(reg).bind(vec![11_u8]).bind(vec![11_u8;32]).bind(vec![1_u8;32]).fetch_one(h.push_registration_pool()).await
        .expect_err("same idempotency key with changed path conflicts");
    assert_eq!(sqlstate(&changed_path).as_deref(), Some("23505"));
    assert_eq!(
        call(1, 13).await?,
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT messaging.opaque_push_canonical_receipt(2,'active')"
        )
        .fetch_one(h.admin_pool())
        .await?
    );
    assert_eq!(
        sqlstate(&call(1, 14).await.expect_err("stale replace")).as_deref(),
        Some("40001")
    );
    let deleted = revoke_push(&h, &f, 2, 0x15).await?;
    let replay: Vec<u8> = sqlx::query_scalar("SELECT messaging.opaque_push_commit_delete($1,$2,'DELETE','/v43/push',$3,2::bigint,$4,1::smallint,1::smallint,1::smallint,1::smallint,'active',1::bigint,$5)").bind(f.session_id).bind(vec![3_u8;32]).bind(vec![0x15_u8]).bind(vec![0x15_u8;32]).bind(vec![1_u8;32]).fetch_one(h.push_registration_pool()).await?;
    assert_eq!(replay, deleted);
    assert_eq!(
        sqlstate(&call(0, 22).await.expect_err("revoked create")).as_deref(),
        Some("40001")
    );
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_broker_claim_finish_expiry_and_prune_are_transactional()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let mailbox_pool = h.mailbox_runtime_pool().clone();
    let reg = Uuid::now_v7();
    let _: Vec<u8> = register_push(&h, &f, reg, 0, 1).await?;
    sqlx::query("INSERT INTO realtime.identity_heads(identity_id) VALUES($1)")
        .bind(&f.identity_id)
        .execute(h.admin_pool())
        .await?;
    sqlx::query("INSERT INTO realtime.encrypted_account_read_cursors(identity_id,conversation_digest,encrypted_cursor,revision,updated_by_device,updated_at_ms,identity_head,ciphertext_digest) VALUES($1,decode(repeat('01',32),'hex'),decode('aa','hex'),1,$2,20,decode(repeat('01',32),'hex'),decode(repeat('02',32),'hex'))").bind(&f.identity_id).bind(f.device_id).execute(h.mailbox_runtime_pool()).await?;
    let before_cursor_mutation: i64 =
        sqlx::query_scalar("SELECT count(*) FROM messaging.opaque_push_deliveries")
            .fetch_one(h.admin_pool())
            .await?;
    sqlx::query("UPDATE realtime.encrypted_account_read_cursors SET revision=2,updated_at_ms=21 WHERE identity_id=$1").bind(&f.identity_id).execute(h.mailbox_runtime_pool()).await?;
    let after_cursor_mutation: i64 =
        sqlx::query_scalar("SELECT count(*) FROM messaging.opaque_push_deliveries")
            .fetch_one(h.admin_pool())
            .await?;
    assert_eq!(before_cursor_mutation, after_cursor_mutation);
    let delivery = Uuid::now_v7();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT messaging.enqueue_opaque_push_intent($1,$2,$3)")
            .bind(delivery)
            .bind(f.mailbox_id)
            .bind(f.envelope_id)
            .fetch_one(&mailbox_pool)
            .await?,
        1
    );
    let rollback_envelope = Uuid::now_v7();
    let rollback_delivery = Uuid::now_v7();
    let mut mailbox_tx = h.mailbox_runtime_pool().begin().await?;
    sqlx::query("INSERT INTO messaging.mailbox_envelopes(mailbox_id,envelope_id,delivery_sequence,opaque_ciphertext,request_digest,receipt_bytes,receipt_hash,expires_at_ms,created_at_ms) VALUES($1,$2,2,decode('09','hex'),decode(repeat('09',32),'hex'),decode('09','hex'),decode(repeat('09',32),'hex'),1000000,0)")
        .bind(f.mailbox_id).bind(rollback_envelope).execute(&mut *mailbox_tx).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT messaging.enqueue_opaque_push_intent($1,$2,$3)")
            .bind(rollback_delivery)
            .bind(f.mailbox_id)
            .bind(rollback_envelope)
            .fetch_one(&mut *mailbox_tx)
            .await?,
        1
    );
    mailbox_tx.rollback().await?;
    let rolled_back: (bool, bool) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM messaging.mailbox_envelopes WHERE envelope_id=$1), EXISTS(SELECT 1 FROM messaging.opaque_push_deliveries WHERE delivery_id=$2)").bind(rollback_envelope).bind(rollback_delivery).fetch_one(h.admin_pool()).await?;
    assert_eq!(rolled_back, (false, false));
    let claim = Uuid::now_v7();
    let mut claim_tx = h.push_broker_pool().begin().await?;
    let claimed: Vec<(Uuid,)> =
        sqlx::query_as("SELECT delivery_id FROM messaging.claim_opaque_push_deliveries($1,1)")
            .bind(claim)
            .fetch_all(&mut *claim_tx)
            .await?;
    assert_eq!(claimed.len(), 1);
    let other_claim = Uuid::now_v7();
    let duplicate: Vec<(Uuid,)> =
        sqlx::query_as("SELECT delivery_id FROM messaging.claim_opaque_push_deliveries($1,1)")
            .bind(other_claim)
            .fetch_all(h.push_broker_pool())
            .await?;
    assert!(duplicate.is_empty());
    claim_tx.commit().await?;
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT messaging.finish_opaque_push_invalid_token($1,$2,1)")
            .bind(claimed[0].0)
            .bind(claim)
            .fetch_one(h.push_broker_pool())
            .await?
    );
    let states: (String,String) = sqlx::query_as("SELECT d.state,r.state FROM messaging.opaque_push_deliveries d JOIN messaging.opaque_push_registrations r ON r.registration_id=d.registration_id WHERE d.delivery_id=$1").bind(claimed[0].0).fetch_one(h.admin_pool()).await?;
    assert_eq!(states, ("permanent_failure".into(), "suspended".into()));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT messaging.prune_opaque_push_terminal(256)")
            .fetch_one(h.push_broker_pool())
            .await?,
        0
    );
    sqlx::query(
        "UPDATE messaging.opaque_push_deliveries SET terminal_at_ms=0 WHERE delivery_id=$1",
    )
    .bind(claimed[0].0)
    .execute(h.admin_pool())
    .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT messaging.prune_opaque_push_terminal(256)")
            .fetch_one(h.push_broker_pool())
            .await?,
        1
    );
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_concurrent_exact_retries_share_receipt_and_revision()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let registration = Uuid::now_v7();
    let mut tx1 = h.push_registration_pool().begin().await?;
    let tx1_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx1)
        .await?;
    let key = vec![0x0a_u8];
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('opaque_push:idempotency:'||$1::text||':'||encode($2,'hex'),0))")
        .bind(f.device_id).bind(&key).execute(&mut *tx1).await?;
    let first: Vec<u8> = sqlx::query_scalar("SELECT messaging.opaque_push_commit_put($1,$2,$3,'PUT','/v43/push',$4,0::bigint,$5,1::smallint,1::smallint,1::smallint,1::smallint,'active',1::bigint,$6,decode(repeat('aa',17),'hex'),decode(repeat('01',24),'hex'),decode('bb','hex'),'kms-v1',decode('cc','hex'))")
        .bind(f.session_id).bind(vec![3_u8;32]).bind(registration).bind(&key).bind(vec![0x0a_u8;32]).bind(vec![1_u8;32]).fetch_one(&mut *tx1).await?;
    let pool_b = h.push_registration_pool().clone();
    let mut conn2 = pool_b.acquire().await?;
    let tx2_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *conn2)
        .await?;
    let second = tokio::spawn(async move {
        sqlx::query_scalar::<_, Vec<u8>>("SELECT messaging.opaque_push_commit_put($1,$2,$3,'PUT','/v43/push',$4,0::bigint,$5,1::smallint,1::smallint,1::smallint,1::smallint,'active',1::bigint,$6,decode(repeat('aa',17),'hex'),decode(repeat('01',24),'hex'),decode('bb','hex'),'kms-v1',decode('cc','hex'))")
            .bind(f.session_id).bind(vec![3_u8;32]).bind(registration).bind(vec![0x0a_u8]).bind(vec![0x0a_u8;32]).bind(vec![1_u8;32]).fetch_one(&mut *conn2).await
    });
    let mut blocked = false;
    for _ in 0..50 {
        let blockers: Vec<i32> = sqlx::query_scalar("SELECT pg_blocking_pids($1)")
            .bind(tx2_pid)
            .fetch_one(h.admin_pool())
            .await?;
        if blockers.contains(&tx1_pid) {
            blocked = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        blocked,
        "second connection must be observed blocked before winner commit"
    );
    tx1.commit().await?;
    assert_eq!(second.await??, first);
    let durable: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM messaging.opaque_push_registrations WHERE device_id=$1), (SELECT count(*) FROM messaging.opaque_push_idempotency_claims WHERE device_id=$1)")
        .bind(f.device_id).fetch_one(h.admin_pool()).await?;
    assert_eq!(durable, (1, 1));
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_concurrent_if_match_zero_keys_have_one_stable_cas_winner()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let registration = Uuid::now_v7();
    let key_a = vec![0x0b_u8];
    let key_b = vec![0x0c_u8];
    let mut tx1 = h.push_registration_pool().begin().await?;
    let tx1_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx1)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('opaque_push:idempotency:'||$1::text||':'||encode($2,'hex'),0))").bind(f.device_id).bind(&key_a).execute(&mut *tx1).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('opaque_push:provider:'||$1::text||':fcm',0))").bind(f.device_id).execute(&mut *tx1).await?;
    let _: Vec<u8> = sqlx::query_scalar("SELECT messaging.opaque_push_commit_put($1,$2,$3,'PUT','/v43/push',$4,0::bigint,$5,1::smallint,1::smallint,1::smallint,1::smallint,'active',1::bigint,$6,decode(repeat('aa',17),'hex'),decode(repeat('01',24),'hex'),decode('bb','hex'),'kms-v1',decode('cc','hex'))").bind(f.session_id).bind(vec![3_u8;32]).bind(registration).bind(&key_a).bind(vec![0x0b_u8;32]).bind(vec![1_u8;32]).fetch_one(&mut *tx1).await?;
    let pool_b = h.push_registration_pool().clone();
    let mut conn2 = pool_b.acquire().await?;
    let tx2_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *conn2)
        .await?;
    let second = tokio::spawn(async move {
        sqlx::query_scalar::<_, Vec<u8>>("SELECT messaging.opaque_push_commit_put($1,$2,$3,'PUT','/v43/push',$4,0::bigint,$5,1::smallint,1::smallint,1::smallint,1::smallint,'active',1::bigint,$6,decode(repeat('aa',17),'hex'),decode(repeat('01',24),'hex'),decode('bb','hex'),'kms-v1',decode('cc','hex'))").bind(f.session_id).bind(vec![3_u8;32]).bind(registration).bind(&key_b).bind(vec![0x0c_u8;32]).bind(vec![1_u8;32]).fetch_one(&mut *conn2).await
    });
    let mut blocked = false;
    for _ in 0..50 {
        let blockers: Vec<i32> = sqlx::query_scalar("SELECT pg_blocking_pids($1)")
            .bind(tx2_pid)
            .fetch_one(h.admin_pool())
            .await?;
        if blockers.contains(&tx1_pid) {
            blocked = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        blocked,
        "competing provider mutation must be observed blocked before winner commit"
    );
    tx1.commit().await?;
    let conflict = second.await?.expect_err("exactly one CAS conflict");
    assert_eq!(sqlstate(&conflict).as_deref(), Some("40001"));
    let state: (i64, i64, i64) = sqlx::query_as("SELECT count(*), max(revision), (SELECT count(*) FROM messaging.opaque_push_idempotency_claims WHERE device_id=$1) FROM messaging.opaque_push_registrations WHERE device_id=$1")
        .bind(f.device_id).fetch_one(h.admin_pool()).await?;
    assert_eq!(state, (1, 1, 1));
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_identity_auth_force_rls_and_cross_role_denial()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let visible: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM identity.device_sessions),(SELECT count(*) FROM identity.log_heads),(SELECT count(*) FROM identity.log_entries)").fetch_one(h.push_identity_auth_pool()).await?;
    assert!(visible.0 >= 1 && visible.1 >= 1 && visible.2 >= 1);
    for query in [
        "SELECT 1 FROM messaging.opaque_push_registrations",
        "SELECT 1 FROM messaging.opaque_push_idempotency_claims",
        "SELECT 1 FROM messaging.opaque_push_deliveries",
        "UPDATE identity.device_sessions SET expires_at_ms=expires_at_ms WHERE false",
    ] {
        let error = sqlx::raw_sql(query)
            .execute(h.push_identity_auth_pool())
            .await
            .expect_err("identity auth role must not access push/write surfaces");
        assert_eq!(sqlstate(&error).as_deref(), Some("42501"));
    }
    let registration_read = sqlx::query("SELECT 1 FROM identity.device_sessions")
        .fetch_one(h.push_registration_pool())
        .await
        .expect_err("registration role must not gain identity-auth visibility");
    assert_eq!(sqlstate(&registration_read).as_deref(), Some("42501"));
    let _ = f;
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_prepare_auth_replay_survives_logical_expiry_then_prune()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let key = vec![0x41_u8];
    let digest = vec![0x42_u8; 32];
    let prepared: (String, String, Uuid, Uuid, i64, Option<Vec<u8>>) = sqlx::query_as("SELECT outcome,identity_id,device_id,registration_id,next_revision,receipt_bytes FROM messaging.opaque_push_prepare_mutation($1,$2,'PUT','/v43/push',$3,0,$4,$5)").bind(f.session_id).bind(vec![3_u8;32]).bind(&key).bind(&digest).bind(Uuid::now_v7()).fetch_one(h.push_registration_pool()).await?;
    assert_eq!(prepared.0, "execute");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM messaging.opaque_push_registrations WHERE device_id=$1"
        )
        .bind(f.device_id)
        .fetch_one(h.admin_pool())
        .await?,
        0
    );
    let wrong = sqlx::query_as::<_, (String, String, Uuid, Uuid, i64, Option<Vec<u8>>)>(
        "SELECT * FROM messaging.opaque_push_prepare_mutation($1,$2,'PUT','/v43/push',$3,0,$4,$5)",
    )
    .bind(f.session_id)
    .bind(vec![9_u8; 32])
    .bind(&key)
    .bind(&digest)
    .bind(Uuid::now_v7())
    .fetch_one(h.push_registration_pool())
    .await
    .expect_err("wrong secret must fail before replay lookup");
    assert_eq!(sqlstate(&wrong).as_deref(), Some("42501"));
    let receipt = register_push(&h, &f, Uuid::now_v7(), 0, 0x43).await?;
    let replay_key = vec![0x43_u8];
    let replay_digest = vec![0x43_u8; 32];
    let mut expiry_tx = h.admin_pool().begin().await?;
    sqlx::query(
        "ALTER TABLE identity.device_sessions DISABLE TRIGGER identity_device_sessions_append_only",
    )
    .execute(&mut *expiry_tx)
    .await?;
    sqlx::query("UPDATE identity.device_sessions SET expires_at_ms=1 WHERE session_id=$1")
        .bind(f.session_id)
        .execute(&mut *expiry_tx)
        .await?;
    sqlx::query(
        "ALTER TABLE identity.device_sessions ENABLE TRIGGER identity_device_sessions_append_only",
    )
    .execute(&mut *expiry_tx)
    .await?;
    expiry_tx.commit().await?;
    let replay: (String, String, Uuid, Option<Uuid>, Option<i64>, Option<Vec<u8>>) = sqlx::query_as("SELECT outcome,identity_id,device_id,registration_id,next_revision,receipt_bytes FROM messaging.opaque_push_prepare_mutation($1,$2,'PUT','/v43/push',$3,0,$4,$5)").bind(f.session_id).bind(vec![3_u8;32]).bind(&replay_key).bind(&replay_digest).bind(Uuid::now_v7()).fetch_one(h.push_registration_pool()).await?;
    assert_eq!(replay.0, "replay");
    let wrong_replay = sqlx::query_as::<
        _,
        (
            String,
            String,
            Uuid,
            Option<Uuid>,
            Option<i64>,
            Option<Vec<u8>>,
        ),
    >(
        "SELECT * FROM messaging.opaque_push_prepare_mutation($1,$2,'PUT','/v43/push',$3,0,$4,$5)",
    )
    .bind(f.session_id)
    .bind(vec![9_u8; 32])
    .bind(&replay_key)
    .bind(&replay_digest)
    .bind(Uuid::now_v7())
    .fetch_one(h.push_registration_pool())
    .await
    .expect_err("wrong secret must fail before replay receipt lookup");
    assert_eq!(sqlstate(&wrong_replay).as_deref(), Some("42501"));
    let _ = receipt;
    let _pruned: i64 =
        sqlx::query_scalar("SELECT identity.prune_expired_device_sessions(253402300799999,100)")
            .fetch_one(h.identity_runtime_pool())
            .await?;
    let physical = sqlx::query_as::<_, (String, String, Uuid, Uuid, i64, Option<Vec<u8>>)>(
        "SELECT * FROM messaging.opaque_push_prepare_mutation($1,$2,'PUT','/v43/push',$3,0,$4,$5)",
    )
    .bind(f.session_id)
    .bind(vec![3_u8; 32])
    .bind(&replay_key)
    .bind(&replay_digest)
    .bind(Uuid::now_v7())
    .fetch_one(h.push_registration_pool())
    .await
    .expect_err("physical prune must end replay");
    assert_eq!(sqlstate(&physical).as_deref(), Some("42501"));
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_enqueue_ttl_starts_after_provider_lock_unblock()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    register_push(&h, &f, Uuid::now_v7(), 0, 0x51).await?;
    let mut blocker = h.admin_pool().begin().await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('opaque_push:provider:'||$1::text||':fcm',0))").bind(f.device_id).execute(&mut *blocker).await?;
    let mut conn = h.mailbox_runtime_pool().acquire().await?;
    let waiting_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *conn)
        .await?;
    let delivery = Uuid::now_v7();
    let mailbox = f.mailbox_id;
    let envelope = f.envelope_id;
    let task = tokio::spawn(async move {
        sqlx::query_scalar::<_, i64>("SELECT messaging.enqueue_opaque_push_intent($1,$2,$3)")
            .bind(delivery)
            .bind(mailbox)
            .bind(envelope)
            .fetch_one(&mut *conn)
            .await
    });
    let mut blocked = false;
    for _ in 0..100 {
        let pids: Vec<i32> = sqlx::query_scalar("SELECT pg_blocking_pids($1)")
            .bind(waiting_pid)
            .fetch_one(h.admin_pool())
            .await?;
        if pids.contains(&blocker_pid) {
            blocked = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(blocked);
    let unblock: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(h.admin_pool())
            .await?;
    blocker.commit().await?;
    assert_eq!(task.await??, 1);
    let times:(i64,i64)=sqlx::query_as("SELECT created_at_ms,expires_at_ms FROM messaging.opaque_push_deliveries WHERE delivery_id=$1").bind(delivery).fetch_one(h.admin_pool()).await?;
    assert!(times.0 >= unblock && times.1 - times.0 == 60000);
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_transient_clock_is_after_authorize_lock_unblock()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    register_push(&h, &f, Uuid::now_v7(), 0, 0x52).await?;
    let delivery = Uuid::now_v7();
    enqueue_push(&h, &f, delivery, 0).await?;
    let claim = Uuid::now_v7();
    sqlx::query("SELECT delivery_id FROM messaging.claim_opaque_push_deliveries($1,1)")
        .bind(claim)
        .fetch_one(h.push_broker_pool())
        .await?;
    let mut blocker = h.admin_pool().begin().await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('opaque_push:provider:'||$1::text||':fcm',0))").bind(f.device_id).execute(&mut *blocker).await?;
    let mut conn = h.push_broker_pool().acquire().await?;
    let waiting_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *conn)
        .await?;
    let task = tokio::spawn(async move {
        sqlx::query_as::<_, (String, i64, Option<i64>, Option<i64>)>(
            "SELECT * FROM messaging.finish_opaque_push_transient($1,$2,1,'transient')",
        )
        .bind(delivery)
        .bind(claim)
        .fetch_one(&mut *conn)
        .await
    });
    let mut blocked = false;
    for _ in 0..100 {
        let pids: Vec<i32> = sqlx::query_scalar("SELECT pg_blocking_pids($1)")
            .bind(waiting_pid)
            .fetch_one(h.admin_pool())
            .await?;
        if pids.contains(&blocker_pid) {
            blocked = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(blocked);
    let unblock: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(h.admin_pool())
            .await?;
    blocker.commit().await?;
    let row = task.await??;
    assert_eq!(row.0, "scheduled");
    assert!(row.1 >= unblock && row.2.unwrap() > row.1 && row.2.unwrap() < row.3.unwrap());
    Ok(())
}

#[tokio::test]
async fn opaque_push_v43_commit_rechecks_expiry_after_provider_lock_unblock()
-> Result<(), Box<dyn std::error::Error>> {
    let h = PostgresHarness::start().await?;
    let f = opaque_push_fixture(&h).await?;
    let registration = Uuid::now_v7();
    let key = vec![0x53_u8];
    let digest = vec![0x53_u8; 32];
    let expiry: i64 = sqlx::query_scalar(
        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 100",
    )
    .fetch_one(h.admin_pool())
    .await?;
    let mut age = h.admin_pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *age)
        .await?;
    sqlx::query("UPDATE identity.device_sessions SET expires_at_ms=$2 WHERE session_id=$1")
        .bind(f.session_id)
        .bind(expiry)
        .execute(&mut *age)
        .await?;
    age.commit().await?;
    let mut blocker = h.admin_pool().begin().await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('opaque_push:provider:'||$1::text||':fcm',0))").bind(f.device_id).execute(&mut *blocker).await?;
    let mut conn = h.push_registration_pool().acquire().await?;
    let waiting_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *conn)
        .await?;
    let session = f.session_id;
    let task = tokio::spawn(async move {
        sqlx::query_scalar::<_,Vec<u8>>("SELECT messaging.opaque_push_commit_put($1,$2,$3,'PUT','/v43/push',$4,0::bigint,$5,1::smallint,1::smallint,1::smallint,1::smallint,'active',1::bigint,$6,decode(repeat('aa',17),'hex'),decode(repeat('01',24),'hex'),decode('bb','hex'),'kms-v1',decode('cc','hex'))").bind(session).bind(vec![3_u8;32]).bind(registration).bind(key).bind(digest).bind(vec![1_u8;32]).fetch_one(&mut *conn).await
    });
    let mut blocked = false;
    for _ in 0..100 {
        let pids: Vec<i32> = sqlx::query_scalar("SELECT pg_blocking_pids($1)")
            .bind(waiting_pid)
            .fetch_one(h.admin_pool())
            .await?;
        if pids.contains(&blocker_pid) {
            blocked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(blocked);
    let mut expired = false;
    for _ in 0..100 {
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
                .fetch_one(h.admin_pool())
                .await?;
        if now > expiry {
            expired = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        tokio::task::yield_now().await;
    }
    assert!(
        expired,
        "observer clock must pass stored expiry while commit remains blocked"
    );
    blocker.commit().await?;
    let error = task
        .await?
        .expect_err("expired session must reject after provider unblock");
    assert!(matches!(
        sqlstate(&error).as_deref(),
        Some("42501") | Some("22023")
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM messaging.opaque_push_registrations WHERE device_id=$1"
        )
        .bind(f.device_id)
        .fetch_one(h.admin_pool())
        .await?,
        0
    );
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one migration boundary keeps credential quota, authentication, rotation, and revocation coherent"
)]
async fn agent_mcp_credentials_are_digest_only_rotatable_and_exactly_scoped()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let tenant_id = Uuid::now_v7();
    let installation_id = Uuid::now_v7();
    let agent_device_id = Uuid::now_v7();
    let host_id = Uuid::now_v7();
    let connector_id = Uuid::now_v7();
    let binding_id = Uuid::now_v7();
    let conversation_id = Uuid::now_v7();
    let grant_id = Uuid::now_v7();
    let approved_device_id = Uuid::now_v7();
    let owner_id = format!("dtxi1{}", "a".repeat(52));
    let agent_id = format!("dtxa1{}", "a".repeat(52));
    let mut transaction = harness.admin_pool().begin().await?;
    PostgresHarness::set_tenant(&mut transaction, tenant_id).await?;

    sqlx::query("INSERT INTO system.tenant_stream_heads(tenant_id) VALUES($1)")
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO agent.agent_definitions(
             agent_id, definition_version, publisher_id, descriptor_hash,
             expires_at_ms, admitted_at_ms
         ) VALUES($1, 1, $2, $3, 100000, 1)",
    )
    .bind(&agent_id)
    .bind(&owner_id)
    .bind(vec![1_u8; 32])
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.installations(
             tenant_id, installation_id, agent_id, owner_id, execution_mode,
             descriptor_version, descriptor_hash, policy_revision,
             desired_state, observed_state, aggregate_revision,
             created_at_ms, updated_at_ms, agent_identity_id
         ) VALUES($1, $2, $3, $4, 'connector_managed', 1, $5, 1,
                  'enabled', 'ready', 1, 1, 1, $4)",
    )
    .bind(tenant_id)
    .bind(installation_id)
    .bind(&agent_id)
    .bind(&owner_id)
    .bind(vec![1_u8; 32])
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.agent_devices(
             tenant_id, agent_device_id, installation_id,
             credential_fingerprint, state, aggregate_revision,
             created_at_ms, updated_at_ms, identity_device_id
         ) VALUES($1, $2, $3, $4, 'active', 1, 1, 1, $5)",
    )
    .bind(tenant_id)
    .bind(agent_device_id)
    .bind(installation_id)
    .bind(vec![2_u8; 32])
    .bind(approved_device_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.hosts(
             tenant_id, host_id, owner_id, lifecycle, desired_revision,
             observed_revision, reported_health, heartbeat_observed_at_ms,
             heartbeat_expires_at_ms, aggregate_revision, created_at_ms, updated_at_ms
         ) VALUES($1, $2, $3, 'active', 1, 1, 'healthy', 1, 10000, 1, 1, 1)",
    )
    .bind(tenant_id)
    .bind(host_id)
    .bind(&owner_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.connector_instances(
             tenant_id, connector_id, host_id, adapter_kind, generation,
             desired_state, observed_state, max_concurrency, spec_revision,
             highest_lease_epoch, created_at_ms, updated_at_ms
         ) VALUES($1, $2, $3, 'codex', 1, 'running', 'ready', 1, 1, 0, 1, 1)",
    )
    .bind(tenant_id)
    .bind(connector_id)
    .bind(host_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.binding_set_heads(
             tenant_id, mutation_sequence, created_at_ms, updated_at_ms
         ) VALUES($1, 0, 1, 1)",
    )
    .bind(tenant_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.installation_routing_policies(
             tenant_id, installation_id, routing_policy, policy_revision,
             created_at_ms, updated_at_ms
         ) VALUES($1, $2, 'exclusive', 1, 1, 1)",
    )
    .bind(tenant_id)
    .bind(installation_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.connector_bindings(
             tenant_id, binding_id, installation_id, connector_id,
             agent_device_id, priority, max_concurrency, state,
             aggregate_revision, created_at_ms, updated_at_ms
         ) VALUES($1, $2, $3, $4, $5, 0, 1, 'enabled', 1, 1, 1)",
    )
    .bind(tenant_id)
    .bind(binding_id)
    .bind(installation_id)
    .bind(connector_id)
    .bind(agent_device_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.conversation_grant_ids(
             tenant_id, grant_id, conversation_id, installation_id, reserved_at_ms
         ) VALUES($1, $2, $3, $4, 1)",
    )
    .bind(tenant_id)
    .bind(grant_id)
    .bind(conversation_id)
    .bind(installation_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.conversation_grant_versions(
             tenant_id, conversation_id, installation_id, grant_version,
             grant_id, trigger_policy, privacy_policy_hash,
             approved_by_device_id, approved_at_ms, expires_at_ms,
             revoked_at_ms, recorded_at_ms
         ) VALUES($1, $2, $3, 1, $4, 'mention_only', $5, $6, 1, NULL, NULL, 1)",
    )
    .bind(tenant_id)
    .bind(conversation_id)
    .bind(installation_id)
    .bind(grant_id)
    .bind(vec![3_u8; 32])
    .bind(approved_device_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO agent.conversation_grant_heads(
             tenant_id, conversation_id, installation_id,
             current_grant_version, current_grant_id, created_at_ms, updated_at_ms
         ) VALUES($1, $2, $3, 1, $4, 1, 1)",
    )
    .bind(tenant_id)
    .bind(conversation_id)
    .bind(installation_id)
    .bind(grant_id)
    .execute(&mut *transaction)
    .await?;

    let credentials = [
        (Uuid::now_v7(), vec![11_u8; 32]),
        (Uuid::now_v7(), vec![12_u8; 32]),
    ];
    let now_ms: i64 =
        sqlx::query_scalar("SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut *transaction)
            .await?;
    let created_at_ms = now_ms - 1_000;
    let expires_at_ms = now_ms + 60_000;
    for (credential_id, digest) in &credentials {
        sqlx::query(
            "SELECT agent.register_mcp_credential_digest(
                 $1, $2, $3, $4, $5, $6, 'codex-alpha-x3', $7,
                 'mcp.references.v1', $8, $9
             )",
        )
        .bind(tenant_id)
        .bind(credential_id)
        .bind(digest)
        .bind(installation_id)
        .bind(binding_id)
        .bind(agent_device_id)
        .bind(conversation_id)
        .bind(created_at_ms)
        .bind(expires_at_ms)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query("SAVEPOINT third_agent_mcp_credential")
        .execute(&mut *transaction)
        .await?;
    let third = sqlx::query(
        "SELECT agent.register_mcp_credential_digest(
             $1, $2, $3, $4, $5, $6, 'codex-alpha-x3', $7,
             'mcp.references.v1', $8, $9
         )",
    )
    .bind(tenant_id)
    .bind(Uuid::now_v7())
    .bind(vec![13_u8; 32])
    .bind(installation_id)
    .bind(binding_id)
    .bind(agent_device_id)
    .bind(conversation_id)
    .bind(created_at_ms)
    .bind(expires_at_ms)
    .execute(&mut *transaction)
    .await;
    assert!(third.is_err(), "a third live credential must be rejected");
    sqlx::query("ROLLBACK TO SAVEPOINT third_agent_mcp_credential")
        .execute(&mut *transaction)
        .await?;

    sqlx::query("SAVEPOINT future_agent_mcp_credential")
        .execute(&mut *transaction)
        .await?;
    let future = sqlx::query(
        "SELECT agent.register_mcp_credential_digest(
             $1, $2, $3, $4, $5, $6, 'codex-alpha-x3', $7,
             'mcp.references.v1', $8, $9
         )",
    )
    .bind(tenant_id)
    .bind(Uuid::now_v7())
    .bind(vec![14_u8; 32])
    .bind(installation_id)
    .bind(binding_id)
    .bind(agent_device_id)
    .bind(conversation_id)
    .bind(now_ms + 120_000)
    .bind(now_ms + 180_000)
    .execute(&mut *transaction)
    .await;
    assert!(
        future.is_err(),
        "a future creation timestamp must not bypass registration limits"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT future_agent_mcp_credential")
        .execute(&mut *transaction)
        .await?;

    let authorized: Option<Uuid> = sqlx::query_scalar(
        "SELECT conversation_id
           FROM agent.authenticate_mcp_reference_credential($1, $2, $3, $4)",
    )
    .bind(tenant_id)
    .bind(&credentials[0].1)
    .bind("codex-alpha-x3")
    .bind(now_ms)
    .fetch_optional(&mut *transaction)
    .await?;
    assert_eq!(authorized, Some(conversation_id));
    let before_creation: Option<Uuid> = sqlx::query_scalar(
        "SELECT conversation_id
           FROM agent.authenticate_mcp_reference_credential($1, $2, $3, $4)",
    )
    .bind(tenant_id)
    .bind(&credentials[0].1)
    .bind("codex-alpha-x3")
    .bind(created_at_ms - 1)
    .fetch_optional(&mut *transaction)
    .await?;
    assert_eq!(
        before_creation, None,
        "credentials must not authenticate before their creation time"
    );
    let wrong_node: Option<Uuid> = sqlx::query_scalar(
        "SELECT conversation_id
           FROM agent.authenticate_mcp_reference_credential($1, $2, $3, $4)",
    )
    .bind(tenant_id)
    .bind(&credentials[0].1)
    .bind("other-node")
    .bind(now_ms)
    .fetch_optional(&mut *transaction)
    .await?;
    assert_eq!(wrong_node, None);

    let revoked: bool =
        sqlx::query_scalar("SELECT agent.revoke_mcp_credential_digest($1, $2, $3, $4)")
            .bind(tenant_id)
            .bind(credentials[0].0)
            .bind(&credentials[0].1)
            .bind(now_ms)
            .fetch_one(&mut *transaction)
            .await?;
    assert!(revoked);
    let after_revoke: Option<Uuid> = sqlx::query_scalar(
        "SELECT conversation_id
           FROM agent.authenticate_mcp_reference_credential($1, $2, $3, $4)",
    )
    .bind(tenant_id)
    .bind(&credentials[0].1)
    .bind("codex-alpha-x3")
    .bind(now_ms + 1)
    .fetch_optional(&mut *transaction)
    .await?;
    assert_eq!(after_revoke, None);

    transaction.rollback().await?;
    Ok(())
}

#[tokio::test]
async fn agent_run_runtime_privileges_are_forward_and_reversible()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(
        "DO $role$
         BEGIN
             IF to_regrole('dtx_agent_runtime') IS NULL THEN
                 CREATE ROLE dtx_agent_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS
                     NOCREATEDB NOCREATEROLE NOREPLICATION;
             END IF;
         END
         $role$;",
    )
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql(AGENT_RUN_RUNTIME_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;

    let expected_rights = "SELECT count(*)
           FROM (VALUES
             ('agent.agent_run_execution_heads', 'SELECT'),
             ('agent.agent_run_execution_heads', 'INSERT'),
             ('agent.agent_run_execution_heads', 'UPDATE'),
             ('agent.agent_run_checkpoints', 'SELECT'),
             ('agent.agent_run_checkpoints', 'INSERT'),
             ('agent.agent_run_outputs', 'SELECT'),
             ('agent.agent_run_outputs', 'INSERT'),
             ('agent.agent_run_terminals', 'SELECT'),
             ('agent.agent_run_terminals', 'INSERT'),
             ('agent.agent_run_cancellation_intents', 'SELECT'),
             ('agent.agent_run_cancellation_intents', 'INSERT')
           ) AS expected(relation_name, privilege_name)
          WHERE has_table_privilege(
              'dtx_agent_runtime', relation_name, privilege_name
          )";
    let before: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(before, 0);

    sqlx::raw_sql(AGENT_RUN_RUNTIME_PRIVILEGES_UP)
        .execute(harness.admin_pool())
        .await?;
    let granted: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(granted, 11);
    let excess: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM (VALUES
             ('agent.agent_run_execution_heads', 'DELETE'),
             ('agent.agent_run_checkpoints', 'UPDATE'),
             ('agent.agent_run_outputs', 'UPDATE'),
             ('agent.agent_run_terminals', 'UPDATE'),
             ('agent.agent_run_cancellation_intents', 'UPDATE')
           ) AS denied(relation_name, privilege_name)
          WHERE has_table_privilege(
              'dtx_agent_runtime', relation_name, privilege_name
          )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(excess, 0);

    sqlx::raw_sql(AGENT_RUN_RUNTIME_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let after: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(after, 0);
    Ok(())
}

#[tokio::test]
async fn agent_acceptance_finalize_privileges_are_exact_and_reversible()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(
        "DO $role$
         BEGIN
             IF to_regrole('dtx_agent_runtime') IS NULL THEN
                 CREATE ROLE dtx_agent_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS
                     NOCREATEDB NOCREATEROLE NOREPLICATION;
             END IF;
         END
         $role$;",
    )
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql(AGENT_ACCEPTANCE_FINALIZE_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;

    let expected_rights = "SELECT count(*)
           FROM (VALUES
             ('agent.agent_definitions', 'SELECT'),
             ('agent.agent_definitions', 'INSERT'),
             ('agent.agent_definition_heads', 'SELECT'),
             ('agent.agent_definition_heads', 'INSERT'),
             ('agent.agent_definition_heads', 'UPDATE'),
             ('agent.installations', 'INSERT'),
             ('agent.installations', 'UPDATE'),
             ('agent.agent_devices', 'INSERT'),
             ('agent.agent_devices', 'UPDATE'),
             ('agent.host_credentials', 'SELECT')
           ) AS expected(relation_name, privilege_name)
          WHERE has_table_privilege(
              'dtx_agent_runtime', relation_name, privilege_name
          )";
    let before: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(before, 0);

    sqlx::raw_sql(AGENT_ACCEPTANCE_FINALIZE_PRIVILEGES_UP)
        .execute(harness.admin_pool())
        .await?;
    let granted: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(granted, 10);
    let excess: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM (VALUES
             ('agent.agent_definitions', 'UPDATE'),
             ('agent.agent_definitions', 'DELETE'),
             ('agent.agent_definition_heads', 'DELETE'),
             ('agent.installations', 'DELETE'),
             ('agent.agent_devices', 'DELETE'),
             ('agent.host_credentials', 'INSERT'),
             ('agent.host_credentials', 'UPDATE'),
             ('agent.host_credentials', 'DELETE')
           ) AS denied(relation_name, privilege_name)
          WHERE has_table_privilege(
              'dtx_agent_runtime', relation_name, privilege_name
          )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(excess, 0);

    sqlx::raw_sql(AGENT_ACCEPTANCE_FINALIZE_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let after: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(after, 0);
    Ok(())
}

#[tokio::test]
async fn agent_acceptance_prepare_privileges_are_exact_and_reversible()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(
        "DO $role$
         BEGIN
             IF to_regrole('dtx_agent_runtime') IS NULL THEN
                 CREATE ROLE dtx_agent_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS
                     NOCREATEDB NOCREATEROLE NOREPLICATION;
             END IF;
         END
         $role$;",
    )
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql(AGENT_ACCEPTANCE_PREPARE_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;

    let expected_rights = "SELECT count(*)
           FROM (VALUES
             ('agent.hosts', 'INSERT'),
             ('agent.host_credentials', 'INSERT')
           ) AS expected(relation_name, privilege_name)
          WHERE has_table_privilege(
              'dtx_agent_runtime', relation_name, privilege_name
          )";
    let before: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(before, 0);

    sqlx::raw_sql(AGENT_ACCEPTANCE_PREPARE_PRIVILEGES_UP)
        .execute(harness.admin_pool())
        .await?;
    let granted: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(granted, 2);
    let excess: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM (VALUES
             ('agent.hosts', 'UPDATE'),
             ('agent.hosts', 'DELETE'),
             ('agent.host_credentials', 'UPDATE'),
             ('agent.host_credentials', 'DELETE')
           ) AS denied(relation_name, privilege_name)
          WHERE has_table_privilege(
              'dtx_agent_runtime', relation_name, privilege_name
          )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(excess, 0);

    sqlx::raw_sql(AGENT_ACCEPTANCE_PREPARE_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let after: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(after, 0);
    Ok(())
}

#[tokio::test]
async fn agent_acceptance_tenant_stream_privileges_are_exact_and_reversible()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(
        "DO $role$
         BEGIN
             IF to_regrole('dtx_agent_runtime') IS NULL THEN
                 CREATE ROLE dtx_agent_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS
                     NOCREATEDB NOCREATEROLE NOREPLICATION;
             END IF;
         END
         $role$;",
    )
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql(AGENT_ACCEPTANCE_TENANT_STREAM_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;

    let expected_rights = "SELECT count(*)
           FROM (VALUES
             ('system.tenant_stream_heads', 'INSERT')
           ) AS expected(relation_name, privilege_name)
          WHERE has_table_privilege(
              'dtx_agent_runtime', relation_name, privilege_name
          )";
    let before: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(before, 0);

    sqlx::raw_sql(AGENT_ACCEPTANCE_TENANT_STREAM_PRIVILEGES_UP)
        .execute(harness.admin_pool())
        .await?;
    let granted: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(granted, 1);
    let excess: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM (VALUES
             ('system.tenant_stream_heads', 'SELECT'),
             ('system.tenant_stream_heads', 'UPDATE'),
             ('system.tenant_stream_heads', 'DELETE')
           ) AS denied(relation_name, privilege_name)
          WHERE has_table_privilege(
              'dtx_agent_runtime', relation_name, privilege_name
          )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(excess, 0);

    sqlx::raw_sql(AGENT_ACCEPTANCE_TENANT_STREAM_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let after: i64 = sqlx::query_scalar(expected_rights)
        .fetch_one(harness.admin_pool())
        .await?;
    assert_eq!(after, 0);
    Ok(())
}

#[tokio::test]
async fn agent_acceptance_tenant_stream_select_is_exact_and_reversible()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(
        "DO $role$
         BEGIN
             IF to_regrole('dtx_agent_runtime') IS NULL THEN
                 CREATE ROLE dtx_agent_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS
                     NOCREATEDB NOCREATEROLE NOREPLICATION;
             END IF;
         END
         $role$;",
    )
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql(AGENT_ACCEPTANCE_TENANT_STREAM_SELECT_DOWN)
        .execute(harness.admin_pool())
        .await?;

    let expected_right = "SELECT has_table_privilege(
        'dtx_agent_runtime', 'system.tenant_stream_heads', 'SELECT'
    )";
    let before: bool = sqlx::query_scalar(expected_right)
        .fetch_one(harness.admin_pool())
        .await?;
    assert!(!before);

    sqlx::raw_sql(AGENT_ACCEPTANCE_TENANT_STREAM_SELECT_UP)
        .execute(harness.admin_pool())
        .await?;
    let granted: bool = sqlx::query_scalar(expected_right)
        .fetch_one(harness.admin_pool())
        .await?;
    assert!(granted);
    let excess: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM (VALUES
             ('system.tenant_stream_heads', 'UPDATE'),
             ('system.tenant_stream_heads', 'DELETE')
           ) AS denied(relation_name, privilege_name)
          WHERE has_table_privilege(
              'dtx_agent_runtime', relation_name, privilege_name
          )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(excess, 0);

    sqlx::raw_sql(AGENT_ACCEPTANCE_TENANT_STREAM_SELECT_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let after: bool = sqlx::query_scalar(expected_right)
        .fetch_one(harness.admin_pool())
        .await?;
    assert!(!after);
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
            .and_then(sqlx::error::DatabaseError::code),
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
async fn mailbox_retention_empty_down_up_preserves_v49_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(MAILBOX_RETAINED_QUOTA_GC_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let removed: bool = sqlx::query_scalar(
        "SELECT to_regprocedure('messaging.enforce_replay_claim_retention()') IS NULL
            AND to_regclass('messaging.messaging_identity_delivery_expiry_gc_idx') IS NULL
            AND to_regclass('messaging.messaging_mailbox_retained_quota_idx') IS NULL
            AND to_regclass('messaging.messaging_envelope_tombstone_gc_idx') IS NULL
            AND to_regclass('messaging.messaging_mailbox_ack_replay_gc_idx') IS NULL
            AND to_regclass('messaging.messaging_device_ack_replay_gc_idx') IS NULL",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(removed);

    sqlx::raw_sql(MAILBOX_RETAINED_QUOTA_GC_V1_UP)
        .execute(harness.admin_pool())
        .await?;
    let restored: bool = sqlx::query_scalar(
        "SELECT to_regprocedure('messaging.enforce_replay_claim_retention()') IS NOT NULL
            AND to_regclass('messaging.messaging_identity_delivery_expiry_gc_idx') IS NOT NULL
            AND to_regclass('messaging.messaging_mailbox_retained_quota_idx') IS NOT NULL
            AND to_regclass('messaging.messaging_envelope_tombstone_gc_idx') IS NOT NULL
            AND to_regclass('messaging.messaging_mailbox_ack_replay_gc_idx') IS NOT NULL
            AND to_regclass('messaging.messaging_device_ack_replay_gc_idx') IS NOT NULL",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(restored);
    Ok(())
}

#[tokio::test]
async fn realtime_retention_down_refuses_to_drop_a_compacted_delivery_floor()
-> Result<(), Box<dyn std::error::Error>> {
    const IDENTITY_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(MAILBOX_RETAINED_QUOTA_GC_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    let mut transaction = harness.admin_pool().begin().await?;
    sqlx::query(
        "INSERT INTO identity.log_heads(
             identity_id,protocol_major,protocol_minor,minimum_reader_major,
             minimum_reader_minor,head_sequence,head_hash,state,created_at_ms,updated_at_ms
         ) VALUES($1,1,1,1,1,1,$2,'active',0,0)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![7_u8; 32])
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO identity.log_entries(
             identity_id,sequence,entry_hash,previous_hash,protocol_major,
             protocol_minor,minimum_reader_major,minimum_reader_minor,event_bytes,recorded_at_ms
         ) VALUES($1,1,$2,NULL,1,1,1,1,$3,0)",
    )
    .bind(IDENTITY_ID)
    .bind(vec![7_u8; 32])
    .bind(vec![1_u8])
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO messaging.identity_delivery_heads(
             identity_id,next_sequence,compacted_through
         ) VALUES($1,1,1)",
    )
    .bind(IDENTITY_ID)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let error = sqlx::raw_sql(REALTIME_SYNC_RETENTION_SAFETY_V1_DOWN)
        .execute(harness.admin_pool())
        .await
        .expect_err("rollback must preserve a compacted delivery floor");
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("55000")),
    );
    let floor: i64 = sqlx::query_scalar(
        "SELECT compacted_through FROM messaging.identity_delivery_heads WHERE identity_id=$1",
    )
    .bind(IDENTITY_ID)
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(floor, 1);
    Ok(())
}

#[tokio::test]
async fn realtime_retention_empty_down_restores_v47_ciphertext_schema()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(MAILBOX_RETAINED_QUOTA_GC_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(REALTIME_SYNC_RETENTION_SAFETY_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;

    let (nullable, compacted_column_exists, constraint): (String, bool, String) = sqlx::query_as(
        "SELECT column_info.is_nullable,
                    EXISTS(
                        SELECT 1 FROM information_schema.columns
                         WHERE table_schema='messaging'
                           AND table_name='identity_delivery_heads'
                           AND column_name='compacted_through'
                    ),
                    pg_get_constraintdef(constraint_info.oid)
               FROM information_schema.columns AS column_info
               JOIN pg_constraint AS constraint_info
                 ON constraint_info.conrelid='messaging.mailbox_envelopes'::regclass
                AND constraint_info.conname='messaging_envelopes_ciphertext_bounded'
              WHERE column_info.table_schema='messaging'
                AND column_info.table_name='mailbox_envelopes'
                AND column_info.column_name='opaque_ciphertext'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(nullable, "NO");
    assert!(!compacted_column_exists);
    assert!(constraint.contains("octet_length(opaque_ciphertext)"));
    assert!(!constraint.contains("IS NULL"));
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
          WHERE version IN ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50, $51, $52, $53, $54, $55)",
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
    .bind(AGENT_RUN_RUNTIME_PRIVILEGES_MIGRATION_VERSION)
    .bind(GROUP_MEMBER_REMOVAL_V32_MIGRATION_VERSION)
    .bind(MCP_REFERENCE_QUERIES_MIGRATION_VERSION)
    .bind(AGENT_MCP_CREDENTIALS_MIGRATION_VERSION)
    .bind(AGENT_ACCEPTANCE_FINALIZE_PRIVILEGES_MIGRATION_VERSION)
    .bind(AGENT_ACCEPTANCE_PREPARE_PRIVILEGES_MIGRATION_VERSION)
    .bind(AGENT_ACCEPTANCE_TENANT_STREAM_PRIVILEGES_MIGRATION_VERSION)
    .bind(AGENT_ACCEPTANCE_TENANT_STREAM_SELECT_MIGRATION_VERSION)
    .bind(PUBLIC_DISCUSSION_V1_MIGRATION_VERSION)
    .bind(CONNECTOR_CREDENTIAL_REISSUE_V1_MIGRATION_VERSION)
    .bind(REALTIME_SYNC_MULTIDEVICE_MAILBOX_V1_MIGRATION_VERSION)
    .bind(ACCOUNT_RECOVERY_REALTIME_OUTBOX_V1_MIGRATION_VERSION)
    .bind(REALTIME_SYNC_CONTINUITY_V2_MIGRATION_VERSION)
    .bind(HISTORY_RECOVERY_V1_MIGRATION_VERSION)
    .bind(REALTIME_SYNC_RETENTION_SAFETY_V1_MIGRATION_VERSION)
    .bind(MAILBOX_RETAINED_QUOTA_GC_V1_MIGRATION_VERSION)
    .bind(FEDERATED_MLS_V5_AUTHORIZATION_V1_MIGRATION_VERSION)
    .bind(RECOVERY_SCOPE_CATALOG_V1_MIGRATION_VERSION)
    .bind(OPAQUE_PUSH_V1_MIGRATION_VERSION)
    .bind(CONNECTOR_BOOTSTRAP_ISSUANCE_V1_MIGRATION_VERSION)
    .bind(AGENT_IDENTITY_READER_RLS_FIX_MIGRATION_VERSION)
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql(AGENT_IDENTITY_READER_RLS_FIX_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(CONNECTOR_BOOTSTRAP_ISSUANCE_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(OPAQUE_PUSH_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(RECOVERY_SCOPE_CATALOG_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(FEDERATED_MLS_V5_AUTHORIZATION_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(MAILBOX_RETAINED_QUOTA_GC_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(REALTIME_SYNC_RETENTION_SAFETY_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(HISTORY_RECOVERY_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(REALTIME_SYNC_CONTINUITY_V2_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(ACCOUNT_RECOVERY_REALTIME_OUTBOX_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(REALTIME_SYNC_MULTIDEVICE_MAILBOX_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(CONNECTOR_CREDENTIAL_REISSUE_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(PUBLIC_DISCUSSION_V1_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_ACCEPTANCE_TENANT_STREAM_SELECT_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_ACCEPTANCE_TENANT_STREAM_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_ACCEPTANCE_PREPARE_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_ACCEPTANCE_FINALIZE_PRIVILEGES_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_MCP_CREDENTIALS_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(MCP_REFERENCE_QUERIES_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(GROUP_MEMBER_REMOVAL_V32_DOWN)
        .execute(harness.admin_pool())
        .await?;
    sqlx::raw_sql(AGENT_RUN_RUNTIME_PRIVILEGES_DOWN)
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
#[allow(
    clippy::too_many_lines,
    reason = "one migration boundary audits the runtime role's complete RLS, capability, and DDL surface"
)]
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
    let direct_directory_table_grants: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM information_schema.table_privileges
          WHERE grantee = 'dtx_runtime_test'
            AND table_schema = 'directory'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(direct_directory_table_grants, 0);
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
    for function in [
        "groups.mcp_visible_private_conversations(uuid,text,text,integer)",
        "directory.mcp_public_reference_facts(uuid,integer,integer,bigint)",
        "agent.authenticate_mcp_reference_credential(uuid,bytea,text,bigint)",
    ] {
        let available: bool = sqlx::query_scalar(
            "SELECT has_function_privilege('dtx_runtime_test', $1::regprocedure, 'EXECUTE')",
        )
        .bind(function)
        .fetch_one(harness.admin_pool())
        .await?;
        assert!(available, "{function} must be the only MCP read capability");
    }
    let direct_agent_mcp_table_access: bool = sqlx::query_scalar(
        "SELECT has_table_privilege(
                    'dtx_runtime_test',
                    'agent.mcp_credentials',
                    'SELECT,INSERT,UPDATE,DELETE'
                )",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(
        !direct_agent_mcp_table_access,
        "runtime must authenticate only through the scoped digest function"
    );
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
