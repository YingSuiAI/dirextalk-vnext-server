mod support;

use dtx_storage::MigrationRunner;
use support::PostgresHarness;

const CURRENT_BASELINE_COUNT: i64 = 26;
const LOCAL_RUNTIME_GRANTS: &str =
    include_str!("../../../docker/local/postgres/20-local-runtime-grants.sql");

#[tokio::test]
async fn fresh_baseline_installs_current_schema_and_reruns_idempotently()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;

    MigrationRunner::new().run(harness.admin_pool()).await?;
    let before_rerun: (i64, String, Vec<u8>) = sqlx::query_as(
        "SELECT count(*), (SELECT epoch FROM system.schema_epoch WHERE singleton), \
                (SELECT baseline_digest FROM system.schema_epoch WHERE singleton) \
         FROM public._sqlx_migrations WHERE success = true",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    MigrationRunner::new().run(harness.admin_pool()).await?;

    let applied: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public._sqlx_migrations WHERE success = true")
            .fetch_one(harness.admin_pool())
            .await?;
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM system.schema_versions")
        .fetch_one(harness.admin_pool())
        .await?;
    let epoch: (String, i32) = sqlx::query_as(
        "SELECT epoch, octet_length(baseline_digest) FROM system.schema_epoch WHERE singleton",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    let digest_after_rerun: Vec<u8> =
        sqlx::query_scalar("SELECT baseline_digest FROM system.schema_epoch WHERE singleton")
            .fetch_one(harness.admin_pool())
            .await?;
    assert_eq!(applied, CURRENT_BASELINE_COUNT);
    assert_eq!(visible, CURRENT_BASELINE_COUNT);
    assert_eq!(
        epoch,
        (
            "product-core-alpha-20260725-history-recovery-completion-v2".to_owned(),
            32
        )
    );
    assert_eq!(before_rerun.0, applied);
    assert_eq!(before_rerun.1, epoch.0);
    assert_eq!(before_rerun.2, digest_after_rerun);
    Ok(())
}

#[tokio::test]
async fn fresh_baseline_retains_current_business_schema_and_rls()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let current: (bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT to_regclass('identity.log_heads') IS NOT NULL,
                to_regclass('groups.policy_heads') IS NOT NULL,
                to_regclass('messaging.mailbox_envelopes') IS NOT NULL,
                to_regclass('messaging.opaque_push_deliveries') IS NOT NULL,
                to_regclass('agent.agent_runs') IS NOT NULL,
                (SELECT relrowsecurity AND relforcerowsecurity
                   FROM pg_class WHERE oid = 'messaging.mailbox_envelopes'::regclass)",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(current, (true, true, true, true, true, true));
    Ok(())
}

#[tokio::test]
async fn active_runtime_roles_receive_only_schema_epoch_read_access()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    sqlx::raw_sql(
        "DO $roles$
         DECLARE
           role_name text;
         BEGIN
           FOREACH role_name IN ARRAY ARRAY[
             'dtx_identity_runtime', 'dtx_group_runtime', 'dtx_mailbox_runtime',
             'dtx_realtime_sync_runtime', 'dtx_push_registration_runtime',
             'dtx_push_identity_auth_runtime', 'dtx_push_broker_runtime',
             'dtx_public_feed_runtime', 'dtx_public_feed_node', 'dtx_indexer_node'
           ] LOOP
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
               EXECUTE format('CREATE ROLE %I NOLOGIN', role_name);
             END IF;
           END LOOP;
         END
         $roles$;",
    )
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql(LOCAL_RUNTIME_GRANTS)
        .execute(harness.admin_pool())
        .await?;
    let grants: (bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT has_table_privilege('dtx_identity_runtime', 'system.schema_epoch', 'SELECT'),
                has_table_privilege('dtx_group_runtime', 'system.schema_epoch', 'SELECT'),
                has_table_privilege('dtx_mailbox_runtime', 'system.schema_epoch', 'SELECT'),
                has_table_privilege('dtx_realtime_sync_runtime', 'system.schema_epoch', 'SELECT'),
                has_table_privilege('dtx_identity_runtime', 'system.schema_epoch', 'INSERT'),
                has_table_privilege('dtx_group_runtime', 'system.schema_epoch', 'INSERT'),
                has_table_privilege('dtx_mailbox_runtime', 'system.schema_epoch', 'INSERT'),
                has_table_privilege('dtx_realtime_sync_runtime', 'system.schema_epoch', 'INSERT')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(grants, (true, true, true, true, false, false, false, false));
    Ok(())
}
