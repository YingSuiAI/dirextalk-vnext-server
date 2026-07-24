#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
async fn realtime_compactor_waits_for_writer_advisory_lock_before_realtime_head()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let database_now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let owner =
        enroll_active_device_at(&identity_store, 226, 227, 228, [229; 32], database_now).await?;
    let identity_id = owner.identity_id.to_string();

    let expired = sqlx::query(
        "UPDATE realtime.journal
            SET created_at_ms=$2,expires_at_ms=$3
          WHERE identity_id=$1",
    )
    .bind(&identity_id)
    .bind(database_now - 2)
    .bind(database_now - 1)
    .execute(harness.admin_pool())
    .await?;
    assert!(expired.rows_affected() > 0);
    sqlx::query(
        "INSERT INTO messaging.identity_delivery_heads(identity_id)
         VALUES($1) ON CONFLICT(identity_id) DO NOTHING",
    )
    .bind(&identity_id)
    .execute(harness.admin_pool())
    .await?;

    // Mirror the business writer's advisory -> messaging head -> realtime head
    // order. The compactor must wait at the advisory edge and must not retain a
    // realtime head lock while waiting, which was the former deadlock cycle.
    let mut writer = harness.admin_pool().begin().await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(
             hashtextextended('mailbox-identity:' || $1,0))",
    )
    .bind(&identity_id)
    .execute(&mut *writer)
    .await?;
    sqlx::query(
        "SELECT 1 FROM messaging.identity_delivery_heads
          WHERE identity_id=$1 FOR UPDATE",
    )
    .bind(&identity_id)
    .execute(&mut *writer)
    .await?;

    let mut compactor_connection =
        PgConnection::connect_with(&harness.realtime_sync_runtime_options()).await?;
    let compactor_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut compactor_connection)
        .await?;
    let compact_task = tokio::spawn(async move {
        sqlx::query_scalar::<_, i32>("SELECT realtime.compact_expired($1,256)")
            .bind(database_now)
            .fetch_one(&mut compactor_connection)
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let waiting_for_advisory: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                     SELECT 1 FROM pg_locks
                      WHERE pid=$1 AND locktype='advisory' AND NOT granted
                 )",
            )
            .bind(compactor_pid)
            .fetch_one(harness.admin_pool())
            .await?;
            if waiting_for_advisory {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "realtime compactor did not reach its advisory lock barrier")??;

    let realtime_head: i64 = sqlx::query_scalar(
        "SELECT next_cursor FROM realtime.identity_heads
          WHERE identity_id=$1 FOR UPDATE NOWAIT",
    )
    .bind(&identity_id)
    .fetch_one(&mut *writer)
    .await?;
    assert!(realtime_head > 0);
    writer.commit().await?;

    let compacted = compact_task.await??;
    assert!(compacted > 0);
    Ok(())
}
