mod support;

use support::PostgresHarness;

#[tokio::test]
async fn readiness_requires_embedded_migrations_and_every_requested_privilege()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(2).await?;
    let required = [
        ("system.tenant_stream_heads", "SELECT"),
        ("system.tenant_stream_heads", "INSERT"),
        ("system.tenant_stream_heads", "UPDATE"),
    ];
    let required_functions = [("system.current_tenant_id()", "EXECUTE")];

    let database_and_migrations = store.readiness_check(&[], &[]).await?;
    let required_privileges = store
        .readiness_check(&required, &required_functions)
        .await?;
    let missing_privilege = store
        .readiness_check(&[("system.tenant_stream_heads", "DELETE")], &[])
        .await?;
    sqlx::query("REVOKE EXECUTE ON FUNCTION system.current_tenant_id() FROM dtx_runtime_test")
        .execute(harness.admin_pool())
        .await?;
    let revoked_function = store
        .readiness_check(&required, &required_functions)
        .await?;
    assert!(
        database_and_migrations && required_privileges && !missing_privilege && !revoked_function,
        "readiness evidence: database_and_migrations={database_and_migrations}, \
         required_privileges={required_privileges}, missing_privilege={missing_privilege}, \
         revoked_function={revoked_function}"
    );
    Ok(())
}

#[tokio::test]
async fn readiness_rejects_any_non_exact_schema_epoch_record()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(2).await?;
    assert!(store.readiness_check(&[], &[]).await?);

    let (version, checksum): (i64, Vec<u8>) = sqlx::query_as(
        "SELECT version, checksum FROM public._sqlx_migrations ORDER BY version LIMIT 1",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    sqlx::query("UPDATE public._sqlx_migrations SET checksum=decode(repeat('00',48),'hex') WHERE version=$1")
        .bind(version)
        .execute(harness.admin_pool())
        .await?;
    assert!(!store.readiness_check(&[], &[]).await?);
    sqlx::query("UPDATE public._sqlx_migrations SET checksum=$1 WHERE version=$2")
        .bind(checksum)
        .bind(version)
        .execute(harness.admin_pool())
        .await?;

    sqlx::query("INSERT INTO public._sqlx_migrations(version,description,success,checksum,execution_time) VALUES(999999999998,'unexpected baseline',true,decode(repeat('00',48),'hex'),0)")
        .execute(harness.admin_pool()).await?;
    assert!(!store.readiness_check(&[], &[]).await?);
    sqlx::query("DELETE FROM public._sqlx_migrations WHERE version=999999999998")
        .execute(harness.admin_pool())
        .await?;

    sqlx::query("INSERT INTO public._sqlx_migrations(version,description,success,checksum,execution_time) VALUES(999999999997,'failed baseline',false,decode(repeat('00',48),'hex'),0)")
        .execute(harness.admin_pool()).await?;
    assert!(!store.readiness_check(&[], &[]).await?);
    sqlx::query("DELETE FROM public._sqlx_migrations WHERE version=999999999997")
        .execute(harness.admin_pool())
        .await?;

    let digest: Vec<u8> =
        sqlx::query_scalar("SELECT baseline_digest FROM system.schema_epoch WHERE singleton")
            .fetch_one(harness.admin_pool())
            .await?;
    sqlx::query("UPDATE system.schema_epoch SET baseline_digest=decode(repeat('00',32),'hex') WHERE singleton")
        .execute(harness.admin_pool()).await?;
    assert!(!store.readiness_check(&[], &[]).await?);
    sqlx::query("UPDATE system.schema_epoch SET baseline_digest=$1 WHERE singleton")
        .bind(digest)
        .execute(harness.admin_pool())
        .await?;

    sqlx::query("DELETE FROM public._sqlx_migrations WHERE version=$1")
        .bind(version)
        .execute(harness.admin_pool())
        .await?;
    assert!(!store.readiness_check(&[], &[]).await?);
    Ok(())
}
