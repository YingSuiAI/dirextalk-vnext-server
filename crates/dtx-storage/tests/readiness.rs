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
