//! Hermetic migration/preflight coverage for the Route Health HTTP boundary.
//!
//! The shared harness starts either the repository-local PostgreSQL fixture or
//! the pinned testcontainer and runs every forward migration before returning.

#[path = "support/mod.rs"]
mod support;

use std::error::Error;

use sqlx::Executor;
use support::PostgresHarness;

#[tokio::test]
async fn route_health_migration_and_runtime_role_preflight() -> Result<(), Box<dyn Error>> {
    // `PostgresHarness::start` runs the complete forward migration set and
    // provisions the least-privilege runtime role. A failure here is a hard
    // preflight failure rather than a test skip.
    let harness = PostgresHarness::start().await?;
    // Test-only privilege expansion is limited to the two Route Health
    // ledger relations; production grants and tenant RLS remain unchanged.
    sqlx::raw_sql(
        "GRANT SELECT, INSERT ON agent.agent_route_health_receipts TO dtx_runtime_test;
         GRANT SELECT, INSERT, UPDATE ON agent.agent_route_health_heads TO dtx_runtime_test;",
    )
    .execute(harness.admin_pool())
    .await?;
    Ok(())
}

#[tokio::test]
async fn route_health_fixture_establishes_installed_route_and_runtime_visibility()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = support::route_health::RouteHealthFixtureBuilder::new(&harness)
        .establish()
        .await?;

    let mut session = fixture.store.begin_tenant(fixture.tenant_id).await?;
    let installed: (String, Vec<u8>, uuid::Uuid, uuid::Uuid) = sqlx::query_as(
        "SELECT b.state, h.route_fence, b.route_health_key_id, b.connector_id
           FROM agent.agent_route_bootstraps b
           JOIN agent.agent_route_binding_heads h
             ON h.tenant_id=b.tenant_id AND h.bootstrap_id=b.bootstrap_id
          WHERE b.tenant_id=$1 AND b.route_id=$2 AND b.state='installed'",
    )
    .bind(uuid::Uuid::from(fixture.tenant_id))
    .bind(uuid::Uuid::from(fixture.route_id))
    .fetch_one(session.connection())
    .await?;
    assert_eq!(installed.0, "installed");
    assert_eq!(installed.1, fixture.route_fence);
    assert_eq!(installed.2, uuid::Uuid::from(fixture.route_health_key_id));
    assert_eq!(installed.3, uuid::Uuid::from(fixture.connector_id));

    let active_lease: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM agent.connector_leases l
           JOIN agent.connector_control_credentials c
             ON c.tenant_id=l.tenant_id AND c.connector_id=l.connector_id
            AND c.connector_generation=l.generation
          WHERE l.tenant_id=$1 AND l.connector_id=$2 AND l.lease_id=$3
            AND l.generation=$4 AND l.lease_epoch=$5 AND l.status='active'
            AND c.certificate_fingerprint=$6",
    )
    .bind(uuid::Uuid::from(fixture.tenant_id))
    .bind(uuid::Uuid::from(fixture.connector_id))
    .bind(uuid::Uuid::from(fixture.lease_id))
    .bind(i64::try_from(fixture.connector_generation)?)
    .bind(i64::try_from(fixture.lease_epoch)?)
    .bind(
        fixture
            .connector_credential
            .certificate_fingerprint()
            .as_bytes()
            .to_vec(),
    )
    .fetch_one(session.connection())
    .await?;
    assert_eq!(active_lease, 1);

    let current_approval: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM agent.agent_identity_approvals a
           JOIN agent.agent_devices d
             ON d.tenant_id=a.tenant_id AND d.installation_id=a.installation_id
            AND d.agent_device_id=a.agent_device_id
           JOIN identity.log_heads h
             ON h.identity_id=a.agent_identity_id
            AND h.head_sequence=a.identity_head_sequence AND h.head_hash=a.identity_head_hash
          WHERE a.tenant_id=$1 AND a.installation_id=$2 AND a.binding_id=$3
            AND a.agent_device_id=$4 AND d.state='active'",
    )
    .bind(uuid::Uuid::from(fixture.tenant_id))
    .bind(uuid::Uuid::from(fixture.installation_id))
    .bind(uuid::Uuid::from(fixture.binding_id))
    .bind(uuid::Uuid::from(fixture.agent_device_id))
    .fetch_one(session.connection())
    .await?;
    assert_eq!(current_approval, 1);
    session.rollback().await?;
    Ok(())
}
