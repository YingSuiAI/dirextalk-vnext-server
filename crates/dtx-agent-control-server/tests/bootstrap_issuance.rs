#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, str::FromStr};

use dtx_agent_control::{EnrollmentToken, Sha256Digest};
use dtx_agent_control_server::{
    ConnectorBootstrapIssuance, HostProvisioningConnectorRequest, HostProvisioningRequest,
    ensure_connector_bootstrap_issuance, ensure_host_provisioning,
};
use dtx_connect_registry::AdapterKind;
use dtx_domain::{
    ConnectorId, EnrollmentIntentId, HostCredentialId, HostId, IdentityId, RequestId, Revision,
    TenantId,
};
use support::PostgresHarness;
use uuid::Uuid;

const CREATED_AT_MILLIS: i64 = 1_800_000_000_000;
const EXPIRES_AT_MILLIS: i64 = CREATED_AT_MILLIS + 600_000;
const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

#[tokio::test]
async fn bootstrap_issuance_is_atomic_exact_append_only_and_fenced() -> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(2).await?;
    let first_ids = FixtureIds::new(0x100)?;

    let first = ensure_connector_bootstrap_issuance(
        &store,
        provisioning(&first_ids)?,
        issuance(&first_ids, None),
    )
    .await?;
    assert!(first.changed);
    let replay = ensure_connector_bootstrap_issuance(
        &store,
        provisioning(&first_ids)?,
        issuance(&first_ids, None),
    )
    .await?;
    assert!(!replay.changed);

    assert!(
        ensure_connector_bootstrap_issuance(
            &store,
            provisioning(&first_ids)?,
            issuance(&first_ids, Some("/root/alternate.plan.json")),
        )
        .await
        .is_err(),
        "a changed canonical plan path must fail exact replay"
    );
    assert_eq!(issuance_count(&harness, first_ids.tenant_id).await?, 1);

    let stored_json: String = sqlx::query_scalar(
        "SELECT request_json::text || plan_json::text
           FROM agent.connector_bootstrap_issuances
          WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(Uuid::from(first_ids.tenant_id))
    .bind(Uuid::from(first_ids.operation_id))
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!stored_json.contains("enrollment_token"));
    assert!(!stored_json.contains("mcp_bearer"));
    assert!(!stored_json.contains("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"));

    for statement in [
        "UPDATE agent.connector_bootstrap_issuances SET state='ready' WHERE tenant_id=$1 AND operation_id=$2",
        "DELETE FROM agent.connector_bootstrap_issuances WHERE tenant_id=$1 AND operation_id=$2",
    ] {
        let error = sqlx::query(statement)
            .bind(Uuid::from(first_ids.tenant_id))
            .bind(Uuid::from(first_ids.operation_id))
            .execute(harness.admin_pool())
            .await
            .expect_err("issuance rows are append-only");
        assert_eq!(sqlstate(&error).as_deref(), Some("55000"));
    }

    let rollback_ids = FixtureIds::new(0x200)?;
    let mut conflicting = issuance(&rollback_ids, None);
    conflicting.connector_id = ConnectorId::from_str("0197f1f0-0000-7000-8000-0000000002ff")?;
    assert!(
        ensure_connector_bootstrap_issuance(&store, provisioning(&rollback_ids)?, conflicting,)
            .await
            .is_err()
    );
    let rolled_back: (i64, i64, i64) = sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM agent.hosts WHERE tenant_id=$1 AND host_id=$2),
             (SELECT count(*) FROM agent.connector_instances WHERE tenant_id=$1 AND connector_id=$3),
             (SELECT count(*) FROM agent.connector_bootstrap_issuances WHERE tenant_id=$1 AND operation_id=$4)",
    )
    .bind(Uuid::from(rollback_ids.tenant_id))
    .bind(Uuid::from(rollback_ids.host_id))
    .bind(Uuid::from(rollback_ids.connector_id))
    .bind(Uuid::from(rollback_ids.operation_id))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(rolled_back, (0, 0, 0));

    let fence_ids = FixtureIds::new(0x300)?;
    ensure_host_provisioning(&store, provisioning(&fence_ids)?).await?;
    let mut transaction = harness.admin_pool().begin().await?;
    sqlx::query(
        "INSERT INTO agent.connector_bootstrap_issuances (
             tenant_id, operation_id, connector_id, host_id,
             enrollment_request_id, enrollment_intent_id,
             connector_generation, spec_revision, request_digest, plan_digest,
             handoff_digest, enrollment_token_digest, mcp_bearer_digest,
             handoff_path, plan_path, request_json, plan_json, state,
             expires_at_ms, created_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,1,1,$7,$8,$9,$10,$11,$12,$13,$14,$15,'ready',$16,$17)",
    )
    .bind(Uuid::from(fence_ids.tenant_id))
    .bind(Uuid::from(fence_ids.operation_id))
    .bind(Uuid::from(fence_ids.connector_id))
    .bind(Uuid::from(fence_ids.host_id))
    .bind(Uuid::from(fence_ids.enrollment_request_id))
    .bind(Uuid::from(fence_ids.enrollment_intent_id))
    .bind(vec![0x11_u8; 32])
    .bind(vec![0x22_u8; 32])
    .bind(vec![0x33_u8; 32])
    .bind(vec![0x99_u8; 32])
    .bind(vec![0x55_u8; 32])
    .bind(fence_ids.handoff_path())
    .bind(fence_ids.plan_path())
    .bind(serde_json::json!({"schema":"request"}))
    .bind(serde_json::json!({"schema":"plan"}))
    .bind(EXPIRES_AT_MILLIS)
    .bind(CREATED_AT_MILLIS)
    .execute(&mut *transaction)
    .await?;
    let error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .expect_err("wrong token digest must fail the deferred enrollment fence");
    assert_eq!(sqlstate(&error).as_deref(), Some("23514"));
    transaction.rollback().await?;
    assert_eq!(issuance_count(&harness, fence_ids.tenant_id).await?, 1);

    sqlx::query(
        "ALTER TABLE agent.connector_bootstrap_issuances
         DISABLE TRIGGER connector_bootstrap_issuances_fence",
    )
    .execute(harness.admin_pool())
    .await?;
    let missing_ids = FixtureIds::new(0x400)?;
    let mut transaction = harness.admin_pool().begin().await?;
    sqlx::query(
        "INSERT INTO agent.connector_bootstrap_issuances
         SELECT tenant_id, $2, connector_id, host_id, $3, $4,
                connector_generation, spec_revision, request_digest, plan_digest,
                handoff_digest, enrollment_token_digest, mcp_bearer_digest,
                $5, $6, request_json, plan_json, state, expires_at_ms, created_at_ms
           FROM agent.connector_bootstrap_issuances
          WHERE tenant_id=$1 AND operation_id=$7",
    )
    .bind(Uuid::from(first_ids.tenant_id))
    .bind(Uuid::from(missing_ids.operation_id))
    .bind(Uuid::from(missing_ids.enrollment_request_id))
    .bind(Uuid::from(missing_ids.enrollment_intent_id))
    .bind(missing_ids.handoff_path())
    .bind(missing_ids.plan_path())
    .bind(Uuid::from(first_ids.operation_id))
    .execute(&mut *transaction)
    .await?;
    let error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .expect_err("missing enrollment intent must fail both durable foreign keys");
    assert_eq!(sqlstate(&error).as_deref(), Some("23503"));
    transaction.rollback().await?;
    sqlx::query(
        "ALTER TABLE agent.connector_bootstrap_issuances
         ENABLE TRIGGER connector_bootstrap_issuances_fence",
    )
    .execute(harness.admin_pool())
    .await?;
    assert_eq!(issuance_count(&harness, first_ids.tenant_id).await?, 1);
    Ok(())
}

struct FixtureIds {
    tenant_id: TenantId,
    operation_id: RequestId,
    host_id: HostId,
    host_credential_id: HostCredentialId,
    connector_id: ConnectorId,
    enrollment_request_id: RequestId,
    enrollment_intent_id: EnrollmentIntentId,
    token_byte: u8,
}

impl FixtureIds {
    fn new(base: u64) -> Result<Self, Box<dyn Error>> {
        let id = |offset: u64| format!("0197f1f0-0000-7000-8000-{:012x}", base + offset);
        Ok(Self {
            tenant_id: TenantId::from_str("0197f1f0-0000-7000-8000-000000000001")?,
            operation_id: RequestId::from_str(&id(1))?,
            host_id: HostId::from_str(&id(2))?,
            host_credential_id: HostCredentialId::from_str(&id(3))?,
            connector_id: ConnectorId::from_str(&id(4))?,
            enrollment_request_id: RequestId::from_str(&id(5))?,
            enrollment_intent_id: EnrollmentIntentId::from_str(&id(6))?,
            token_byte: u8::try_from(base / 0x100)?,
        })
    }

    fn handoff_path(&self) -> String {
        format!(
            "/root/bootstrap/{}-{}.handoff.json",
            self.tenant_id, self.operation_id
        )
    }

    fn plan_path(&self) -> String {
        format!(
            "/root/bootstrap/{}-{}.plan.json",
            self.tenant_id, self.operation_id
        )
    }
}

fn provisioning(ids: &FixtureIds) -> Result<HostProvisioningRequest, Box<dyn Error>> {
    Ok(HostProvisioningRequest::new(
        ids.operation_id,
        ids.tenant_id,
        ids.host_id,
        IdentityId::from_str(OWNER_ID)?,
        ids.host_credential_id,
        Sha256Digest::from_bytes([0x11; 32]),
        CREATED_AT_MILLIS,
        vec![HostProvisioningConnectorRequest::new(
            ids.connector_id,
            AdapterKind::Codex,
            ids.enrollment_request_id,
            ids.enrollment_intent_id,
            1,
            600_000,
            EnrollmentToken::from_bytes([ids.token_byte; 32]),
        )?],
    )?)
}

fn issuance(ids: &FixtureIds, plan_path: Option<&str>) -> ConnectorBootstrapIssuance {
    ConnectorBootstrapIssuance {
        operation_id: ids.operation_id,
        tenant_id: ids.tenant_id,
        connector_id: ids.connector_id,
        host_id: ids.host_id,
        enrollment_request_id: ids.enrollment_request_id,
        enrollment_intent_id: ids.enrollment_intent_id,
        connector_generation: 1,
        spec_revision: Revision::INITIAL,
        request_digest: Sha256Digest::from_bytes([0x11; 32]),
        plan_digest: Sha256Digest::from_bytes([0x22; 32]),
        handoff_digest: Sha256Digest::from_bytes([0x33; 32]),
        enrollment_token_digest: EnrollmentToken::from_bytes([ids.token_byte; 32]).digest(),
        mcp_bearer_digest: Sha256Digest::from_bytes([0x55; 32]),
        handoff_path: ids.handoff_path(),
        plan_path: plan_path.map_or_else(|| ids.plan_path(), str::to_owned),
        request_json: serde_json::json!({"schema":"request"}),
        plan_json: serde_json::json!({"schema":"plan"}),
        expires_at_millis: EXPIRES_AT_MILLIS,
        created_at_millis: CREATED_AT_MILLIS,
    }
}

async fn issuance_count(
    harness: &PostgresHarness,
    tenant_id: TenantId,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM agent.connector_bootstrap_issuances WHERE tenant_id=$1",
    )
    .bind(Uuid::from(tenant_id))
    .fetch_one(harness.admin_pool())
    .await
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()?
        .code()
        .map(|code| code.into_owned())
}
