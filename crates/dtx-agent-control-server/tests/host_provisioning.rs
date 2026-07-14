#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{
    error::Error,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use dtx_agent_control::{EnrollmentToken, Sha256Digest};
use dtx_agent_control_server::{
    HostProvisioningConnectorRequest, HostProvisioningError, HostProvisioningRequest,
    ensure_host_provisioning,
};
use dtx_connect_registry::AdapterKind;
use dtx_domain::{
    ConnectorId, EnrollmentIntentId, HostCredentialId, HostId, IdentityId, RequestId, TenantId,
};
use support::PostgresHarness;
use uuid::Uuid;

const NOW_MILLIS: i64 = 1_800_000_000_000;
const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

#[tokio::test]
async fn host_provisioning_is_atomic_sorted_and_exactly_replayable() -> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(2).await?;
    let ids = FixtureIds::new()?;

    let first = ensure_host_provisioning(&store, request(&ids, [0x11; 32], false)?).await?;
    assert!(first.changed);
    assert_eq!(first.connectors.len(), 2);
    assert!(first.connectors[0].connector_id < first.connectors[1].connector_id);
    assert_eq!(durable_counts(&harness, ids.tenant_id).await?, (1, 2, 2, 3));

    let replay = ensure_host_provisioning(&store, request(&ids, [0x11; 32], false)?).await?;
    assert!(!replay.changed);
    assert_eq!(replay.connectors, first.connectors);

    assert!(
        ensure_host_provisioning(&store, request(&ids, [0x22; 32], false)?)
            .await
            .is_err()
    );
    assert_eq!(durable_counts(&harness, ids.tenant_id).await?, (1, 2, 2, 3));

    let failed_host = HostId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f020")?;
    assert!(
        ensure_host_provisioning(&store, request(&ids, [0x33; 32], true)?)
            .await
            .is_err()
    );
    let failed_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM agent.hosts WHERE tenant_id=$1 AND host_id=$2")
            .bind(Uuid::from(ids.tenant_id))
            .bind(Uuid::from(failed_host))
            .fetch_one(harness.admin_pool())
            .await?;
    assert_eq!(
        failed_rows, 0,
        "outer transaction must roll back partial Host state"
    );
    Ok(())
}

#[tokio::test]
async fn host_provisioning_rolls_back_when_intents_expire_before_commit()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(2).await?;
    let ids = FixtureIds::new()?;
    let expired_created_at = current_millis()? - 300_001;

    let error = ensure_host_provisioning(
        &store,
        request_at(&ids, [0x44; 32], false, expired_created_at)?,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, HostProvisioningError::Expired));
    assert_eq!(durable_counts(&harness, ids.tenant_id).await?, (0, 0, 0, 0));
    Ok(())
}

struct FixtureIds {
    tenant_id: TenantId,
    operation_id: RequestId,
    host_id: HostId,
    host_credential_id: HostCredentialId,
    connector_ids: [ConnectorId; 2],
    request_ids: [RequestId; 2],
    intent_ids: [EnrollmentIntentId; 2],
}

impl FixtureIds {
    fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            tenant_id: TenantId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f002")?,
            operation_id: RequestId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f001")?,
            host_id: HostId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f003")?,
            host_credential_id: HostCredentialId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f007")?,
            connector_ids: [
                ConnectorId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f004")?,
                ConnectorId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f008")?,
            ],
            request_ids: [
                RequestId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f005")?,
                RequestId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f009")?,
            ],
            intent_ids: [
                EnrollmentIntentId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f006")?,
                EnrollmentIntentId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f00a")?,
            ],
        })
    }
}

fn request(
    ids: &FixtureIds,
    plan_digest: [u8; 32],
    fail_after_first_connector: bool,
) -> Result<HostProvisioningRequest, Box<dyn Error>> {
    request_at(ids, plan_digest, fail_after_first_connector, NOW_MILLIS)
}

fn request_at(
    ids: &FixtureIds,
    plan_digest: [u8; 32],
    fail_after_first_connector: bool,
    created_at_millis: i64,
) -> Result<HostProvisioningRequest, Box<dyn Error>> {
    let (operation_id, host_id, host_credential_id, connector_ids, request_ids, intent_ids) =
        if fail_after_first_connector {
            (
                RequestId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f021")?,
                HostId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f020")?,
                HostCredentialId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f022")?,
                [
                    ConnectorId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f023")?,
                    ConnectorId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f024")?,
                ],
                [
                    RequestId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f025")?,
                    ids.request_ids[0],
                ],
                [
                    EnrollmentIntentId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f026")?,
                    EnrollmentIntentId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f027")?,
                ],
            )
        } else {
            (
                ids.operation_id,
                ids.host_id,
                ids.host_credential_id,
                ids.connector_ids,
                ids.request_ids,
                ids.intent_ids,
            )
        };
    let connectors = vec![
        HostProvisioningConnectorRequest::new(
            connector_ids[1],
            AdapterKind::OpenClawAcp,
            request_ids[1],
            intent_ids[1],
            2,
            300_000,
            EnrollmentToken::from_bytes([0x42; 32]),
        )?,
        HostProvisioningConnectorRequest::new(
            connector_ids[0],
            AdapterKind::Codex,
            request_ids[0],
            intent_ids[0],
            1,
            300_000,
            EnrollmentToken::from_bytes([0x24; 32]),
        )?,
    ];
    Ok(HostProvisioningRequest::new(
        operation_id,
        ids.tenant_id,
        host_id,
        IdentityId::from_str(OWNER_ID)?,
        host_credential_id,
        Sha256Digest::from_bytes(plan_digest),
        created_at_millis,
        connectors,
    )?)
}

fn current_millis() -> Result<i64, Box<dyn Error>> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

async fn durable_counts(
    harness: &PostgresHarness,
    tenant_id: TenantId,
) -> Result<(i64, i64, i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM agent.hosts WHERE tenant_id=$1),
             (SELECT count(*) FROM agent.connector_instances WHERE tenant_id=$1),
             (SELECT count(*) FROM agent.connector_enrollment_intents WHERE tenant_id=$1),
             ((SELECT count(*) FROM agent.host_provisioning_operations WHERE tenant_id=$1)
                + (SELECT count(*) FROM agent.connector_control_operations WHERE tenant_id=$1))",
    )
    .bind(Uuid::from(tenant_id))
    .fetch_one(harness.admin_pool())
    .await
}
