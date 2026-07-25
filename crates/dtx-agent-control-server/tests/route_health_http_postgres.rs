//! Hermetic migration/preflight coverage for the Route Health HTTP boundary.
//!
//! The shared harness starts either the repository-local PostgreSQL fixture or
//! the pinned testcontainer and runs every forward migration before returning.

#[path = "support/mod.rs"]
mod support;

use std::error::Error;

use dtx_wire::{CanonicalValue, decode_deterministic_cbor, encode_deterministic_cbor};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
        "GRANT SELECT, INSERT, UPDATE ON agent.agent_route_health_receipts TO dtx_runtime_test;
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

async fn route_health_counts(
    fixture: &support::route_health::RouteHealthFixture,
) -> Result<(i64, Option<(i64, i64)>), Box<dyn Error>> {
    let mut session = fixture.store.begin_tenant(fixture.tenant_id).await?;
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.agent_route_health_receipts
          WHERE tenant_id=$1 AND route_id=$2",
    )
    .bind(uuid::Uuid::from(fixture.tenant_id))
    .bind(uuid::Uuid::from(fixture.route_id))
    .fetch_one(session.connection())
    .await?;
    let head: Option<(i64, i64)> = sqlx::query_as(
        "SELECT observation_revision, status_revision
           FROM agent.agent_route_health_heads
          WHERE tenant_id=$1 AND route_id=$2",
    )
    .bind(uuid::Uuid::from(fixture.tenant_id))
    .bind(uuid::Uuid::from(fixture.route_id))
    .fetch_optional(session.connection())
    .await?;
    session.rollback().await?;
    Ok((receipts, head))
}

fn verify_receipt(
    bytes: &[u8],
    receipt_key_id: dtx_domain::RouteHealthKeyId,
    receipt_seed: [u8; 32],
) -> Result<bool, Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("receipt must be a canonical map".into());
    };
    let key_id = fields
        .iter()
        .find_map(|(key, value)| (*key == CanonicalValue::Unsigned(5)).then(|| value))
        .ok_or("receipt key id missing")?;
    assert_eq!(key_id, &CanonicalValue::Text(receipt_key_id.to_string()));
    let signature = fields
        .iter()
        .find_map(|(key, value)| (*key == CanonicalValue::Unsigned(12)).then(|| value))
        .and_then(|value| match value {
            CanonicalValue::Bytes(bytes) => <[u8; 64]>::try_from(bytes.as_slice()).ok(),
            _ => None,
        })
        .ok_or("receipt signature missing")?;
    let signed_fields = fields
        .iter()
        .filter(|(key, _)| *key != CanonicalValue::Unsigned(12))
        .cloned()
        .collect::<Vec<_>>();
    let signed = encode_deterministic_cbor(&CanonicalValue::Map(signed_fields))?;
    let verifying = VerifyingKey::from_bytes(
        &ed25519_dalek::SigningKey::from_bytes(&receipt_seed)
            .verifying_key()
            .to_bytes(),
    )?;
    verifying.verify(
        dtx_wire::Sha256Digest::hash_domain(
            dtx_agent_control_server::ROUTE_HEALTH_RECEIPT_DOMAIN,
            &signed,
        )
        .as_bytes(),
        &Signature::from_bytes(&signature),
    )?;
    Ok(fields
        .iter()
        .find_map(|(key, value)| {
            (*key == CanonicalValue::Unsigned(11)).then(|| value == &CanonicalValue::Bool(true))
        })
        .unwrap_or(false))
}

#[tokio::test]
async fn route_health_http_accepts_replays_and_pins_signed_receipts() -> Result<(), Box<dyn Error>>
{
    let harness = PostgresHarness::start().await?;
    let fixture = support::route_health::RouteHealthFixtureBuilder::new(&harness)
        .establish()
        .await?;
    let receipt_key_id = dtx_domain::RouteHealthKeyId::new();
    let receipt_seed = [0xE1; 32];
    let body = fixture.signed_request_with_nonce(
        dtx_domain::RequestId::new(),
        dtx_domain::Revision::INITIAL,
        [1; 32],
    );
    let first = fixture
        .post_body(body.clone(), receipt_key_id, receipt_seed)
        .await?;
    let first_status = first.status();
    let first_content_type = first
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let first_bytes = axum::body::to_bytes(first.into_body(), 1_000_000)
        .await?
        .to_vec();
    assert_eq!(first_status, axum::http::StatusCode::CREATED);
    assert_eq!(
        first_content_type.as_deref(),
        Some(dtx_agent_control_server::ROUTE_HEALTH_MEDIA_TYPE_V1)
    );
    assert!(verify_receipt(&first_bytes, receipt_key_id, receipt_seed)?);
    let replay = fixture
        .post_body(body, receipt_key_id, receipt_seed)
        .await?;
    assert_eq!(replay.status(), axum::http::StatusCode::OK);
    let replay_bytes = axum::body::to_bytes(replay.into_body(), 1_000_000)
        .await?
        .to_vec();
    assert_eq!(replay_bytes, first_bytes);
    assert_eq!(route_health_counts(&fixture).await?, (1, Some((1, 1))));
    Ok(())
}

async fn post_status(
    fixture: &support::route_health::RouteHealthFixture,
    body: Vec<u8>,
    receipt_key_id: dtx_domain::RouteHealthKeyId,
    receipt_seed: [u8; 32],
) -> Result<(axum::http::StatusCode, Vec<u8>), Box<dyn Error>> {
    let response = fixture
        .post_body(body, receipt_key_id, receipt_seed)
        .await?;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1_000_000)
        .await?
        .to_vec();
    Ok((status, body))
}

#[tokio::test]
async fn route_health_http_rejects_nonce_conflicts_and_preserves_ledger()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = support::route_health::RouteHealthFixtureBuilder::new(&harness)
        .establish()
        .await?;
    let receipt_key_id = dtx_domain::RouteHealthKeyId::new();
    let seed = [0xE2; 32];
    let body = fixture.signed_request_with_nonce(
        dtx_domain::RequestId::new(),
        dtx_domain::Revision::INITIAL,
        [2; 32],
    );
    assert_eq!(
        post_status(&fixture, body.clone(), receipt_key_id, seed)
            .await?
            .0,
        axum::http::StatusCode::CREATED
    );
    let changed = fixture.resign_request(&body, |fields| {
        for (key, value) in fields {
            if *key == support::agent_provisioning::u(16) {
                *value = support::agent_provisioning::u(2);
            }
        }
    });
    assert_eq!(
        post_status(&fixture, changed, receipt_key_id, seed)
            .await?
            .0,
        axum::http::StatusCode::CONFLICT
    );
    assert_eq!(route_health_counts(&fixture).await?, (1, Some((1, 1))));
    Ok(())
}

#[tokio::test]
async fn route_health_http_replays_exact_receipt_after_route_expiry_and_fences_request_id()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = support::route_health::RouteHealthFixtureBuilder::new(&harness)
        .establish()
        .await?;
    let receipt_key_id = dtx_domain::RouteHealthKeyId::new();
    let seed = [0xE4; 32];
    let request_id = dtx_domain::RequestId::new();
    let body =
        fixture.signed_request_with_nonce(request_id, dtx_domain::Revision::INITIAL, [3; 32]);
    let first = post_status(&fixture, body.clone(), receipt_key_id, seed).await?;
    assert_eq!(first.0, axum::http::StatusCode::CREATED);
    assert_eq!(route_health_counts(&fixture).await?, (1, Some((1, 1))));

    // Mutable route/bootstrap expiry cannot invalidate an already committed
    // authenticated receipt replay.
    sqlx::query(
        "UPDATE agent.agent_route_binding_heads SET expires_at_ms=installed_at_ms + 1
          WHERE tenant_id=$1 AND route_id=$2",
    )
    .bind(uuid::Uuid::from(fixture.tenant_id))
    .bind(uuid::Uuid::from(fixture.route_id))
    .execute(harness.admin_pool())
    .await?;
    sqlx::query(
        "UPDATE agent.agent_route_bootstraps SET expires_at_ms=created_at_ms + 1
          WHERE tenant_id=$1 AND route_id=$2",
    )
    .bind(uuid::Uuid::from(fixture.tenant_id))
    .bind(uuid::Uuid::from(fixture.route_id))
    .execute(harness.admin_pool())
    .await?;
    let replay = post_status(&fixture, body.clone(), receipt_key_id, seed).await?;
    assert_eq!(replay.0, axum::http::StatusCode::OK);
    assert_eq!(replay.1, first.1);
    assert_eq!(route_health_counts(&fixture).await?, (1, Some((1, 1))));

    // A request id is a global idempotency fence: changing nonce/body cannot
    // create another receipt, even if the current route is no longer active.
    let changed = fixture.resign_request(&body, |fields| {
        for (key, value) in fields {
            if *key == support::agent_provisioning::u(22) {
                *value = support::agent_provisioning::bytes(&[4; 32]);
            }
        }
    });
    assert_eq!(
        post_status(&fixture, changed, receipt_key_id, seed)
            .await?
            .0,
        axum::http::StatusCode::CONFLICT
    );
    assert_eq!(route_health_counts(&fixture).await?, (1, Some((1, 1))));
    Ok(())
}

#[tokio::test]
async fn route_health_http_rejects_bootstrap_id_mismatch_without_mutation()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = support::route_health::RouteHealthFixtureBuilder::new(&harness)
        .establish()
        .await?;
    let body = fixture.signed_request_with_nonce(
        dtx_domain::RequestId::new(),
        dtx_domain::Revision::INITIAL,
        [5; 32],
    );
    let mismatched = fixture.resign_request(&body, |fields| {
        for (key, value) in fields {
            if *key == support::agent_provisioning::u(8) {
                *value =
                    support::agent_provisioning::text(dtx_domain::AgentRouteBootstrapId::new());
            }
        }
    });
    assert_eq!(
        post_status(
            &fixture,
            mismatched,
            dtx_domain::RouteHealthKeyId::new(),
            [0xE5; 32]
        )
        .await?
        .0,
        axum::http::StatusCode::CONFLICT
    );
    assert_eq!(route_health_counts(&fixture).await?, (0, None));
    Ok(())
}

#[tokio::test]
async fn route_health_http_concurrent_exact_requests_allocate_one_observation()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = support::route_health::RouteHealthFixtureBuilder::new(&harness)
        .establish()
        .await?;
    let receipt_key_id = dtx_domain::RouteHealthKeyId::new();
    let seed = [0xE3; 32];
    let body = fixture.signed_request_with_nonce(
        dtx_domain::RequestId::new(),
        dtx_domain::Revision::INITIAL,
        [3; 32],
    );
    let (left, right) = tokio::join!(
        post_status(&fixture, body.clone(), receipt_key_id, seed),
        post_status(&fixture, body, receipt_key_id, seed)
    );
    let left = left?;
    let right = right?;
    assert!(matches!(
        (left.0, right.0),
        (axum::http::StatusCode::CREATED, axum::http::StatusCode::OK)
            | (axum::http::StatusCode::OK, axum::http::StatusCode::CREATED)
    ));
    assert_eq!(left.1, right.1);
    assert_eq!(route_health_counts(&fixture).await?, (1, Some((1, 1))));
    Ok(())
}

#[tokio::test]
async fn route_health_http_enforces_strict_status_monotonicity() -> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = support::route_health::RouteHealthFixtureBuilder::new(&harness)
        .establish()
        .await?;
    let receipt_key_id = dtx_domain::RouteHealthKeyId::new();
    let seed = [0xE4; 32];
    let first = fixture.signed_request_with_nonce(
        dtx_domain::RequestId::new(),
        dtx_domain::Revision::INITIAL,
        [4; 32],
    );
    assert_eq!(
        post_status(&fixture, first, receipt_key_id, seed).await?.0,
        axum::http::StatusCode::CREATED
    );
    let stale = fixture.signed_request_with_nonce(
        dtx_domain::RequestId::new(),
        dtx_domain::Revision::INITIAL,
        [5; 32],
    );
    assert_eq!(
        post_status(&fixture, stale, receipt_key_id, seed).await?.0,
        axum::http::StatusCode::CONFLICT
    );
    let next = fixture.signed_request_with_nonce(
        dtx_domain::RequestId::new(),
        dtx_domain::Revision::new(2)?,
        [6; 32],
    );
    assert_eq!(
        post_status(&fixture, next, receipt_key_id, seed).await?.0,
        axum::http::StatusCode::CREATED
    );
    assert_eq!(route_health_counts(&fixture).await?, (2, Some((2, 2))));
    Ok(())
}

#[tokio::test]
async fn route_health_http_fences_stale_route_and_connector_facts() -> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = support::route_health::RouteHealthFixtureBuilder::new(&harness)
        .establish()
        .await?;
    let receipt_key_id = dtx_domain::RouteHealthKeyId::new();
    let seed = [0xE5; 32];
    let cases = vec![
        ([10; 32], 11_u64, support::agent_provisioning::u(999)),
        ([11; 32], 13_u64, support::agent_provisioning::u(999)),
        (
            [12; 32],
            14_u64,
            support::agent_provisioning::bytes(&[0xFA; 32]),
        ),
        (
            [13; 32],
            15_u64,
            support::agent_provisioning::text(dtx_domain::RouteHealthKeyId::new()),
        ),
    ];
    for (nonce, key, value) in cases {
        let body = fixture.signed_request_with_nonce(
            dtx_domain::RequestId::new(),
            dtx_domain::Revision::INITIAL,
            nonce,
        );
        let changed = fixture.resign_request(&body, |fields| {
            for (field, current) in fields {
                if *field == support::agent_provisioning::u(key) {
                    *current = value.clone();
                }
            }
        });
        assert_eq!(
            post_status(&fixture, changed, receipt_key_id, seed)
                .await?
                .0,
            axum::http::StatusCode::CONFLICT
        );
        assert_eq!(route_health_counts(&fixture).await?, (0, None));
    }
    Ok(())
}

#[tokio::test]
async fn route_health_http_marks_stale_agent_approval_without_rejecting_connector()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = support::route_health::RouteHealthFixtureBuilder::new(&harness)
        .establish()
        .await?;
    support::agent_provisioning::revoke_agent_device(
        &fixture.store,
        fixture.tenant_id,
        fixture.installation_id,
        fixture.agent_device_id,
    )
    .await?;
    let receipt_key_id = dtx_domain::RouteHealthKeyId::new();
    let seed = [0xE6; 32];
    let body = fixture.signed_request_with_nonce(
        dtx_domain::RequestId::new(),
        dtx_domain::Revision::INITIAL,
        [20; 32],
    );
    let response = post_status(&fixture, body, receipt_key_id, seed).await?;
    assert_eq!(response.0, axum::http::StatusCode::CREATED);
    assert!(!verify_receipt(&response.1, receipt_key_id, seed)?);
    assert_eq!(route_health_counts(&fixture).await?, (1, Some((1, 1))));
    Ok(())
}

#[tokio::test]
async fn route_health_http_rejects_authenticated_peer_for_another_connector()
-> Result<(), Box<dyn Error>> {
    let harness_a = PostgresHarness::start().await?;
    let fixture_a = support::route_health::RouteHealthFixtureBuilder::new(&harness_a)
        .establish()
        .await?;
    let harness_b = PostgresHarness::start().await?;
    let fixture_b = support::route_health::RouteHealthFixtureBuilder::new(&harness_b)
        .establish()
        .await?;
    let body = fixture_b.signed_request_with_nonce(
        dtx_domain::RequestId::new(),
        dtx_domain::Revision::INITIAL,
        [23; 32],
    );
    let response = fixture_b
        .post_body_as_peer(
            body,
            dtx_domain::RouteHealthKeyId::new(),
            [0xE9; 32],
            fixture_a.peer,
        )
        .await?;
    assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
    assert_eq!(route_health_counts(&fixture_b).await?, (0, None));
    Ok(())
}

#[tokio::test]
async fn route_health_http_rejects_retired_route_and_cross_tenant_request_without_mutation()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = support::route_health::RouteHealthFixtureBuilder::new(&harness)
        .establish()
        .await?;
    let body = fixture.signed_request_with_nonce(
        dtx_domain::RequestId::new(),
        dtx_domain::Revision::INITIAL,
        [21; 32],
    );
    let foreign_tenant = dtx_domain::TenantId::new();
    let isolated = fixture.resign_request(&body, |fields| {
        for (key, value) in fields {
            if *key == support::agent_provisioning::u(3) {
                *value = support::agent_provisioning::text(foreign_tenant);
            }
        }
    });
    assert_eq!(
        post_status(
            &fixture,
            isolated,
            dtx_domain::RouteHealthKeyId::new(),
            [0xE7; 32]
        )
        .await?
        .0,
        axum::http::StatusCode::NOT_FOUND
    );
    assert_eq!(route_health_counts(&fixture).await?, (0, None));

    let mut admin_tx = harness.admin_pool().begin().await?;
    sqlx::query("DELETE FROM agent.agent_route_binding_heads WHERE tenant_id=$1 AND route_id=$2")
        .bind(uuid::Uuid::from(fixture.tenant_id))
        .bind(uuid::Uuid::from(fixture.route_id))
        .execute(&mut *admin_tx)
        .await?;
    sqlx::query("DELETE FROM agent.agent_route_bootstraps WHERE tenant_id=$1 AND route_id=$2")
        .bind(uuid::Uuid::from(fixture.tenant_id))
        .bind(uuid::Uuid::from(fixture.route_id))
        .execute(&mut *admin_tx)
        .await?;
    admin_tx.commit().await?;
    let retired = fixture.signed_request_with_nonce(
        dtx_domain::RequestId::new(),
        dtx_domain::Revision::INITIAL,
        [22; 32],
    );
    assert_eq!(
        post_status(
            &fixture,
            retired,
            dtx_domain::RouteHealthKeyId::new(),
            [0xE8; 32]
        )
        .await?
        .0,
        axum::http::StatusCode::NOT_FOUND
    );
    assert_eq!(route_health_counts(&fixture).await?, (0, None));
    Ok(())
}
