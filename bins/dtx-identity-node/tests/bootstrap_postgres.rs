#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use dtx_domain::{Clock, ClockError, IdentityId};
use dtx_identity_log::{
    IdentityLogEventPayloadV1, IdentityLogEventV1, UnsignedIdentityLogEventV1,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_node::{
    IDENTITY_APPEND_RECEIPT_CONTENT_TYPE, IDENTITY_BOOTSTRAP_PATH, IDENTITY_LOG_EVENT_CONTENT_TYPE,
    IdentityBootstrapState, identity_bootstrap_router_with_state,
};
use dtx_identity_persistence::IdentityPgStore;
use dtx_wire::{Ed25519Signature, SafeUint, SigningPublicKey, UtcMillis};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::PgPool;
use tower::ServiceExt;

const IDEMPOTENCY_KEY: &str = "bootstrap-key-0001";

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end bootstrap boundary test keeps its replay and non-mutation assertions coherent"
)]
async fn bootstrap_http_is_self_authenticated_exactly_replayable_and_non_mutating_on_rejection()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let app = identity_bootstrap_router_with_state(IdentityBootstrapState::with_clock(
        store,
        Arc::new(FixedClock(2_000)),
    ));

    let root = signing_key(1);
    let event = genesis(&root, &signing_key(2), 1_000)?;
    let exact_event_bytes = event.to_deterministic_cbor()?;
    let identity_id = event.identity_id();

    let first = send_bootstrap(app.clone(), IDEMPOTENCY_KEY, exact_event_bytes.clone()).await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(
        first
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(IDENTITY_APPEND_RECEIPT_CONTENT_TYPE)
    );
    let first_receipt = to_bytes(first.into_body(), 16_384).await?.to_vec();
    assert!(!first_receipt.is_empty());
    assert_identity_counts(harness.identity_runtime_pool(), identity_id, 1, 1, 1).await?;
    assert_bootstrap_claim_count(harness.identity_runtime_pool(), 1).await?;

    let replay = send_bootstrap(app.clone(), IDEMPOTENCY_KEY, exact_event_bytes.clone()).await?;
    assert_eq!(replay.status(), StatusCode::OK);
    let replay_receipt = to_bytes(replay.into_body(), 16_384).await?.to_vec();
    assert_eq!(replay_receipt, first_receipt);
    assert_identity_counts(harness.identity_runtime_pool(), identity_id, 1, 1, 1).await?;
    assert_bootstrap_claim_count(harness.identity_runtime_pool(), 1).await?;

    let alternate_genesis = genesis(&root, &signing_key(3), 1_001)?.to_deterministic_cbor()?;
    let key_conflict = send_bootstrap(app.clone(), IDEMPOTENCY_KEY, alternate_genesis).await?;
    assert_eq!(key_conflict.status(), StatusCode::CONFLICT);
    assert_rejection_has_no_secret_echo(key_conflict, IDEMPOTENCY_KEY, "IDEMPOTENCY_CONFLICT")
        .await?;
    assert_identity_counts(harness.identity_runtime_pool(), identity_id, 1, 1, 1).await?;
    assert_bootstrap_claim_count(harness.identity_runtime_pool(), 1).await?;

    let different_identity =
        genesis(&signing_key(4), &signing_key(5), 1_001)?.to_deterministic_cbor()?;
    let cross_identity_conflict =
        send_bootstrap(app.clone(), IDEMPOTENCY_KEY, different_identity).await?;
    assert_eq!(cross_identity_conflict.status(), StatusCode::CONFLICT);
    assert_rejection_has_no_secret_echo(
        cross_identity_conflict,
        IDEMPOTENCY_KEY,
        "IDEMPOTENCY_CONFLICT",
    )
    .await?;
    assert_identity_counts(harness.identity_runtime_pool(), identity_id, 1, 1, 1).await?;
    assert_total_identities(harness.identity_runtime_pool(), 1).await?;
    assert_bootstrap_claim_count(harness.identity_runtime_pool(), 1).await?;

    let invalid = send_bootstrap(app.clone(), "bootstrap-key-0002", vec![0xff, 0x00, 0x01]).await?;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_rejection_has_no_secret_echo(
        invalid,
        "bootstrap-key-0002",
        "IDENTITY_BOOTSTRAP_INVALID",
    )
    .await?;
    assert_identity_counts(harness.identity_runtime_pool(), identity_id, 1, 1, 1).await?;
    assert_bootstrap_claim_count(harness.identity_runtime_pool(), 1).await?;

    let wrong_media_type = Request::builder()
        .method("POST")
        .uri(IDENTITY_BOOTSTRAP_PATH)
        .header(header::CONTENT_TYPE, "application/cbor")
        .header("idempotency-key", "bootstrap-key-0003")
        .body(Body::from(exact_event_bytes.clone()))?;
    let wrong_media_type = app.clone().oneshot(wrong_media_type).await?;
    assert_eq!(wrong_media_type.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_rejection_has_no_secret_echo(
        wrong_media_type,
        "bootstrap-key-0003",
        "IDENTITY_BOOTSTRAP_INVALID",
    )
    .await?;
    assert_identity_counts(harness.identity_runtime_pool(), identity_id, 1, 1, 1).await?;
    assert_bootstrap_claim_count(harness.identity_runtime_pool(), 1).await?;

    let forbidden_precondition = Request::builder()
        .method("POST")
        .uri(IDENTITY_BOOTSTRAP_PATH)
        .header(header::CONTENT_TYPE, IDENTITY_LOG_EVENT_CONTENT_TYPE)
        .header(header::IF_MATCH, "\"not-a-bootstrap-precondition\"")
        .header("idempotency-key", "bootstrap-key-0005")
        .body(Body::from(exact_event_bytes.clone()))?;
    let forbidden_precondition = app.clone().oneshot(forbidden_precondition).await?;
    assert_eq!(
        forbidden_precondition.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_rejection_has_no_secret_echo(
        forbidden_precondition,
        "bootstrap-key-0005",
        "IDENTITY_BOOTSTRAP_INVALID",
    )
    .await?;
    assert_identity_counts(harness.identity_runtime_pool(), identity_id, 1, 1, 1).await?;
    assert_bootstrap_claim_count(harness.identity_runtime_pool(), 1).await?;

    let mut tampered_event = exact_event_bytes.clone();
    let signature_byte = tampered_event
        .last_mut()
        .ok_or("test genesis cannot be empty")?;
    *signature_byte ^= 0x01;
    let tampered = send_bootstrap(app.clone(), "bootstrap-key-0004", tampered_event).await?;
    assert_eq!(tampered.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_rejection_has_no_secret_echo(
        tampered,
        "bootstrap-key-0004",
        "IDENTITY_BOOTSTRAP_INVALID",
    )
    .await?;
    assert_identity_counts(harness.identity_runtime_pool(), identity_id, 1, 1, 1).await?;

    let missing_key = Request::builder()
        .method("POST")
        .uri(IDENTITY_BOOTSTRAP_PATH)
        .header(header::CONTENT_TYPE, IDENTITY_LOG_EVENT_CONTENT_TYPE)
        .body(Body::from(exact_event_bytes))?;
    let missing_key = app.oneshot(missing_key).await?;
    assert_eq!(missing_key.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_identity_counts(harness.identity_runtime_pool(), identity_id, 1, 1, 1).await?;
    assert_bootstrap_claim_count(harness.identity_runtime_pool(), 1).await?;
    Ok(())
}

async fn send_bootstrap(
    app: axum::Router,
    idempotency_key: &str,
    exact_event_bytes: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let request = Request::builder()
        .method("POST")
        .uri(IDENTITY_BOOTSTRAP_PATH)
        .header(header::CONTENT_TYPE, IDENTITY_LOG_EVENT_CONTENT_TYPE)
        .header("idempotency-key", idempotency_key)
        .body(Body::from(exact_event_bytes))?;
    app.oneshot(request).await.map_err(Into::into)
}

async fn assert_rejection_has_no_secret_echo(
    response: axum::response::Response,
    idempotency_key: &str,
    expected_code: &str,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .ok_or("rejection response is missing X-Request-Id")?;
    assert_eq!(uuid::Uuid::parse_str(request_id)?.get_version_num(), 7);
    let body = to_bytes(response.into_body(), 16_384).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert!(!body.contains(idempotency_key));
    let body: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_str),
        Some(expected_code)
    );
    assert_eq!(
        body.pointer("/error/retryable")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    Ok(())
}

async fn assert_identity_counts(
    pool: &PgPool,
    identity_id: IdentityId,
    entries: i64,
    outbox: i64,
    receipts: i64,
) -> Result<(), Box<dyn Error>> {
    let actual_entries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.log_entries WHERE identity_id=$1")
            .bind(identity_id.to_string())
            .fetch_one(pool)
            .await?;
    let actual_outbox: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.log_outbox WHERE identity_id=$1")
            .bind(identity_id.to_string())
            .fetch_one(pool)
            .await?;
    let actual_receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.command_receipts WHERE identity_id=$1")
            .bind(identity_id.to_string())
            .fetch_one(pool)
            .await?;
    assert_eq!(
        (actual_entries, actual_outbox, actual_receipts),
        (entries, outbox, receipts)
    );
    Ok(())
}

async fn assert_total_identities(pool: &PgPool, expected: i64) -> Result<(), Box<dyn Error>> {
    let actual: i64 = sqlx::query_scalar("SELECT count(*) FROM identity.log_heads")
        .fetch_one(pool)
        .await?;
    assert_eq!(actual, expected);
    Ok(())
}

async fn assert_bootstrap_claim_count(pool: &PgPool, expected: i64) -> Result<(), Box<dyn Error>> {
    let actual: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.bootstrap_idempotency_claims")
            .fetch_one(pool)
            .await?;
    assert_eq!(actual, expected);
    Ok(())
}

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now_utc_millis(&self) -> Result<i64, ClockError> {
        Ok(self.0)
    }
}

fn genesis(
    root: &SigningKey,
    recovery: &SigningKey,
    occurred_at: i64,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let root_key = public_key(root)?;
    let recovery_key = public_key(recovery)?;
    let identity_id = IdentityId::derive(root_key.as_domain_key());
    let recovery_acceptance_signature = signature(
        recovery,
        &genesis_recovery_acceptance_input(identity_id, root_key, recovery_key)?,
    );
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        SafeUint::new(1)?,
        None,
        UtcMillis::new(occurred_at)?,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature,
        },
        root_key,
    )?;
    Ok(IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            root,
            &identity_log_signature_input(unsigned.signing_digest()?),
        ),
    )?)
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_key(key: &SigningKey) -> Result<SigningPublicKey, Box<dyn Error>> {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).map_err(Into::into)
}

fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}
