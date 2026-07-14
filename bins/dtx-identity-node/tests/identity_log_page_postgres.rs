#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use dtx_domain::{Clock, ClockError, IdentityId};
use dtx_identity_log::{
    IdentityLogEventPayloadV1, IdentityLogEventV1, IdentityLogPageV1, RelayDescriptorV1,
    UnsignedIdentityLogEventV1, genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_node::{
    IDENTITY_BOOTSTRAP_PATH, IDENTITY_LOG_EVENT_CONTENT_TYPE, IDENTITY_LOG_PAGE_CONTENT_TYPE,
    IdentityBootstrapState, identity_bootstrap_router_with_state,
};
use dtx_identity_persistence::{
    IdentityAppendCommand, IdentityAppendOutcome, IdentityLogHead, IdentityLogRepository,
    IdentityPgStore,
};
use dtx_wire::{Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey, UtcMillis};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::PgPool;
use tower::ServiceExt;

const IDEMPOTENCY_KEY: &str = "identity-log-page-bootstrap-key";

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL route flow keeps pagination, replay, durable-corruption, and stable status assertions on the same identity chain"
)]
async fn identity_log_page_is_exact_replayable_and_never_silently_resets_a_cursor()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let repository_store = store.clone();
    let app = identity_bootstrap_router_with_state(IdentityBootstrapState::with_clock(
        store,
        Arc::new(FixedClock(2_000)),
    ));

    let genesis = genesis(&signing_key(1), &signing_key(2), 1_000)?;
    let identity_id = genesis.identity_id();
    let exact_event_bytes = genesis.to_deterministic_cbor()?;
    let bootstrap = Request::builder()
        .method("POST")
        .uri(IDENTITY_BOOTSTRAP_PATH)
        .header(header::CONTENT_TYPE, IDENTITY_LOG_EVENT_CONTENT_TYPE)
        .header("idempotency-key", IDEMPOTENCY_KEY)
        .body(Body::from(exact_event_bytes.clone()))?;
    assert_eq!(
        app.clone().oneshot(bootstrap).await?.status(),
        StatusCode::CREATED
    );

    let repository = IdentityLogRepository::new();
    let genesis_head = repository
        .load(&repository_store, identity_id)
        .await?
        .ok_or("bootstrap must create an identity log")?
        .head();
    let second_event = relay_event(
        &signing_key(1),
        identity_id,
        2,
        genesis_head.hash(),
        "one",
        2_010,
    )?;
    let second_head = append_committed(
        repository
            .append(
                &repository_store,
                &append_command(2, genesis_head, &second_event)?,
                UtcMillis::new(2_020)?,
            )
            .await?,
    )?;
    let third_event = relay_event(
        &signing_key(1),
        identity_id,
        3,
        second_head.hash(),
        "two",
        2_030,
    )?;
    let third_head = append_committed(
        repository
            .append(
                &repository_store,
                &append_command(3, second_head, &third_event)?,
                UtcMillis::new(2_040)?,
            )
            .await?,
    )?;
    assert_eq!(third_head.sequence().get(), 3);

    let path = format!("/v1/identities/{identity_id}/log?after=0&limit=1");
    let first = get_page(app.clone(), &path).await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        first
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(IDENTITY_LOG_PAGE_CONTENT_TYPE)
    );
    assert_no_store_headers(first.headers())?;
    let first = to_bytes(first.into_body(), 2 * 1024 * 1024).await?.to_vec();
    let page = IdentityLogPageV1::decode_and_verify(&first)?;
    assert_eq!(page.identity_id(), identity_id);
    assert_eq!(page.advertised_head_sequence().get(), 3);
    assert_eq!(page.requested_after_sequence(), 0);
    assert_eq!(page.next_after_sequence(), 1);
    assert!(page.has_more());
    assert_eq!(page.exact_events(), &[exact_event_bytes]);

    // A lost response must be safe to retry: the read has no hidden cursor or
    // acknowledgement state and returns the same canonical bytes.
    let retry = get_page(app.clone(), &path).await?;
    assert_eq!(retry.status(), StatusCode::OK);
    let retry = to_bytes(retry.into_body(), 2 * 1024 * 1024).await?.to_vec();
    assert_eq!(retry, first);

    let second = get_page(
        app.clone(),
        &format!("/v1/identities/{identity_id}/log?after=1&limit=1"),
    )
    .await?;
    assert_eq!(second.status(), StatusCode::OK);
    let second = IdentityLogPageV1::decode_and_verify(
        &to_bytes(second.into_body(), 2 * 1024 * 1024).await?,
    )?;
    assert_eq!(second.requested_after_sequence(), 1);
    assert_eq!(second.next_after_sequence(), 2);
    assert!(second.has_more());
    assert_eq!(
        second.exact_events(),
        &[second_event.to_deterministic_cbor()?]
    );
    assert_eq!(
        IdentityLogEventV1::decode_and_verify(&second.exact_events()[0])?.previous_event_hash(),
        Some(genesis.entry_hash()?)
    );

    let third = get_page(
        app.clone(),
        &format!("/v1/identities/{identity_id}/log?after=2&limit=1"),
    )
    .await?;
    assert_eq!(third.status(), StatusCode::OK);
    let third =
        IdentityLogPageV1::decode_and_verify(&to_bytes(third.into_body(), 2 * 1024 * 1024).await?)?;
    assert_eq!(third.requested_after_sequence(), 2);
    assert_eq!(third.next_after_sequence(), 3);
    assert!(!third.has_more());
    assert_eq!(
        third.exact_events(),
        &[third_event.to_deterministic_cbor()?]
    );
    assert_eq!(
        IdentityLogEventV1::decode_and_verify(&third.exact_events()[0])?.previous_event_hash(),
        Some(second_event.entry_hash()?)
    );

    let terminal = get_page(
        app.clone(),
        &format!("/v1/identities/{identity_id}/log?after=3&limit=1"),
    )
    .await?;
    assert_eq!(terminal.status(), StatusCode::OK);
    let terminal = IdentityLogPageV1::decode_and_verify(
        &to_bytes(terminal.into_body(), 2 * 1024 * 1024).await?,
    )?;
    assert!(terminal.exact_events().is_empty());
    assert_eq!(terminal.next_after_sequence(), 3);
    assert!(!terminal.has_more());

    // A signed, canonical row can still be disconnected from the cursor
    // predecessor. The transport must fail closed instead of emitting a page
    // whose first event only looks valid in isolation.
    let corrupted_second = relay_event(
        &signing_key(1),
        identity_id,
        2,
        Sha256Digest::from_bytes([99; 32]),
        "corrupted-boundary",
        2_050,
    )?;
    let corrupted_hash = corrupted_second.entry_hash()?;
    replace_entry_for_test(
        harness.admin_pool(),
        identity_id,
        second_event.entry_hash()?,
        &corrupted_second,
    )
    .await?;
    let corrupted = get_page(
        app.clone(),
        &format!("/v1/identities/{identity_id}/log?after=1&limit=1"),
    )
    .await?;
    assert_error(
        corrupted,
        StatusCode::SERVICE_UNAVAILABLE,
        "IDENTITY_SERVICE_UNAVAILABLE",
        true,
    )
    .await?;
    replace_entry_for_test(
        harness.admin_pool(),
        identity_id,
        corrupted_hash,
        &second_event,
    )
    .await?;

    let ahead = get_page(
        app.clone(),
        &format!("/v1/identities/{identity_id}/log?after=4&limit=1"),
    )
    .await?;
    assert_error(
        ahead,
        StatusCode::CONFLICT,
        "IDENTITY_LOG_CURSOR_AHEAD",
        false,
    )
    .await?;

    let duplicate_cursor = get_page(
        app.clone(),
        &format!("/v1/identities/{identity_id}/log?after=0&after=0"),
    )
    .await?;
    assert_error(
        duplicate_cursor,
        StatusCode::BAD_REQUEST,
        "IDENTITY_LOG_PAGE_INVALID",
        false,
    )
    .await?;

    sqlx::query("UPDATE identity.log_heads SET state='tombstoned' WHERE identity_id=$1")
        .bind(identity_id.to_string())
        .execute(harness.admin_pool())
        .await?;
    let inactive = get_page(
        app.clone(),
        &format!("/v1/identities/{identity_id}/log?after=0&limit=1"),
    )
    .await?;
    assert_error(inactive, StatusCode::GONE, "IDENTITY_LOG_INACTIVE", false).await?;

    let unknown = IdentityId::derive(public_key(&signing_key(9))?.as_domain_key());
    let unknown = get_page(
        app.clone(),
        &format!("/v1/identities/{unknown}/log?after=0&limit=1"),
    )
    .await?;
    assert_error(
        unknown,
        StatusCode::NOT_FOUND,
        "IDENTITY_LOG_NOT_FOUND",
        false,
    )
    .await?;

    Ok(())
}

async fn get_page(
    app: axum::Router,
    path: &str,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())?;
    app.oneshot(request).await.map_err(Into::into)
}

async fn replace_entry_for_test(
    pool: &PgPool,
    identity_id: IdentityId,
    current_hash: Sha256Digest,
    replacement: &IdentityLogEventV1,
) -> Result<(), Box<dyn Error>> {
    let replacement_hash = replacement.entry_hash()?;
    let replacement_previous = replacement
        .previous_event_hash()
        .ok_or("replacement relay event must have a predecessor")?;
    let mut mutation = pool.begin().await?;
    sqlx::query("ALTER TABLE identity.log_heads DISABLE TRIGGER ALL")
        .execute(&mut *mutation)
        .await?;
    sqlx::query("ALTER TABLE identity.log_entries DISABLE TRIGGER ALL")
        .execute(&mut *mutation)
        .await?;
    sqlx::query(
        "UPDATE identity.log_entries
            SET entry_hash=$1, previous_hash=$2, event_bytes=$3
          WHERE identity_id=$4 AND sequence=2",
    )
    .bind(replacement_hash.as_bytes().as_slice())
    .bind(replacement_previous.as_bytes().as_slice())
    .bind(replacement.to_deterministic_cbor()?)
    .bind(identity_id.to_string())
    .execute(&mut *mutation)
    .await?;
    sqlx::query(
        "UPDATE identity.log_outbox
            SET entry_hash=$1
          WHERE identity_id=$2 AND entry_hash=$3",
    )
    .bind(replacement_hash.as_bytes().as_slice())
    .bind(identity_id.to_string())
    .bind(current_hash.as_bytes().as_slice())
    .execute(&mut *mutation)
    .await?;
    sqlx::query("ALTER TABLE identity.log_entries ENABLE TRIGGER ALL")
        .execute(&mut *mutation)
        .await?;
    sqlx::query("ALTER TABLE identity.log_heads ENABLE TRIGGER ALL")
        .execute(&mut *mutation)
        .await?;
    mutation.commit().await?;
    Ok(())
}

async fn assert_error(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_code: &str,
    expected_retryable: bool,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.status(), expected_status);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_no_store_headers(response.headers())?;
    let body = to_bytes(response.into_body(), 16_384).await?;
    let body: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_str),
        Some(expected_code)
    );
    assert_eq!(
        body.pointer("/error/retryable")
            .and_then(serde_json::Value::as_bool),
        Some(expected_retryable)
    );
    Ok(())
}

fn assert_no_store_headers(headers: &axum::http::HeaderMap) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .ok_or("response is missing X-Request-Id")?;
    assert_eq!(uuid::Uuid::parse_str(request_id)?.get_version_num(), 7);
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

fn relay_event(
    root: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous: Sha256Digest,
    label: &str,
    occurred_at: i64,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let descriptor = RelayDescriptorV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        vec![format!("https://relay-{label}.example/v1")],
        UtcMillis::new(occurred_at + 100)?,
    )?;
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        SafeUint::new(sequence)?,
        Some(previous),
        UtcMillis::new(occurred_at)?,
        IdentityLogEventPayloadV1::RelayDescriptor { descriptor },
        public_key(root)?,
    )?;
    Ok(IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            root,
            &identity_log_signature_input(unsigned.signing_digest()?),
        ),
    )?)
}

fn append_command(
    seed: u8,
    expected_head: IdentityLogHead,
    event: &IdentityLogEventV1,
) -> Result<IdentityAppendCommand, Box<dyn Error>> {
    Ok(IdentityAppendCommand::new(
        Sha256Digest::from_bytes([seed; 32]),
        Some(expected_head),
        event.to_deterministic_cbor()?,
    )?)
}

fn append_committed(outcome: IdentityAppendOutcome) -> Result<IdentityLogHead, Box<dyn Error>> {
    match outcome {
        IdentityAppendOutcome::Committed(receipt) => Ok(receipt.head()),
        IdentityAppendOutcome::Replayed(_) | IdentityAppendOutcome::Forked { .. } => {
            Err("expected first durable append".into())
        }
    }
}
