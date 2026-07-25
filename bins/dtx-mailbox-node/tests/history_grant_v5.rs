#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
async fn history_grant_v5_http_boundary_uses_production_parser_and_role_gate()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 2).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 2).await?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(NOW)),
    ));
    let provider = enroll_active_device(&identity_store, 211, 212, 213, [214; 32]).await?;

    let invalid = send_v2(
        app.clone(),
        DEVICE_HISTORY_GRANT_V5_PATH,
        DEVICE_HISTORY_GRANT_V5_CONTENT_TYPE,
        Some("grant-v5-invalid-parser"),
        provider.session_id,
        provider.session_secret,
        vec![0xa0],
    )
    .await?;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let unauthenticated = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(DEVICE_HISTORY_GRANT_V5_PATH)
                .header(header::CONTENT_TYPE, DEVICE_HISTORY_GRANT_V5_CONTENT_TYPE)
                .header("idempotency-key", "grant-v5-unauthenticated")
                .body(Body::from(vec![0xa0]))?,
        )
        .await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}
