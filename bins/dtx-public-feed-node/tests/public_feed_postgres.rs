#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use dtx_domain::{ChannelId, IdentityId, PublicSubjectId, TenantId};
use dtx_public_descriptor::{
    PUBLIC_DESCRIPTOR_WIRE_VERSION, PublicDescriptorKindV1, PublicDescriptorPayloadV1,
    SignedPublicDescriptorV1, UnsignedPublicDescriptorV1,
};
use dtx_public_feed::{PublicFeedPayloadV1, SignedPublicFeedEventV1, UnsignedPublicFeedEventV1};
use dtx_public_feed_node::{
    DESCRIPTOR_CONTENT_TYPE, EVENT_CONTENT_TYPE, PublicFeedPgStore, public_feed_router,
};
use dtx_wire::{
    CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey, UtcMillis,
    decode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use support::PostgresHarness;
use tower::ServiceExt;

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("time")
}
fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}
fn public_key(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).expect("public key")
}
fn descriptor(now: i64) -> SignedPublicDescriptorV1 {
    let key = signing_key();
    let public = public_key(&key);
    let subject = PublicSubjectId::Channel(ChannelId::derive(public.as_domain_key()));
    let unsigned = UnsignedPublicDescriptorV1::new(
        PUBLIC_DESCRIPTOR_WIRE_VERSION,
        PublicDescriptorKindV1::Channel,
        subject,
        public,
        IdentityId::derive(public.as_domain_key()),
        public,
        SafeUint::new(1).expect("sequence"),
        None,
        UtcMillis::new(now - 1000).expect("time"),
        UtcMillis::new(now + 60_000).expect("time"),
        PublicDescriptorPayloadV1::Channel {
            feed_origin: "https://feed.example".to_owned(),
            capability_digest: Sha256Digest::from_bytes([9; 32]),
        },
    )
    .expect("descriptor");
    let input = unsigned.signature_input().expect("input");
    SignedPublicDescriptorV1::signed(
        unsigned,
        Ed25519Signature::from_bytes(key.sign(&input).to_bytes()),
    )
    .expect("signed")
}
fn event(
    subject: PublicSubjectId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    payload: PublicFeedPayloadV1,
    now: i64,
) -> SignedPublicFeedEventV1 {
    let key = signing_key();
    let public = public_key(&key);
    let unsigned = UnsignedPublicFeedEventV1::new(
        subject,
        IdentityId::derive(public.as_domain_key()),
        public,
        SafeUint::new(sequence).expect("sequence"),
        previous,
        UtcMillis::new(now + i64::try_from(sequence).expect("small")).expect("time"),
        payload,
    )
    .expect("event");
    let input = unsigned.signature_input().expect("input");
    SignedPublicFeedEventV1::signed(
        unsigned,
        Ed25519Signature::from_bytes(key.sign(&input).to_bytes()),
    )
    .expect("signed")
}
fn write_request(
    method: &str,
    path: &str,
    content_type: &str,
    body: Vec<u8>,
    now: i64,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, content_type)
        .header("x-dtx-deadline-ms", (now + 30_000).to_string())
        .body(Body::from(body))
        .expect("request")
}
fn map_field(map: &[(CanonicalValue, CanonicalValue)], key: u64) -> &CanonicalValue {
    map.iter()
        .find_map(|(k, v)| (*k == CanonicalValue::Unsigned(key)).then_some(v))
        .expect("field")
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end acceptance path intentionally keeps all recovery assertions together.
async fn descriptor_two_posts_pagination_replay_and_tombstone_converge()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let tenant = TenantId::new();
    let store = PublicFeedPgStore::from_prevalidated_pool(harness.admin_pool().clone());
    let app = public_feed_router(store.clone(), tenant);
    let replica = public_feed_router(store, tenant);
    let now = now_ms();
    let descriptor = descriptor(now);
    let subject = descriptor.subject_id();
    let root = format!("/.well-known/dirextalk/public/v1/{subject}");
    let feed = format!("{root}/feed");
    for private_header in [header::AUTHORIZATION, header::COOKIE] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&root)
                    .header(private_header, "opaque")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }
    let response = replica
        .clone()
        .oneshot(Request::builder().uri(&root).body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("public, max-age=2, must-revalidate")
    );
    let response = app
        .clone()
        .oneshot(write_request(
            "PUT",
            &root,
            DESCRIPTOR_CONTENT_TYPE,
            descriptor.to_deterministic_cbor()?,
            now,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        replica
            .clone()
            .oneshot(Request::builder().uri(&root).body(Body::empty())?)
            .await?
            .status(),
        StatusCode::OK,
        "descriptor publish must bypass another replica's cached miss"
    );
    let private_read = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&root)
                .header(header::AUTHORIZATION, "opaque")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(private_read.status(), StatusCode::OK);
    assert_eq!(
        private_read
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "credential-bearing reads must bypass the shared cache"
    );
    assert!(private_read.headers().contains_key(header::ETAG));
    let response = replica
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{feed}?limit=1"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("public, max-age=2, must-revalidate")
    );
    let first = event(
        subject,
        1,
        None,
        PublicFeedPayloadV1::Post {
            body: "one".to_owned(),
            attachments: vec![],
        },
        now,
    );
    let response = app
        .clone()
        .oneshot(write_request(
            "POST",
            &feed,
            EVENT_CONTENT_TYPE,
            first.to_deterministic_cbor()?,
            now,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        replica
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{feed}?limit=1"))
                    .body(Body::empty())?,
            )
            .await?
            .status(),
        StatusCode::OK,
        "feed append must bypass another replica's cached root miss"
    );
    let second = event(
        subject,
        2,
        Some(first.entry_hash()?),
        PublicFeedPayloadV1::Post {
            body: "two".to_owned(),
            attachments: vec![],
        },
        now,
    );
    let second_bytes = second.to_deterministic_cbor()?;
    let response = app
        .clone()
        .oneshot(write_request(
            "POST",
            &feed,
            EVENT_CONTENT_TYPE,
            second_bytes.clone(),
            now,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = replica
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{feed}?limit=1"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let root_etag = response
        .headers()
        .get(header::ETAG)
        .ok_or("missing feed ETag")?
        .clone();
    let page = decode_deterministic_cbor(&to_bytes(response.into_body(), 100_000).await?)?;
    let CanonicalValue::Map(fields) = page else {
        panic!("page map")
    };
    let CanonicalValue::Text(cursor) = map_field(&fields, 4) else {
        panic!("cursor")
    };
    let response = replica
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{feed}?limit=1"))
                .header(header::IF_NONE_MATCH, root_etag.clone())
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(response.headers().get(header::ETAG), Some(&root_etag));
    let response = replica
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{feed}?limit=1&cursor={cursor}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = decode_deterministic_cbor(&to_bytes(response.into_body(), 100_000).await?)?;
    let CanonicalValue::Map(fields) = page else {
        panic!("page map")
    };
    assert_eq!(map_field(&fields, 4), &CanonicalValue::Null);
    let response = app
        .clone()
        .oneshot(write_request(
            "POST",
            &feed,
            EVENT_CONTENT_TYPE,
            second_bytes,
            now,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let tombstone = event(
        subject,
        3,
        Some(second.entry_hash()?),
        PublicFeedPayloadV1::Tombstone,
        now,
    );
    let response = app
        .clone()
        .oneshot(write_request(
            "POST",
            &feed,
            EVENT_CONTENT_TYPE,
            tombstone.to_deterministic_cbor()?,
            now,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = replica
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{feed}?limit=1"))
                .header(header::IF_NONE_MATCH, root_etag)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let resurrection = event(
        subject,
        4,
        Some(tombstone.entry_hash()?),
        PublicFeedPayloadV1::Post {
            body: "forbidden".to_owned(),
            attachments: vec![],
        },
        now,
    );
    let response = app
        .oneshot(write_request(
            "POST",
            &feed,
            EVENT_CONTENT_TYPE,
            resurrection.to_deterministic_cbor()?,
            now,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let forced:i64=sqlx::query_scalar("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='directory' AND c.relrowsecurity AND c.relforcerowsecurity").fetch_one(harness.admin_pool()).await?;
    assert_eq!(forced, 9);
    Ok(())
}
