#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use dtx_domain::{
    ChannelId, DirectoryRegistrationId, IdentityId, IndexerId, PublicSubjectId, TenantId,
};
use dtx_indexer::IndexRegistrationRequestV1;
use dtx_indexer_node::{
    FetchedPublicBundle, IndexerPgStore, NodeError, PublicBundleFetcher, REGISTRATION_CONTENT_TYPE,
    indexer_router,
};
use dtx_public_descriptor::{
    PUBLIC_DESCRIPTOR_WIRE_VERSION, PublicDescriptorKindV1, PublicDescriptorPayloadV1,
    SignedPublicDescriptorV1, UnsignedPublicDescriptorV1,
};
use dtx_public_feed::{PublicFeedPayloadV1, SignedPublicFeedEventV1, UnsignedPublicFeedEventV1};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, ProtocolVersion, SafeUint, Sha256Digest,
    SigningPublicKey, UtcMillis, WireVersion, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use support::PostgresHarness;
use tower::ServiceExt;

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("time")
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}
fn public() -> SigningPublicKey {
    SigningPublicKey::try_from(key().verifying_key().to_bytes()).expect("key")
}
fn descriptor(now: i64) -> SignedPublicDescriptorV1 {
    let public = public();
    let unsigned = UnsignedPublicDescriptorV1::new(
        PUBLIC_DESCRIPTOR_WIRE_VERSION,
        PublicDescriptorKindV1::Channel,
        PublicSubjectId::Channel(ChannelId::derive(public.as_domain_key())),
        public,
        IdentityId::derive(public.as_domain_key()),
        public,
        SafeUint::new(1).expect("seq"),
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
        Ed25519Signature::from_bytes(key().sign(&input).to_bytes()),
    )
    .expect("signed")
}
fn event(
    subject: PublicSubjectId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    body: &str,
    now: i64,
) -> SignedPublicFeedEventV1 {
    let public = public();
    let unsigned = UnsignedPublicFeedEventV1::new(
        subject,
        IdentityId::derive(public.as_domain_key()),
        public,
        SafeUint::new(sequence).expect("seq"),
        previous,
        UtcMillis::new(now + i64::try_from(sequence).expect("small")).expect("time"),
        PublicFeedPayloadV1::Post {
            body: body.to_owned(),
            attachments: vec![],
        },
    )
    .expect("event");
    let input = unsigned.signature_input().expect("input");
    SignedPublicFeedEventV1::signed(
        unsigned,
        Ed25519Signature::from_bytes(key().sign(&input).to_bytes()),
    )
    .expect("signed")
}
fn page(subject: PublicSubjectId, events: &[SignedPublicFeedEventV1]) -> Vec<u8> {
    let last = events.last().expect("event");
    let value = CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            WireVersion::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0))
                .to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(subject.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Array(
                events
                    .iter()
                    .map(|v| CanonicalValue::Bytes(v.to_deterministic_cbor().expect("event")))
                    .collect(),
            ),
        ),
        (CanonicalValue::Unsigned(4), CanonicalValue::Null),
        (
            CanonicalValue::Unsigned(5),
            last.sequence().to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            last.entry_hash().expect("hash").to_canonical_value(),
        ),
    ]);
    encode_deterministic_cbor(&value).expect("page")
}
#[derive(Clone)]
struct FixtureFetcher {
    failed: IndexerId,
    bundle: FetchedPublicBundle,
}
impl PublicBundleFetcher for FixtureFetcher {
    fn fetch<'a>(
        &'a self,
        indexer: IndexerId,
        _: &'a SignedPublicDescriptorV1,
    ) -> Pin<Box<dyn Future<Output = Result<FetchedPublicBundle, NodeError>> + Send + 'a>> {
        Box::pin(async move {
            if indexer == self.failed {
                Err(NodeError::FetchFailed)
            } else {
                Ok(self.bundle.clone())
            }
        })
    }
}
fn post(path: &str, body: Vec<u8>, now: i64) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, REGISTRATION_CONTENT_TYPE)
        .header("x-dtx-deadline-ms", (now + 30_000).to_string())
        .body(Body::from(body))
        .expect("request")
}
fn field(map: &[(CanonicalValue, CanonicalValue)], key: u64) -> &CanonicalValue {
    map.iter()
        .find_map(|(k, v)| (*k == CanonicalValue::Unsigned(key)).then_some(v))
        .expect("field")
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end database and HTTP acceptance workflow"
)]
async fn two_logical_indexers_keep_independent_registration_and_search_state()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let tenant = TenantId::new();
    let now = now();
    let descriptor = descriptor(now);
    let subject = descriptor.subject_id();
    let first = event(subject, 1, None, "public alpha", now);
    let second = event(subject, 2, Some(first.entry_hash()?), "second post", now);
    let good = IndexerId::new();
    let failed = IndexerId::new();
    let conflicting = IndexerId::new();
    let fetcher = FixtureFetcher {
        failed,
        bundle: FetchedPublicBundle {
            descriptor: descriptor.to_deterministic_cbor()?,
            pages: vec![page(subject, &[first, second])],
        },
    };
    let store = IndexerPgStore::from_prevalidated_pool(harness.admin_pool().clone());
    let fetcher: Arc<dyn PublicBundleFetcher> = Arc::new(fetcher);
    let good_app = indexer_router(store.clone(), tenant, good, Arc::clone(&fetcher));
    let failed_app = indexer_router(store.clone(), tenant, failed, Arc::clone(&fetcher));
    let conflicting_app = indexer_router(store, tenant, conflicting, fetcher);
    let good_request = IndexRegistrationRequestV1::new(
        DirectoryRegistrationId::new(),
        good,
        descriptor.to_deterministic_cbor()?,
    )?;
    let failed_request = IndexRegistrationRequestV1::new(
        DirectoryRegistrationId::new(),
        failed,
        descriptor.to_deterministic_cbor()?,
    )?;
    let response = good_app
        .clone()
        .oneshot(post("/v1/index-registrations", good_request.encode()?, now))
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let receipt = decode_deterministic_cbor(&to_bytes(response.into_body(), 100_000).await?)?;
    let CanonicalValue::Map(fields) = receipt else {
        panic!("receipt")
    };
    assert_eq!(field(&fields, 5), &CanonicalValue::Unsigned(2));
    let response = failed_app
        .clone()
        .oneshot(post(
            "/v1/index-registrations",
            failed_request.encode()?,
            now,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let receipt = decode_deterministic_cbor(&to_bytes(response.into_body(), 100_000).await?)?;
    let CanonicalValue::Map(fields) = receipt else {
        panic!("receipt")
    };
    assert_eq!(field(&fields, 5), &CanonicalValue::Unsigned(3));
    let response = good_app
        .clone()
        .oneshot(post("/v1/index-registrations", good_request.encode()?, now))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    for (app, indexer, expected) in [
        (good_app.clone(), good, 1_usize),
        (failed_app.clone(), failed, 0_usize),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/public-search?indexer_id={indexer}&q={subject}"
                    ))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let page = decode_deterministic_cbor(&to_bytes(response.into_body(), 100_000).await?)?;
        let CanonicalValue::Map(fields) = page else {
            panic!("page")
        };
        let CanonicalValue::Array(results) = field(&fields, 2) else {
            panic!("results")
        };
        assert_eq!(results.len(), expected);
    }
    let mismatched = IndexRegistrationRequestV1::new(
        DirectoryRegistrationId::new(),
        IndexerId::new(),
        descriptor.to_deterministic_cbor()?,
    )?;
    let response = good_app
        .clone()
        .oneshot(post("/v1/index-registrations", mismatched.encode()?, now))
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let conflicting_registration = DirectoryRegistrationId::new();
    let descriptor_hash = descriptor.entry_hash()?;
    sqlx::query("INSERT INTO directory.index_registrations(tenant_id,registration_id,indexer_id,subject_id,subject_kind,status,descriptor_sequence,descriptor_hash,descriptor_exact_cbor,feed_origin,created_at_ms,updated_at_ms) VALUES($1,$2,$3,$4,1,1,1,$5,$6,'https://feed.example',$7,$7)")
        .bind(tenant.as_uuid()).bind(conflicting_registration.as_uuid()).bind(conflicting.as_uuid()).bind(subject.to_string()).bind(descriptor_hash.as_bytes().as_slice()).bind(descriptor.to_deterministic_cbor()?).bind(now).execute(harness.admin_pool()).await?;
    sqlx::query("INSERT INTO directory.indexed_feed_entries(tenant_id,indexer_id,subject_id,sequence,entry_hash,exact_cbor) VALUES($1,$2,$3,1,$4,$5)")
        .bind(tenant.as_uuid()).bind(conflicting.as_uuid()).bind(subject.to_string()).bind([1_u8;32].as_slice()).bind([1_u8].as_slice()).execute(harness.admin_pool()).await?;
    let conflicting_request = IndexRegistrationRequestV1::new(
        conflicting_registration,
        conflicting,
        descriptor.to_deterministic_cbor()?,
    )?;
    let response = conflicting_app
        .oneshot(post(
            "/v1/index-registrations",
            conflicting_request.encode()?,
            now,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let response = good_app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/public-search?indexer_id={good}&q=public%20alpha"
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = decode_deterministic_cbor(&to_bytes(response.into_body(), 100_000).await?)?;
    let CanonicalValue::Map(fields) = page else {
        panic!("page")
    };
    let CanonicalValue::Array(results) = field(&fields, 2) else {
        panic!("results")
    };
    assert_eq!(results.len(), 1);
    Ok(())
}
