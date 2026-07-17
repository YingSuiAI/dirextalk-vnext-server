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
    collections::HashSet,
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
    key_for(42)
}
fn key_for(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public() -> SigningPublicKey {
    SigningPublicKey::try_from(key().verifying_key().to_bytes()).expect("key")
}
fn descriptor(now: i64) -> SignedPublicDescriptorV1 {
    descriptor_version(now, 1, None, false)
}
fn descriptor_version(
    now: i64,
    sequence: u64,
    previous: Option<Sha256Digest>,
    tombstone: bool,
) -> SignedPublicDescriptorV1 {
    descriptor_version_for(42, now, sequence, previous, tombstone)
}
fn descriptor_version_for(
    seed: u8,
    now: i64,
    sequence: u64,
    previous: Option<Sha256Digest>,
    tombstone: bool,
) -> SignedPublicDescriptorV1 {
    let key = key_for(seed);
    let public = SigningPublicKey::try_from(key.verifying_key().to_bytes()).expect("key");
    let issued = UtcMillis::new(now - 1000).expect("time");
    let payload = if tombstone {
        PublicDescriptorPayloadV1::Tombstone
    } else {
        PublicDescriptorPayloadV1::Channel {
            feed_origin: "https://feed.example".to_owned(),
            capability_digest: Sha256Digest::from_bytes([9; 32]),
        }
    };
    let unsigned = UnsignedPublicDescriptorV1::new(
        PUBLIC_DESCRIPTOR_WIRE_VERSION,
        PublicDescriptorKindV1::Channel,
        PublicSubjectId::Channel(ChannelId::derive(public.as_domain_key())),
        public,
        IdentityId::derive(public.as_domain_key()),
        public,
        SafeUint::new(sequence).expect("seq"),
        previous,
        issued,
        if tombstone {
            issued
        } else {
            UtcMillis::new(now + 60_000).expect("time")
        },
        payload,
    )
    .expect("descriptor");
    let input = unsigned.signature_input().expect("input");
    SignedPublicDescriptorV1::signed(
        unsigned,
        Ed25519Signature::from_bytes(key.sign(&input).to_bytes()),
    )
    .expect("signed")
}

#[derive(Clone)]
struct DynamicFetcher {
    failed: Arc<tokio::sync::Mutex<HashSet<IndexerId>>>,
    bundle: Arc<tokio::sync::Mutex<FetchedPublicBundle>>,
}
impl PublicBundleFetcher for DynamicFetcher {
    fn fetch<'a>(
        &'a self,
        indexer: IndexerId,
        _: &'a SignedPublicDescriptorV1,
    ) -> Pin<Box<dyn Future<Output = Result<FetchedPublicBundle, NodeError>> + Send + 'a>> {
        Box::pin(async move {
            if self.failed.lock().await.contains(&indexer) {
                Err(NodeError::FetchFailed)
            } else {
                Ok(self.bundle.lock().await.clone())
            }
        })
    }
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
async fn search_count(
    app: axum::Router,
    indexer: IndexerId,
    query: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/public-search?indexer_id={indexer}&q={query}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = decode_deterministic_cbor(&to_bytes(response.into_body(), 100_000).await?)?;
    let CanonicalValue::Map(fields) = page else {
        return Err("search page must be a map".into());
    };
    let CanonicalValue::Array(results) = field(&fields, 2) else {
        return Err("search results must be an array".into());
    };
    Ok(results.len())
}

async fn insert_published_subject(
    pool: &sqlx::PgPool,
    tenant: TenantId,
    indexer: IndexerId,
    descriptor: &SignedPublicDescriptorV1,
    search_document: &str,
    now: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let hash = descriptor.entry_hash()?;
    sqlx::query(
        "INSERT INTO directory.index_registrations(tenant_id,registration_id,indexer_id,subject_id,subject_kind,status,descriptor_sequence,descriptor_hash,descriptor_exact_cbor,feed_origin,search_document,created_at_ms,updated_at_ms) VALUES($1,$2,$3,$4,1,2,$5,$6,$7,'https://feed.example',$8,$9,$9)",
    )
    .bind(tenant.as_uuid())
    .bind(DirectoryRegistrationId::new().as_uuid())
    .bind(indexer.as_uuid())
    .bind(descriptor.subject_id().to_string())
    .bind(i64::try_from(descriptor.sequence().get())?)
    .bind(hash.as_bytes().as_slice())
    .bind(descriptor.to_deterministic_cbor()?)
    .bind(search_document)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
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

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one update, partial failure, replay, and permanent revoke workflow"
)]
async fn descriptor_head_updates_atomically_and_tombstone_cannot_be_resurrected()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let tenant = TenantId::new();
    let now = now();
    let v1 = descriptor(now);
    let subject = v1.subject_id();
    let first = event(subject, 1, None, "public alpha", now);
    let first_page = page(subject, std::slice::from_ref(&first));
    let fetcher = DynamicFetcher {
        failed: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        bundle: Arc::new(tokio::sync::Mutex::new(FetchedPublicBundle {
            descriptor: v1.to_deterministic_cbor()?,
            pages: vec![first_page],
        })),
    };
    let first_indexer = IndexerId::new();
    let second_indexer = IndexerId::new();
    let first_registration = DirectoryRegistrationId::new();
    let second_registration = DirectoryRegistrationId::new();
    let store = IndexerPgStore::from_prevalidated_pool(harness.admin_pool().clone());
    let shared: Arc<dyn PublicBundleFetcher> = Arc::new(fetcher.clone());
    let first_app = indexer_router(store.clone(), tenant, first_indexer, Arc::clone(&shared));
    let first_replica = indexer_router(store.clone(), tenant, first_indexer, Arc::clone(&shared));
    let second_app = indexer_router(store, tenant, second_indexer, shared);
    for (app, indexer, registration) in [
        (first_app.clone(), first_indexer, first_registration),
        (second_app.clone(), second_indexer, second_registration),
    ] {
        let subject_path = format!("/v1/public-subjects/{subject}?indexer_id={indexer}");
        for private_header in [header::AUTHORIZATION, header::COOKIE] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(&subject_path)
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
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri(&subject_path)
                        .header(header::IF_NONE_MATCH, "*")
                        .body(Body::empty())?,
                )
                .await?
                .status(),
            StatusCode::BAD_REQUEST,
            "invalid conditional input must be rejected before a cache lookup"
        );
        let missing = app
            .clone()
            .oneshot(Request::builder().uri(&subject_path).body(Body::empty())?)
            .await?;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            missing
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=2, must-revalidate")
        );
        let request =
            IndexRegistrationRequestV1::new(registration, indexer, v1.to_deterministic_cbor()?)?;
        assert_eq!(
            app.clone()
                .oneshot(post("/v1/index-registrations", request.encode()?, now))
                .await?
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            app.clone()
                .oneshot(Request::builder().uri(&subject_path).body(Body::empty())?,)
                .await?
                .status(),
            StatusCode::OK,
            "publish must invalidate the exact local subject miss"
        );
        let private_read = app
            .oneshot(
                Request::builder()
                    .uri(subject_path)
                    .header(header::COOKIE, "opaque")
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
    }

    let first_subject_path = format!("/v1/public-subjects/{subject}?indexer_id={first_indexer}");
    let initial_subject = first_replica
        .clone()
        .oneshot(
            Request::builder()
                .uri(&first_subject_path)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(initial_subject.status(), StatusCode::OK);
    let initial_subject_etag = initial_subject
        .headers()
        .get(header::ETAG)
        .ok_or("missing initial subject ETag")?
        .clone();
    let initial_search = first_replica
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/public-search?indexer_id={first_indexer}&q=alpha"
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(initial_search.status(), StatusCode::OK);
    let initial_search_etag = initial_search
        .headers()
        .get(header::ETAG)
        .ok_or("missing initial search ETag")?
        .clone();

    let v2 = descriptor_version(now, 2, Some(v1.entry_hash()?), false);
    let second = event(subject, 2, Some(first.entry_hash()?), "updated beta", now);
    *fetcher.bundle.lock().await = FetchedPublicBundle {
        descriptor: v2.to_deterministic_cbor()?,
        pages: vec![page(subject, &[first.clone(), second])],
    };
    fetcher.failed.lock().await.insert(second_indexer);
    let first_update = IndexRegistrationRequestV1::new(
        first_registration,
        first_indexer,
        v2.to_deterministic_cbor()?,
    )?;
    let second_update = IndexRegistrationRequestV1::new(
        second_registration,
        second_indexer,
        v2.to_deterministic_cbor()?,
    )?;
    assert_eq!(
        first_app
            .clone()
            .oneshot(post("/v1/index-registrations", first_update.encode()?, now))
            .await?
            .status(),
        StatusCode::CREATED
    );
    let updated_subject = first_replica
        .clone()
        .oneshot(
            Request::builder()
                .uri(&first_subject_path)
                .header(header::IF_NONE_MATCH, initial_subject_etag)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        updated_subject.status(),
        StatusCode::OK,
        "another replica must observe the persistent subject revision"
    );
    let updated_search = first_replica
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/public-search?indexer_id={first_indexer}&q=alpha"
                ))
                .header(header::IF_NONE_MATCH, initial_search_etag)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        updated_search.status(),
        StatusCode::OK,
        "another replica must observe the persistent search generation"
    );
    assert_eq!(
        second_app
            .clone()
            .oneshot(post(
                "/v1/index-registrations",
                second_update.encode()?,
                now
            ))
            .await?
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        search_count(first_app.clone(), first_indexer, "beta").await?,
        1
    );
    assert_eq!(
        search_count(second_app.clone(), second_indexer, "beta").await?,
        0
    );
    assert_eq!(
        search_count(second_app.clone(), second_indexer, "alpha").await?,
        1
    );
    let cached = first_replica
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/public-search?indexer_id={first_indexer}&q=beta"
                ))
                .body(Body::empty())?,
        )
        .await?;
    let etag = cached
        .headers()
        .get(header::ETAG)
        .ok_or("missing ETag")?
        .clone();
    assert_eq!(
        first_replica
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/public-search?indexer_id={first_indexer}&q=beta"
                    ))
                    .header(header::IF_NONE_MATCH, etag.clone())
                    .body(Body::empty())?,
            )
            .await?
            .status(),
        StatusCode::NOT_MODIFIED
    );

    assert_eq!(
        first_app
            .clone()
            .oneshot(post("/v1/index-registrations", first_update.encode()?, now))
            .await?
            .status(),
        StatusCode::OK
    );
    let fork = descriptor_version(now + 1, 2, Some(v1.entry_hash()?), false);
    let fork_request = IndexRegistrationRequestV1::new(
        first_registration,
        first_indexer,
        fork.to_deterministic_cbor()?,
    )?;
    assert_eq!(
        first_app
            .clone()
            .oneshot(post("/v1/index-registrations", fork_request.encode()?, now))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let gap = descriptor_version(now, 4, Some(v2.entry_hash()?), false);
    let gap_request = IndexRegistrationRequestV1::new(
        first_registration,
        first_indexer,
        gap.to_deterministic_cbor()?,
    )?;
    assert_eq!(
        first_app
            .clone()
            .oneshot(post("/v1/index-registrations", gap_request.encode()?, now))
            .await?
            .status(),
        StatusCode::CONFLICT
    );

    let tombstone = descriptor_version(now, 3, Some(v2.entry_hash()?), true);
    *fetcher.bundle.lock().await = FetchedPublicBundle {
        descriptor: tombstone.to_deterministic_cbor()?,
        pages: vec![],
    };
    let revoke = IndexRegistrationRequestV1::new(
        first_registration,
        first_indexer,
        tombstone.to_deterministic_cbor()?,
    )?;
    let response = first_app
        .clone()
        .oneshot(post("/v1/index-registrations", revoke.encode()?, now))
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let receipt = decode_deterministic_cbor(&to_bytes(response.into_body(), 100_000).await?)?;
    let CanonicalValue::Map(fields) = receipt else {
        return Err("receipt must be a map".into());
    };
    assert_eq!(field(&fields, 5), &CanonicalValue::Unsigned(5));
    let revoked_subject = first_replica
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/public-subjects/{subject}?indexer_id={first_indexer}"
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(revoked_subject.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        revoked_subject
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("public, max-age=2, must-revalidate")
    );
    assert_eq!(
        search_count(first_replica.clone(), first_indexer, "alpha").await?,
        0
    );
    assert_eq!(
        first_replica
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/public-search?indexer_id={first_indexer}&q=beta"
                    ))
                    .header(header::IF_NONE_MATCH, etag)
                    .body(Body::empty())?,
            )
            .await?
            .status(),
        StatusCode::OK
    );
    let old = IndexRegistrationRequestV1::new(
        first_registration,
        first_indexer,
        v1.to_deterministic_cbor()?,
    )?;
    assert_eq!(
        first_app
            .oneshot(post("/v1/index-registrations", old.encode()?, now))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one public pagination, cursor rejection, and replica invalidation contract"
)]
async fn search_pagination_is_stable_bound_and_invalidated_across_replicas()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let tenant = TenantId::new();
    let indexer = IndexerId::new();
    let now = now();
    let descriptors = [11_u8, 22, 33].map(|seed| descriptor_version_for(seed, now, 1, None, false));
    for descriptor in &descriptors {
        insert_published_subject(
            harness.admin_pool(),
            tenant,
            indexer,
            descriptor,
            "stable pagination",
            now,
        )
        .await?;
    }
    sqlx::query(
        "INSERT INTO directory.index_cache_generations(tenant_id,indexer_id,generation,updated_at_ms) VALUES($1,$2,1,$3)",
    )
    .bind(tenant.as_uuid())
    .bind(indexer.as_uuid())
    .bind(now)
    .execute(harness.admin_pool())
    .await?;

    let unused_bundle = FetchedPublicBundle {
        descriptor: descriptors[0].to_deterministic_cbor()?,
        pages: vec![],
    };
    let fetcher: Arc<dyn PublicBundleFetcher> = Arc::new(FixtureFetcher {
        failed: indexer,
        bundle: unused_bundle,
    });
    let store = IndexerPgStore::from_prevalidated_pool(harness.admin_pool().clone());
    let reader = indexer_router(store.clone(), tenant, indexer, Arc::clone(&fetcher));
    let _writer_replica = indexer_router(store, tenant, indexer, fetcher);

    let first = reader
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/public-search?indexer_id={indexer}&q=%20Stable%20%20Pagination%20&limit=1"
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(first.status(), StatusCode::OK);
    let first_etag = first
        .headers()
        .get(header::ETAG)
        .ok_or("missing first page ETag")?
        .clone();
    let first_cursor = first
        .headers()
        .get("x-dtx-next-cursor")
        .ok_or("missing first continuation")?
        .to_str()?
        .to_owned();
    let first_page = decode_deterministic_cbor(&to_bytes(first.into_body(), 100_000).await?)?;
    let CanonicalValue::Map(first_fields) = first_page else {
        return Err("first search page must be a map".into());
    };
    let CanonicalValue::Array(first_results) = field(&first_fields, 2) else {
        return Err("first search results must be an array".into());
    };
    assert_eq!(first_results.len(), 1);

    let conditional = reader
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/public-search?indexer_id={indexer}&q=stable%20pagination&limit=1"
                ))
                .header(header::IF_NONE_MATCH, first_etag)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(conditional.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        conditional
            .headers()
            .get("x-dtx-next-cursor")
            .and_then(|value| value.to_str().ok()),
        Some(first_cursor.as_str())
    );

    for rejected_uri in [
        format!("/v1/public-search?indexer_id={indexer}&q=different&cursor={first_cursor}"),
        format!(
            "/v1/public-search?indexer_id={indexer}&q=stable%20pagination&kind=agent&cursor={first_cursor}"
        ),
        format!(
            "/v1/public-search?indexer_id={indexer}&q=stable%20pagination&limit=2&cursor={first_cursor}"
        ),
    ] {
        assert_eq!(
            reader
                .clone()
                .oneshot(Request::builder().uri(rejected_uri).body(Body::empty())?)
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let mut tampered = first_cursor.clone().into_bytes();
    let last = tampered.last_mut().ok_or("empty cursor")?;
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered)?;
    assert_eq!(
        reader
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/public-search?indexer_id={indexer}&q=stable%20pagination&cursor={tampered}"
                    ))
                    .body(Body::empty())?,
            )
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );

    let mut seen = Vec::new();
    let mut cursor = Some(first_cursor.clone());
    let CanonicalValue::Map(first_result) = &first_results[0] else {
        return Err("search result must be a map".into());
    };
    let CanonicalValue::Text(first_subject) = field(first_result, 2) else {
        return Err("search result subject must be text".into());
    };
    seen.push(first_subject.clone());
    for _ in 0..3 {
        let Some(current) = cursor.take() else {
            break;
        };
        let response = reader
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/public-search?indexer_id={indexer}&q=stable%20pagination&cursor={current}"
                    ))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        cursor = response
            .headers()
            .get("x-dtx-next-cursor")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let page = decode_deterministic_cbor(&to_bytes(response.into_body(), 100_000).await?)?;
        let CanonicalValue::Map(fields) = page else {
            return Err("search page must be a map".into());
        };
        let CanonicalValue::Array(results) = field(&fields, 2) else {
            return Err("search results must be an array".into());
        };
        if results.is_empty() {
            assert!(cursor.is_none());
            break;
        }
        assert_eq!(results.len(), 1);
        let CanonicalValue::Map(result) = &results[0] else {
            return Err("search result must be a map".into());
        };
        let CanonicalValue::Text(subject) = field(result, 2) else {
            return Err("search result subject must be text".into());
        };
        seen.push(subject.clone());
    }
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(
        seen, sorted,
        "equal-rank pages need a stable subject tie-break"
    );
    assert_eq!(seen.len(), 3);
    assert_eq!(seen.iter().collect::<HashSet<_>>().len(), 3);

    let root_before_mutation = reader
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/public-search?indexer_id={indexer}&q=stable%20pagination"
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(root_before_mutation.status(), StatusCode::OK);
    let stale_etag = root_before_mutation
        .headers()
        .get(header::ETAG)
        .ok_or("missing root ETag")?
        .clone();

    let added = descriptor_version_for(44, now, 1, None, false);
    let mut mutation = harness.admin_pool().begin().await?;
    let added_hash = added.entry_hash()?;
    sqlx::query(
        "INSERT INTO directory.index_registrations(tenant_id,registration_id,indexer_id,subject_id,subject_kind,status,descriptor_sequence,descriptor_hash,descriptor_exact_cbor,feed_origin,search_document,created_at_ms,updated_at_ms) VALUES($1,$2,$3,$4,1,2,1,$5,$6,'https://feed.example','stable pagination',$7,$7)",
    )
    .bind(tenant.as_uuid())
    .bind(DirectoryRegistrationId::new().as_uuid())
    .bind(indexer.as_uuid())
    .bind(added.subject_id().to_string())
    .bind(added_hash.as_bytes().as_slice())
    .bind(added.to_deterministic_cbor()?)
    .bind(now)
    .execute(&mut *mutation)
    .await?;
    sqlx::query(
        "UPDATE directory.index_cache_generations SET generation=2,updated_at_ms=$3 WHERE tenant_id=$1 AND indexer_id=$2 AND generation=1",
    )
    .bind(tenant.as_uuid())
    .bind(indexer.as_uuid())
    .bind(now + 1)
    .execute(&mut *mutation)
    .await?;
    mutation.commit().await?;

    assert_eq!(
        reader
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/public-search?indexer_id={indexer}&q=stable%20pagination&cursor={first_cursor}"
                    ))
                    .body(Body::empty())?,
            )
            .await?
            .status(),
        StatusCode::BAD_REQUEST,
        "a cursor from an older durable generation must fail closed"
    );
    let refreshed = reader
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/public-search?indexer_id={indexer}&q=stable%20pagination"
                ))
                .header(header::IF_NONE_MATCH, stale_etag)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        refreshed.status(),
        StatusCode::OK,
        "persistent generation must bypass another process-local cache"
    );
    let refreshed = decode_deterministic_cbor(&to_bytes(refreshed.into_body(), 100_000).await?)?;
    let CanonicalValue::Map(fields) = refreshed else {
        return Err("refreshed page must be a map".into());
    };
    let CanonicalValue::Array(results) = field(&fields, 2) else {
        return Err("refreshed results must be an array".into());
    };
    assert_eq!(results.len(), 4);
    Ok(())
}
