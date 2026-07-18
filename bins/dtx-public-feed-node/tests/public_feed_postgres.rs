#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use dtx_domain::{ChannelId, DeviceId, EventId, IdentityId, PublicSubjectId, TenantId};
use dtx_federated_identity::FederatedIdentityError;
use dtx_public_descriptor::{
    PUBLIC_DESCRIPTOR_WIRE_VERSION, PublicDescriptorKindV1, PublicDescriptorPayloadV1,
    SignedPublicDescriptorV1, UnsignedPublicDescriptorV1,
};
use dtx_public_discussion::{
    DiscussionAcceptancePolicyV1, ReactionKindV1, ReactionTargetKindV1, SignedCommentEventV1,
    SignedDiscussionPolicyV1, SignedReactionEventV1, UnsignedCommentEventV1,
    UnsignedDiscussionPolicyV1, UnsignedReactionEventV1,
};
use dtx_public_feed::{PublicFeedPayloadV1, SignedPublicFeedEventV1, UnsignedPublicFeedEventV1};
use dtx_public_feed_node::{
    DESCRIPTOR_CONTENT_TYPE, DeviceAuthority, EVENT_CONTENT_TYPE, PublicDiscussionRouterConfig,
    PublicFeedPgStore, public_feed_router, public_feed_router_with_discussion,
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
fn lower_hex_digest(value: Sha256Digest) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in value.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("write digest");
    }
    encoded
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
    let idempotency_key = format!(
        "test-{}",
        Sha256Digest::hash_domain(b"public-feed-test-idempotency.v1\0", &body)
    );
    write_request_with_key(method, path, content_type, body, now, &idempotency_key)
}
fn write_request_with_key(
    method: &str,
    path: &str,
    content_type: &str,
    body: Vec<u8>,
    now: i64,
    idempotency_key: &str,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, content_type)
        .header("x-dtx-deadline-ms", (now + 30_000).to_string())
        .header("idempotency-key", idempotency_key)
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
    let first_append = app.clone().oneshot(write_request(
        "POST",
        &feed,
        EVENT_CONTENT_TYPE,
        second_bytes.clone(),
        now,
    ));
    let concurrent_replay = replica.clone().oneshot(write_request(
        "POST",
        &feed,
        EVENT_CONTENT_TYPE,
        second_bytes.clone(),
        now,
    ));
    let (first_append, concurrent_replay) = tokio::join!(first_append, concurrent_replay);
    let statuses = [first_append?.status(), concurrent_replay?.status()];
    assert!(
        statuses == [StatusCode::CREATED, StatusCode::OK]
            || statuses == [StatusCode::OK, StatusCode::CREATED],
        "concurrent requests with one exact idempotency key must create once and replay once: {statuses:?}",
    );
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
    assert_eq!(forced, 19);
    Ok(())
}

#[derive(Clone)]
struct TestDeviceAuthority {
    key: SigningPublicKey,
    active: Arc<AtomicBool>,
}
impl DeviceAuthority for TestDeviceAuthority {
    fn active_device_signing_key<'a>(
        &'a self,
        _origin: &'a str,
        _identity_id: IdentityId,
        _device_id: DeviceId,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, FederatedIdentityError>> + Send + 'a>>
    {
        Box::pin(async move {
            if self.active.load(Ordering::SeqCst) {
                Ok(self.key)
            } else {
                Err(FederatedIdentityError::DeviceUnavailable)
            }
        })
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn policy_comments_replies_likes_and_exact_replay_are_origin_hosted()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    let tenant = TenantId::new();
    let store = PublicFeedPgStore::from_prevalidated_pool(harness.admin_pool().clone());
    let actor_key = SigningKey::from_bytes(&[77; 32]);
    let actor_public = public_key(&actor_key);
    let active = Arc::new(AtomicBool::new(true));
    let app = public_feed_router_with_discussion(
        store,
        tenant,
        PublicDiscussionRouterConfig::new(Arc::new(TestDeviceAuthority {
            key: actor_public,
            active: active.clone(),
        })),
    );
    let now = now_ms();
    let descriptor = descriptor(now);
    let subject = descriptor.subject_id();
    let root = format!("/.well-known/dirextalk/public/v1/{subject}");
    let feed = format!("{root}/feed");
    assert_eq!(
        app.clone()
            .oneshot(write_request(
                "PUT",
                &root,
                DESCRIPTOR_CONTENT_TYPE,
                descriptor.to_deterministic_cbor()?,
                now,
            ))
            .await?
            .status(),
        StatusCode::CREATED
    );
    let post = event(
        subject,
        1,
        None,
        PublicFeedPayloadV1::Post {
            body: "discussion post".to_owned(),
            attachments: vec![],
        },
        now,
    );
    assert_eq!(
        app.clone()
            .oneshot(write_request(
                "POST",
                &feed,
                EVENT_CONTENT_TYPE,
                post.to_deterministic_cbor()?,
                now,
            ))
            .await?
            .status(),
        StatusCode::CREATED
    );
    let post_hash = post.entry_hash()?;
    let post_hash_path = lower_hex_digest(post_hash);
    let owner_key = signing_key();
    let owner_public = public_key(&owner_key);
    let policy_unsigned = UnsignedDiscussionPolicyV1::new(
        subject,
        IdentityId::derive(owner_public.as_domain_key()),
        owner_public,
        SafeUint::new(1)?,
        None,
        DiscussionAcceptancePolicyV1::VerifiedIdentity,
        UtcMillis::new(now)?,
    )?;
    let policy = SignedDiscussionPolicyV1::signed(
        policy_unsigned.clone(),
        Ed25519Signature::from_bytes(
            owner_key
                .sign(&policy_unsigned.signature_input()?)
                .to_bytes(),
        ),
    )?;
    let policy_path = format!("{root}/discussion-policy");
    assert_eq!(
        app.clone()
            .oneshot(write_request_with_key(
                "PUT",
                &policy_path,
                "application/vnd.dirextalk.public-discussion-policy.v1+cbor",
                policy.to_deterministic_cbor()?,
                now,
                "discussion-policy-0001",
            ))
            .await?
            .status(),
        StatusCode::CREATED
    );
    let policy_get = app
        .clone()
        .oneshot(Request::builder().uri(&policy_path).body(Body::empty())?)
        .await?;
    assert_eq!(policy_get.status(), StatusCode::OK);
    assert!(policy_get.headers().contains_key(header::ETAG));

    let actor_identity = IdentityId::derive(actor_public.as_domain_key());
    let actor_device: DeviceId = "0190f2a5-7b41-7abc-8def-0123456789ab".parse()?;
    let comments_path = format!("{root}/posts/{post_hash_path}/comments");
    let reactions_path = format!("{root}/posts/{post_hash_path}/reactions");
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{comments_path}?limit=1"))
                    .body(Body::empty())?,
            )
            .await?
            .status(),
        StatusCode::NOT_FOUND,
        "an existing post without a comment thread has the stable empty/404 contract",
    );
    let empty_projection = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "{reactions_path}?target_kind=post&target_hash={post_hash_path}&kind=like"
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(empty_projection.status(), StatusCode::OK);
    assert!(empty_projection.headers().contains_key(header::ETAG));
    let missing_comment_hash = Sha256Digest::from_bytes([0xab; 32]);
    let missing_comment_hash = lower_hex_digest(missing_comment_hash);
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "{reactions_path}?target_kind=comment&target_hash={missing_comment_hash}&kind=like"
                    ))
                    .body(Body::empty())?,
            )
            .await?
            .status(),
        StatusCode::NOT_FOUND,
    );
    let make_comment = |event_id: &str,
                        parent: Option<Sha256Digest>,
                        body: &str|
     -> Result<SignedCommentEventV1, Box<dyn std::error::Error>> {
        let unsigned = UnsignedCommentEventV1::new(
            event_id.parse::<EventId>()?,
            subject,
            post_hash,
            parent,
            body.to_owned(),
            actor_identity,
            actor_device,
            "https://identity.example".to_owned(),
            SafeUint::new(1)?,
            policy.policy_digest()?,
            UtcMillis::new(now + 1)?,
        )?;
        Ok(SignedCommentEventV1::signed(
            unsigned.clone(),
            Ed25519Signature::from_bytes(actor_key.sign(&unsigned.signature_input()?).to_bytes()),
            actor_public,
        )?)
    };
    let comment = make_comment("0190f2a5-7b42-7abc-8def-0123456789ab", None, "first")?;
    let comment_exact = comment.to_deterministic_cbor()?;
    let comment_key = "discussion-comment-0001";
    let first_comment = app.clone().oneshot(write_request_with_key(
        "POST",
        &comments_path,
        "application/vnd.dirextalk.public-comment.v1+cbor",
        comment_exact.clone(),
        now,
        comment_key,
    ));
    let concurrent_replay = app.clone().oneshot(write_request_with_key(
        "POST",
        &comments_path,
        "application/vnd.dirextalk.public-comment.v1+cbor",
        comment_exact.clone(),
        now,
        comment_key,
    ));
    let (first_comment, concurrent_replay) = tokio::join!(first_comment, concurrent_replay);
    let first_comment = first_comment?;
    let concurrent_replay = concurrent_replay?;
    let statuses = [first_comment.status(), concurrent_replay.status()];
    assert!(
        statuses == [StatusCode::CREATED, StatusCode::OK]
            || statuses == [StatusCode::OK, StatusCode::CREATED],
        "concurrent discussion requests with one exact idempotency key must create once and replay once: {statuses:?}",
    );
    let first_receipt = to_bytes(first_comment.into_body(), 65_536).await?.to_vec();
    let concurrent_body = to_bytes(concurrent_replay.into_body(), 65_536)
        .await?
        .to_vec();
    assert_eq!(first_receipt, concurrent_body);
    let first_receipt = dtx_public_discussion::CommentReceiptV1::decode(&first_receipt)?;

    active.store(false, Ordering::SeqCst);
    assert_eq!(
        app.clone()
            .oneshot(write_request_with_key(
                "POST",
                &comments_path,
                "application/vnd.dirextalk.public-comment.v1+cbor",
                comment_exact,
                now,
                comment_key,
            ))
            .await?
            .status(),
        StatusCode::OK,
        "receipt lookup must precede later device revocation"
    );
    let conflicting = make_comment("0190f2a5-7b43-7abc-8def-0123456789ab", None, "different")?;
    assert_eq!(
        app.clone()
            .oneshot(write_request_with_key(
                "POST",
                &comments_path,
                "application/vnd.dirextalk.public-comment.v1+cbor",
                conflicting.to_deterministic_cbor()?,
                now,
                comment_key,
            ))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.clone()
            .oneshot(write_request_with_key(
                "POST",
                &comments_path,
                "application/vnd.dirextalk.public-comment.v1+cbor",
                conflicting.to_deterministic_cbor()?,
                now,
                "discussion-comment-0002",
            ))
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    active.store(true, Ordering::SeqCst);
    let reply = make_comment(
        "0190f2a5-7b44-7abc-8def-0123456789ab",
        Some(first_receipt.thread_entry_hash()),
        "reply",
    )?;
    let reply_response = app
        .clone()
        .oneshot(write_request_with_key(
            "POST",
            &comments_path,
            "application/vnd.dirextalk.public-comment.v1+cbor",
            reply.to_deterministic_cbor()?,
            now,
            "discussion-comment-0003",
        ))
        .await?;
    assert_eq!(reply_response.status(), StatusCode::CREATED);
    let reply_receipt = dtx_public_discussion::CommentReceiptV1::decode(
        &to_bytes(reply_response.into_body(), 65_536).await?,
    )?;
    let over_depth = make_comment(
        "0190f2a5-7b45-7abc-8def-0123456789ab",
        Some(reply_receipt.thread_entry_hash()),
        "too deep",
    )?;
    assert_eq!(
        app.clone()
            .oneshot(write_request_with_key(
                "POST",
                &comments_path,
                "application/vnd.dirextalk.public-comment.v1+cbor",
                over_depth.to_deterministic_cbor()?,
                now,
                "discussion-comment-0004",
            ))
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );

    let reaction_unsigned = UnsignedReactionEventV1::new(
        "0190f2a5-7b46-7abc-8def-0123456789ab".parse::<EventId>()?,
        subject,
        post_hash,
        ReactionTargetKindV1::Post,
        post_hash,
        ReactionKindV1::Like,
        true,
        SafeUint::new(1)?,
        None,
        actor_identity,
        actor_device,
        "https://identity.example".to_owned(),
        SafeUint::new(1)?,
        policy.policy_digest()?,
        UtcMillis::new(now + 2)?,
    )?;
    let reaction = SignedReactionEventV1::signed(
        reaction_unsigned.clone(),
        Ed25519Signature::from_bytes(
            actor_key
                .sign(&reaction_unsigned.signature_input()?)
                .to_bytes(),
        ),
        actor_public,
    )?;
    assert_eq!(
        app.clone()
            .oneshot(write_request_with_key(
                "POST",
                &reactions_path,
                "application/vnd.dirextalk.public-reaction.v1+cbor",
                reaction.to_deterministic_cbor()?,
                now,
                "discussion-reaction-0001",
            ))
            .await?
            .status(),
        StatusCode::CREATED
    );
    let unlike_unsigned = UnsignedReactionEventV1::new(
        "0190f2a5-7b47-7abc-8def-0123456789ab".parse::<EventId>()?,
        subject,
        post_hash,
        ReactionTargetKindV1::Post,
        post_hash,
        ReactionKindV1::Like,
        false,
        SafeUint::new(2)?,
        Some(reaction.event_digest()?),
        actor_identity,
        actor_device,
        "https://identity.example".to_owned(),
        SafeUint::new(1)?,
        policy.policy_digest()?,
        UtcMillis::new(now + 3)?,
    )?;
    let unlike = SignedReactionEventV1::signed(
        unlike_unsigned.clone(),
        Ed25519Signature::from_bytes(
            actor_key
                .sign(&unlike_unsigned.signature_input()?)
                .to_bytes(),
        ),
        actor_public,
    )?;
    assert_eq!(
        app.clone()
            .oneshot(write_request_with_key(
                "POST",
                &reactions_path,
                "application/vnd.dirextalk.public-reaction.v1+cbor",
                unlike.to_deterministic_cbor()?,
                now,
                "discussion-reaction-0002",
            ))
            .await?
            .status(),
        StatusCode::CREATED
    );
    let projection = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "{reactions_path}?target_kind=post&target_hash={post_hash_path}&kind=like"
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(projection.status(), StatusCode::OK);
    assert!(projection.headers().contains_key(header::ETAG));
    let page = app
        .oneshot(Request::builder().uri(&comments_path).body(Body::empty())?)
        .await?;
    assert_eq!(page.status(), StatusCode::OK);
    assert!(page.headers().contains_key(header::ETAG));
    Ok(())
}
