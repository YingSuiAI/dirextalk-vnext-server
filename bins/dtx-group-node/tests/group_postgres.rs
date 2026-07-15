#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{
    error::Error,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{
    Clock, ClockError, ConversationId, DeviceId, DeviceSessionId, IdentityId, InviteCapabilityId,
    JoinRequestId, RequestId, Revision, TenantId,
};
use dtx_group_node::{
    DEVICE_SESSION_AUTHORIZATION_SCHEME, GROUP_ACTION_RECEIPT_CONTENT_TYPE,
    GROUP_APPROVE_JOIN_CONTENT_TYPE, GROUP_APPROVE_JOIN_V2_CONTENT_TYPE, GROUP_CREATE_CONTENT_TYPE,
    GROUP_ISSUE_INVITE_CONTENT_TYPE, GROUP_JOIN_REQUEST_CONTENT_TYPE,
    GROUP_JOIN_REQUEST_PAGE_CONTENT_TYPE, GROUP_JOIN_REQUEST_PAGE_V2_CONTENT_TYPE,
    GROUP_JOIN_REQUEST_V2_CONTENT_TYPE, GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE,
    GROUP_QUERY_PROOF_HEADER, GROUP_SCOPE_PATH_TEMPLATE, GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE,
    GROUP_SERVICE_DESCRIPTOR_PATH, GroupNodeState, IDENTITY_ORIGIN_HEADER,
    MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE, MLS_COMMIT_CONTENT_TYPE, MLS_COMMIT_FEED_CONTENT_TYPE,
    MLS_COMMIT_RECEIPT_CONTENT_TYPE, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE,
    MLS_COMMIT_V3_CONTENT_TYPE, MLS_CONFIRMATION_PROOF_HEADER, MLS_CONFIRMATION_V3_CONTENT_TYPE,
    RECEIPT_QUERY_PROOF_HEADER, group_router_with_state,
};
use dtx_group_persistence::{
    GroupControlCommand, GroupControlDisposition, GroupControlOperation, GroupControlRejection,
    GroupControlRepository, GroupMembershipRepository, GroupPgStore,
    MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, MlsCommitAuthorization, MlsCommitCommand,
    MlsDeviceJoinConfirmation, mls_candidate_proof_digest, mls_candidate_proof_signature_input,
    mls_device_confirmation_signature_input, mls_opaque_commit_digest,
};
use dtx_group_policy::GroupScope;
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_node::identity_bootstrap_router;
use dtx_identity_persistence::{
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceSessionCompletionCommand, DeviceSessionOutcome,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogRepository,
    IdentityPgStore, device_session_proof_input,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, Sha256Digest, SigningPublicKey, UtcMillis,
    decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::postgres::PgConnectOptions;
use tower::ServiceExt;

const AUDIENCE: &str = "https://group.test";
const NOW: i64 = 2_000;
const IDEMPOTENCY_HASH_DOMAIN: &[u8] = b"dirextalk.membership-idempotency-key.v1\0";
const BUSINESS_FIELDS_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-business-fields.v1\0";
const ACTION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-binding.v1\0";
const ACTION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-action-signature.v1\0";
const FEDERATED_ACTION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-binding.v2\0";
const FEDERATED_ACTION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-action-signature.v2\0";
const GROUP_QUERY_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.group-query-binding.v1\0";
const GROUP_QUERY_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.group-query-signature.v1\0";
const MLS_CONFIRMATION_BODY_HASH_DOMAIN: &[u8] = b"dirextalk.mls-confirmation-body.v3\0";
const MLS_CONFIRMATION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.mls-confirmation-binding.v3\0";
const MLS_CONFIRMATION_PROOF_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.mls-confirmation-proof-signature.v3\0";

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn remote_owner_admin_and_candidate_use_fresh_identity_logs_without_session_forwarding()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let owner = enroll_active_device(&identity_store, 51, 52, 53, [54; 32]).await?;
    let admin = enroll_active_device(&identity_store, 61, 62, 63, [64; 32]).await?;
    let candidate = enroll_active_device(&identity_store, 71, 72, 73, [74; 32]).await?;
    let (admin_origin, admin_server) = start_identity_log_server(identity_store.clone()).await?;
    let (candidate_origin, candidate_server) =
        start_identity_log_server(identity_store.clone()).await?;
    let tenant_id = TenantId::new();
    let state =
        GroupNodeState::with_clock(group_store.clone(), tenant_id, Arc::new(FixedClock(NOW)))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                [admin_origin.clone(), candidate_origin.clone()],
            )?;
    let app = group_router_with_state(state);
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_key = "federated-group-create-0001";
    let create = send_mutation(
        app.clone(),
        "PUT",
        &scope_path,
        GROUP_CREATE_CONTENT_TYPE,
        create_key,
        &owner,
        create_body(&owner, scope, &scope_path, create_key, 1_000)?,
    )
    .await?;
    assert_eq!(create.status(), StatusCode::CREATED);

    let grant_path = format!("{scope_path}/admins/{}", admin.identity_id);
    let grant_key = "federated-grant-admin-0001";
    let grant = send_mutation(
        app.clone(),
        "PUT",
        &grant_path,
        "application/vnd.dirextalk.group-grant-admin.v1+cbor",
        grant_key,
        &owner,
        grant_admin_body(
            &owner,
            scope,
            &grant_path,
            grant_key,
            1_000,
            Revision::INITIAL,
            admin.identity_id,
        )?,
    )
    .await?;
    assert_eq!(grant.status(), StatusCode::CREATED);

    let invite_id = InviteCapabilityId::new();
    let invite_path = format!("{scope_path}/invites/{invite_id}");
    let invite_key = "federated-admin-invite-0001";
    let invite_body = federated_issue_invite_body(
        &admin,
        &admin_origin,
        scope,
        &invite_path,
        invite_key,
        1_000,
        Revision::new(2)?,
        Some(candidate.identity_id),
        1,
        10_000,
    )?;
    let invite = send_federated_mutation(
        app.clone(),
        "PUT",
        &invite_path,
        GROUP_ISSUE_INVITE_CONTENT_TYPE,
        invite_key,
        &admin_origin,
        invite_body,
    )
    .await?;
    assert_eq!(invite.status(), StatusCode::CREATED);

    let join_request_id = JoinRequestId::new();
    let join_command_id = RequestId::new();
    let join_path = format!("{scope_path}/join-requests/{join_request_id}");
    let join_key = "federated-candidate-join-0001";
    let join_body = federated_join_request_body(
        &candidate,
        &candidate_origin,
        scope,
        &join_path,
        join_key,
        1_000,
        join_command_id,
        invite_id,
        Revision::new(3)?,
        Sha256Digest::hash_domain(b"test-group-head\0", b"federated-join"),
    )?;
    let join = send_federated_mutation(
        app.clone(),
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_CONTENT_TYPE,
        join_key,
        &candidate_origin,
        join_body.clone(),
    )
    .await?;
    assert_eq!(join.status(), StatusCode::ACCEPTED);
    assert_membership_phase(&response_bytes(join).await?, 1)?;
    let join_receipt_path = format!("{scope_path}/membership-receipts/{join_command_id}");
    let recovered_join = send_federated_get(
        app.clone(),
        &join_receipt_path,
        &candidate_origin,
        receipt_query_proof(
            &candidate,
            &candidate_origin,
            scope,
            &join_receipt_path,
            join_command_id,
            1_500,
        )?,
    )
    .await?;
    assert_eq!(recovered_join.status(), StatusCode::OK);
    assert_membership_phase(&response_bytes(recovered_join).await?, 1)?;

    let approval_path = format!("{join_path}/approvals");
    let approval_key = "federated-admin-approval-0001";
    let approval = send_federated_mutation(
        app.clone(),
        "POST",
        &approval_path,
        GROUP_APPROVE_JOIN_CONTENT_TYPE,
        approval_key,
        &admin_origin,
        federated_approve_join_body(
            &admin,
            &admin_origin,
            scope,
            &approval_path,
            approval_key,
            1_000,
            RequestId::new(),
            candidate.identity_id,
            candidate.device_id,
            invite_id,
            Revision::new(4)?,
            Sha256Digest::hash_domain(b"test-group-head\0", b"federated-approval"),
        )?,
    )
    .await?;
    assert_eq!(approval.status(), StatusCode::ACCEPTED);
    assert_membership_phase(&response_bytes(approval).await?, 2)?;

    revoke_device(&identity_store, &candidate, 30_000).await?;
    let revoked_replay = send_federated_mutation(
        app,
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_CONTENT_TYPE,
        join_key,
        &candidate_origin,
        join_body,
    )
    .await?;
    assert_eq!(revoked_replay.status(), StatusCode::UNAUTHORIZED);

    admin_server.abort();
    candidate_server.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn owner_admin_discovery_is_bound_paged_cached_and_restart_safe() -> Result<(), Box<dyn Error>>
{
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let untrusted_http_public_origin = "http://group.test";
    assert!(
        GroupNodeState::with_clock(
            group_store.clone(),
            TenantId::new(),
            Arc::new(FixedClock(NOW)),
        )
        .with_public_origin_and_allowed_http_identity_origins(untrusted_http_public_origin, [])
        .is_err()
    );
    assert!(
        GroupNodeState::with_clock(
            group_store.clone(),
            TenantId::new(),
            Arc::new(FixedClock(NOW)),
        )
        .with_public_origin_and_allowed_http_identity_origins(
            untrusted_http_public_origin,
            ["http://other.test".to_owned()],
        )
        .is_err()
    );
    assert!(
        GroupNodeState::with_clock(
            group_store.clone(),
            TenantId::new(),
            Arc::new(FixedClock(NOW)),
        )
        .with_public_origin_and_allowed_http_identity_origins(
            untrusted_http_public_origin,
            [untrusted_http_public_origin.to_owned()],
        )
        .is_ok()
    );
    let owner = enroll_active_device(&identity_store, 81, 82, 83, [84; 32]).await?;
    let remote_admin = enroll_active_device(&identity_store, 85, 86, 87, [88; 32]).await?;
    let local_candidate = enroll_active_device(&identity_store, 89, 90, 91, [92; 32]).await?;
    let remote_candidate = enroll_active_device(&identity_store, 93, 94, 95, [96; 32]).await?;
    let ordinary_member = enroll_active_device(&identity_store, 97, 98, 99, [100; 32]).await?;
    let (remote_origin, identity_server) = start_identity_log_server(identity_store).await?;
    let tenant_id = TenantId::new();
    let sequencer_key = SigningKey::from_bytes(&[101; 32]);
    let build_state = || {
        GroupNodeState::with_clock(group_store.clone(), tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(sequencer_key.clone())
            .with_public_origin_and_allowed_http_identity_origins(AUDIENCE, [remote_origin.clone()])
    };
    let app = group_router_with_state(build_state()?);
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let descriptor = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(GROUP_SERVICE_DESCRIPTOR_PATH)
                .header(header::HOST, "attacker.invalid")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(descriptor.status(), StatusCode::OK);
    assert_content_type(&descriptor, GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE);
    assert_eq!(
        descriptor
            .headers()
            .get(header::CACHE_CONTROL)
            .ok_or("descriptor cache policy")?,
        "public, max-age=60, stale-while-revalidate=300"
    );
    let descriptor_etag = descriptor
        .headers()
        .get(header::ETAG)
        .ok_or("descriptor ETag")?
        .clone();
    let descriptor_value = decode_deterministic_cbor(&response_bytes(descriptor).await?)?;
    let CanonicalValue::Map(descriptor_fields) = descriptor_value else {
        return Err("descriptor must be a canonical map".into());
    };
    assert_eq!(
        descriptor_fields[1].1,
        CanonicalValue::Text(AUDIENCE.to_owned())
    );
    let not_modified = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(GROUP_SERVICE_DESCRIPTOR_PATH)
                .header(header::HOST, "different.invalid")
                .header(header::IF_NONE_MATCH, descriptor_etag)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

    let create_key = "discovery-create-0001";
    assert_eq!(
        send_mutation(
            app.clone(),
            "PUT",
            &scope_path,
            GROUP_CREATE_CONTENT_TYPE,
            create_key,
            &owner,
            create_body(&owner, scope, &scope_path, create_key, 1_000)?,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    let grant_path = format!("{scope_path}/admins/{}", remote_admin.identity_id);
    let grant_key = "discovery-grant-admin-0001";
    assert_eq!(
        send_mutation(
            app.clone(),
            "PUT",
            &grant_path,
            "application/vnd.dirextalk.group-grant-admin.v1+cbor",
            grant_key,
            &owner,
            grant_admin_body(
                &owner,
                scope,
                &grant_path,
                grant_key,
                1_000,
                Revision::INITIAL,
                remote_admin.identity_id,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );

    let local_invite = InviteCapabilityId::new();
    let local_invite_path = format!("{scope_path}/invites/{local_invite}");
    let local_invite_key = "discovery-local-invite-0001";
    assert_eq!(
        send_mutation(
            app.clone(),
            "PUT",
            &local_invite_path,
            GROUP_ISSUE_INVITE_CONTENT_TYPE,
            local_invite_key,
            &owner,
            issue_invite_body(
                &owner,
                scope,
                &local_invite_path,
                local_invite_key,
                1_000,
                Revision::new(2)?,
                Some(local_candidate.identity_id),
                1,
                10_000,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    let local_join_id = JoinRequestId::new();
    let local_join_path = format!("{scope_path}/join-requests/{local_join_id}");
    let local_join_key = "discovery-local-join-0001";
    assert_eq!(
        send_mutation(
            app.clone(),
            "PUT",
            &local_join_path,
            GROUP_JOIN_REQUEST_CONTENT_TYPE,
            local_join_key,
            &local_candidate,
            join_request_body(
                &local_candidate,
                scope,
                &local_join_path,
                local_join_key,
                1_000,
                RequestId::new(),
                local_invite,
                Revision::new(3)?,
                Sha256Digest::hash_domain(b"test-group-head\0", b"discovery-local"),
            )?,
        )
        .await?
        .status(),
        StatusCode::ACCEPTED
    );

    let remote_invite = InviteCapabilityId::new();
    let remote_invite_path = format!("{scope_path}/invites/{remote_invite}");
    let remote_invite_key = "discovery-remote-invite-0001";
    assert_eq!(
        send_mutation(
            app.clone(),
            "PUT",
            &remote_invite_path,
            GROUP_ISSUE_INVITE_CONTENT_TYPE,
            remote_invite_key,
            &owner,
            issue_invite_body(
                &owner,
                scope,
                &remote_invite_path,
                remote_invite_key,
                1_000,
                Revision::new(4)?,
                Some(remote_candidate.identity_id),
                1,
                10_000,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    let remote_join_id = JoinRequestId::new();
    let remote_join_path = format!("{scope_path}/join-requests/{remote_join_id}");
    let remote_join_key = "discovery-remote-join-0001";
    assert_eq!(
        send_federated_mutation(
            app.clone(),
            "PUT",
            &remote_join_path,
            GROUP_JOIN_REQUEST_CONTENT_TYPE,
            remote_join_key,
            &remote_origin,
            federated_join_request_body(
                &remote_candidate,
                &remote_origin,
                scope,
                &remote_join_path,
                remote_join_key,
                1_000,
                RequestId::new(),
                remote_invite,
                Revision::new(5)?,
                Sha256Digest::hash_domain(b"test-group-head\0", b"discovery-remote"),
            )?,
        )
        .await?
        .status(),
        StatusCode::ACCEPTED
    );

    let first_target = format!("{scope_path}/join-requests?after=&limit=1");
    let first = send_group_query(
        app.clone(),
        &first_target,
        &remote_admin,
        &remote_origin,
        true,
        group_query_proof(&remote_admin, &remote_origin, scope, &first_target, 1_000)?,
    )
    .await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_content_type(&first, GROUP_JOIN_REQUEST_PAGE_CONTENT_TYPE);
    let (mut discovered, next_after) = decode_discovery_page(&response_bytes(first).await?)?;
    let next_after = next_after.ok_or("first discovery page must continue")?;

    let tampered_target = format!("{scope_path}/join-requests?after=&limit=2");
    let tampered = send_group_query(
        app.clone(),
        &tampered_target,
        &remote_admin,
        &remote_origin,
        true,
        group_query_proof(&remote_admin, &remote_origin, scope, &first_target, 1_000)?,
    )
    .await?;
    assert_eq!(tampered.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let second_target = format!("{scope_path}/join-requests?after={next_after}&limit=1");
    let second = send_group_query(
        app.clone(),
        &second_target,
        &remote_admin,
        &remote_origin,
        true,
        group_query_proof(&remote_admin, &remote_origin, scope, &second_target, 1_100)?,
    )
    .await?;
    let (second_items, second_next) = decode_discovery_page(&response_bytes(second).await?)?;
    assert!(second_next.is_none());
    discovered.extend(second_items);
    discovered.sort();
    let mut expected = vec![
        (local_join_id.to_string(), AUDIENCE.to_owned()),
        (remote_join_id.to_string(), remote_origin.clone()),
    ];
    expected.sort();
    assert_eq!(discovered, expected);

    let restarted = group_router_with_state(build_state()?);
    let restart_target = format!("{scope_path}/join-requests?after=&limit=64");
    let restart_page = send_group_query(
        restarted.clone(),
        &restart_target,
        &owner,
        AUDIENCE,
        false,
        group_query_proof(&owner, AUDIENCE, scope, &restart_target, 1_200)?,
    )
    .await?;
    assert_eq!(restart_page.status(), StatusCode::OK);
    assert_eq!(
        decode_discovery_page(&response_bytes(restart_page).await?)?
            .0
            .len(),
        2
    );

    let scope_id = scope_path.rsplit('/').next().ok_or("scope id")?;
    let persisted_origins: Vec<String> = sqlx::query_scalar(
        "SELECT candidate_identity_origin
           FROM groups.membership_workflows
          WHERE tenant_id=$1 AND scope_kind='private_conversation' AND scope_id=$2
          ORDER BY candidate_identity_origin",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .bind(scope_id)
    .fetch_all(harness.admin_pool())
    .await?;
    let mut expected_origins = vec![AUDIENCE.to_owned(), remote_origin.clone()];
    expected_origins.sort();
    assert_eq!(persisted_origins, expected_origins);

    sqlx::query(
        "INSERT INTO groups.members
             (tenant_id, scope_kind, scope_id, identity_id, admitted_at_ms)
         VALUES ($1, 'private_conversation', $2, $3, $4)",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .bind(scope_id)
    .bind(ordinary_member.identity_id.to_string())
    .bind(NOW)
    .execute(harness.admin_pool())
    .await?;
    let member_denied = send_group_query(
        restarted.clone(),
        &restart_target,
        &ordinary_member,
        AUDIENCE,
        false,
        group_query_proof(&ordinary_member, AUDIENCE, scope, &restart_target, 1_300)?,
    )
    .await?;
    assert_eq!(member_denied.status(), StatusCode::FORBIDDEN);

    sqlx::query(
        "UPDATE groups.membership_workflows
            SET candidate_identity_origin=NULL
          WHERE tenant_id=$1 AND scope_kind='private_conversation' AND scope_id=$2
            AND request_id=$3",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .bind(scope_id)
    .bind(uuid::Uuid::from(local_join_id))
    .execute(harness.admin_pool())
    .await?;
    let historical_unavailable = send_group_query(
        restarted,
        &restart_target,
        &remote_admin,
        &remote_origin,
        true,
        group_query_proof(&remote_admin, &remote_origin, scope, &restart_target, 1_400)?,
    )
    .await?;
    assert_eq!(
        historical_unavailable.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    identity_server.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn active_member_fetches_exact_consecutive_v30_commit_feed_without_welcome()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 6).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let owner = enroll_active_device(&identity_store, 111, 112, 113, [114; 32]).await?;
    let member = enroll_active_device(&identity_store, 115, 116, 117, [118; 32]).await?;
    let peer = enroll_active_device(&identity_store, 119, 120, 121, [122; 32]).await?;
    let outsider = enroll_active_device(&identity_store, 123, 124, 125, [126; 32]).await?;
    let tenant_id = TenantId::new();
    let app = group_router_with_state(
        GroupNodeState::with_clock(group_store.clone(), tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(SigningKey::from_bytes(&[127; 32]))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                std::iter::empty::<String>(),
            )?,
    );
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_key = "commit-feed-create-0001";
    let create = send_mutation(
        app.clone(),
        "PUT",
        &scope_path,
        GROUP_CREATE_CONTENT_TYPE,
        create_key,
        &owner,
        create_body(&owner, scope, &scope_path, create_key, 1_000)?,
    )
    .await?;
    assert_eq!(create.status(), StatusCode::CREATED);

    let bootstrap_submission = RequestId::new();
    let bootstrap_path = format!("{scope_path}/mls-commits/{bootstrap_submission}");
    let bootstrap_key = "commit-feed-bootstrap-0001";
    let bootstrap = send_mutation(
        app.clone(),
        "POST",
        &bootstrap_path,
        MLS_COMMIT_CONTENT_TYPE,
        bootstrap_key,
        &owner,
        mls_commit_body(
            &owner,
            &owner,
            scope,
            bootstrap_submission,
            bootstrap_key,
            0,
            Sha256Digest::from_bytes([0; 32]),
            vec![0x41; 48],
            MlsCommitAuthorization::OwnerBootstrap,
        )?,
    )
    .await?;
    assert_eq!(bootstrap.status(), StatusCode::CREATED);
    let bootstrap_head = mls_receipt_head(&response_bytes(bootstrap).await?)?;

    let (member_receipt, member_head) = admit_local_v30_member(
        app.clone(),
        &owner,
        &member,
        scope,
        &scope_path,
        Revision::INITIAL,
        1,
        bootstrap_head,
        vec![0x52; 48],
        "commit-feed-member",
    )
    .await?;
    assert_eq!(mls_receipt_epoch(&member_receipt)?, 2);
    let next_revision = GroupMembershipRepository
        .load_policy(&group_store, tenant_id, scope)
        .await?
        .revision();
    let peer_commit = vec![0x63; 48];
    let (peer_receipt, _) = admit_local_v30_member(
        app.clone(),
        &owner,
        &peer,
        scope,
        &scope_path,
        next_revision,
        2,
        member_head,
        peer_commit.clone(),
        "commit-feed-peer",
    )
    .await?;
    assert_eq!(mls_receipt_epoch(&peer_receipt)?, 3);

    let target = format!("{scope_path}/mls-commits?after_epoch=2&limit=64");
    let feed = send_local_commit_feed(
        app.clone(),
        &target,
        &member,
        group_query_proof_for_action(&member, AUDIENCE, scope, &target, 2, 1_100)?,
    )
    .await?;
    assert_eq!(feed.status(), StatusCode::OK);
    assert_content_type(&feed, MLS_COMMIT_FEED_CONTENT_TYPE);
    assert_eq!(
        feed.headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let feed_bytes = response_bytes(feed).await?;
    let items = decode_commit_feed(&feed_bytes, 2)?;
    assert_eq!(items, vec![(peer_receipt.clone(), peer_commit.clone())]);

    let caught_up_target = format!("{scope_path}/mls-commits?after_epoch=3&limit=64");
    let caught_up = send_local_commit_feed(
        app.clone(),
        &caught_up_target,
        &member,
        group_query_proof_for_action(&member, AUDIENCE, scope, &caught_up_target, 2, 1_200)?,
    )
    .await?;
    assert_eq!(caught_up.status(), StatusCode::OK);
    assert!(decode_commit_feed(&response_bytes(caught_up).await?, 3)?.is_empty());

    let denied = send_local_commit_feed(
        app,
        &target,
        &outsider,
        group_query_proof_for_action(&outsider, AUDIENCE, scope, &target, 2, 1_300)?,
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(
        denied
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(MLS_COMMIT_FEED_CONTENT_TYPE)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires the disposable three-node Docker Compose cluster"]
#[allow(clippy::too_many_lines)]
async fn three_node_compose_runs_v30_peer_admission_and_exact_recovery()
-> Result<(), Box<dyn Error>> {
    if std::env::var("DTX_THREE_NODE_COMPOSE_ACCEPTANCE").as_deref() != Ok("1") {
        return Err(
            "set DTX_THREE_NODE_COMPOSE_ACCEPTANCE=1 for the disposable local cluster".into(),
        );
    }

    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let admin_a =
        sqlx::PgPool::connect("postgres://postgres@127.0.0.1:15432/dtx_node_a?sslmode=disable")
            .await?;
    let admin_b =
        sqlx::PgPool::connect("postgres://postgres@127.0.0.1:15432/dtx_node_b?sslmode=disable")
            .await?;
    let admin_c =
        sqlx::PgPool::connect("postgres://postgres@127.0.0.1:15432/dtx_node_c?sslmode=disable")
            .await?;
    for (node, pool) in [("A", &admin_a), ("B", &admin_b), ("C", &admin_c)] {
        let migration_026_applied: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM public._sqlx_migrations
                  WHERE version=202607160026 AND success)",
        )
        .fetch_one(pool)
        .await?;
        assert!(
            migration_026_applied,
            "node {node} must apply migration 026"
        );
    }

    let identity_a = IdentityPgStore::connect(
        PgConnectOptions::from_str(
            "postgres://dtx_identity_node@127.0.0.1:15432/dtx_node_a?sslmode=disable",
        )?,
        2,
    )
    .await?;
    let identity_b = IdentityPgStore::connect(
        PgConnectOptions::from_str(
            "postgres://dtx_identity_node@127.0.0.1:15432/dtx_node_b?sslmode=disable",
        )?,
        2,
    )
    .await?;
    let owner = enroll_active_device_at(&identity_a, 151, 152, 153, [154; 32], now).await?;
    let candidate = enroll_active_device_at(&identity_b, 161, 162, 163, [164; 32], now).await?;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    for (port, expected_origin) in [
        (18_080, "http://node-a:8080"),
        (18_081, "http://node-b:8080"),
        (18_082, "http://node-c:8080"),
    ] {
        let health = client
            .get(format!("http://127.0.0.1:{port}/local-health"))
            .send()
            .await?;
        assert_eq!(health.status(), StatusCode::NO_CONTENT);
        let response = client
            .get(format!(
                "http://127.0.0.1:{port}{GROUP_SERVICE_DESCRIPTOR_PATH}"
            ))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE)
        );
        let CanonicalValue::Map(descriptor) = decode_deterministic_cbor(&response.bytes().await?)?
        else {
            return Err("unified Group Service descriptor must be a map".into());
        };
        assert_eq!(
            descriptor[1].1,
            CanonicalValue::Text(expected_origin.to_owned())
        );
        assert!(matches!(
            &descriptor[5].1,
            CanonicalValue::Bytes(key) if key.len() == 32
        ));
        assert_eq!(descriptor[3].1, CanonicalValue::Unsigned(5));
        assert_eq!(descriptor[4].1, CanonicalValue::Unsigned(64));
    }
    let group_origin = "http://127.0.0.1:18080";
    let candidate_identity_origin = "http://node-b:8080";
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_key = "compose-federated-create-0001";
    let create = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::PUT,
        &scope_path,
        GROUP_CREATE_CONTENT_TYPE,
        create_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
        create_body(&owner, scope, &scope_path, create_key, now)?,
    )
    .await?;
    assert_eq!(create.status(), StatusCode::CREATED);

    let bootstrap_submission = RequestId::new();
    let bootstrap_path = format!("{scope_path}/mls-commits/{bootstrap_submission}");
    let bootstrap_key = "compose-v30-owner-bootstrap-0001";
    let bootstrap = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::POST,
        &bootstrap_path,
        MLS_COMMIT_CONTENT_TYPE,
        bootstrap_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
        mls_commit_body(
            &owner,
            &owner,
            scope,
            bootstrap_submission,
            bootstrap_key,
            0,
            Sha256Digest::from_bytes([0; 32]),
            vec![0x41; 48],
            MlsCommitAuthorization::OwnerBootstrap,
        )?,
    )
    .await?;
    assert_eq!(bootstrap.status(), StatusCode::CREATED);
    assert_eq!(
        bootstrap
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(MLS_COMMIT_RECEIPT_CONTENT_TYPE)
    );
    let bootstrap_head = mls_receipt_head(&bootstrap.bytes().await?)?;

    let invite_id = InviteCapabilityId::new();
    let invite_path = format!("{scope_path}/invites/{invite_id}");
    let invite_key = "compose-federated-invite-0001";
    let invite = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::PUT,
        &invite_path,
        GROUP_ISSUE_INVITE_CONTENT_TYPE,
        invite_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
        issue_invite_body(
            &owner,
            scope,
            &invite_path,
            invite_key,
            now,
            Revision::INITIAL,
            Some(candidate.identity_id),
            1,
            now + 600_000,
        )?,
    )
    .await?;
    assert_eq!(invite.status(), StatusCode::CREATED);

    let join_request_id = JoinRequestId::new();
    let join_command_id = RequestId::new();
    let join_path = format!("{scope_path}/join-requests/{join_request_id}");
    let join_key = "compose-v30-federated-join-0001";
    let candidate_key_package_digest = test_candidate_key_package_digest(&candidate);
    let join = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::PUT,
        &join_path,
        GROUP_JOIN_REQUEST_V2_CONTENT_TYPE,
        join_key,
        None,
        Some(candidate_identity_origin),
        federated_join_request_body_v2(
            &candidate,
            candidate_identity_origin,
            scope,
            &join_path,
            join_key,
            now,
            join_command_id,
            invite_id,
            Revision::new(2)?,
            bootstrap_head,
            candidate_key_package_digest,
        )?,
    )
    .await?;
    assert_eq!(join.status(), StatusCode::ACCEPTED);
    assert_eq!(
        join.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE)
    );
    let join_receipt = join.bytes().await?;
    assert_membership_phase(&join_receipt, 1)?;
    let join_request_digest = membership_receipt_request_digest(&join_receipt)?;

    let approval_command_id = RequestId::new();
    let approval_path = format!("{join_path}/approvals");
    let approval_key = "compose-v30-owner-approval-0001";
    let approval_body = approve_join_body_v2(
        &owner,
        scope,
        &approval_path,
        approval_key,
        now,
        approval_command_id,
        candidate.identity_id,
        candidate.device_id,
        invite_id,
        Revision::new(3)?,
        bootstrap_head,
        candidate_key_package_digest,
    )?;
    let authorization_digest = action_proof_binding_digest(&approval_body)?;
    let approval = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::POST,
        &approval_path,
        GROUP_APPROVE_JOIN_V2_CONTENT_TYPE,
        approval_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
        approval_body,
    )
    .await?;
    assert_eq!(approval.status(), StatusCode::ACCEPTED);
    assert_eq!(
        approval
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE)
    );
    let approval_receipt = approval.bytes().await?;
    assert_membership_phase(&approval_receipt, 2)?;
    let approval_request_digest = membership_receipt_request_digest(&approval_receipt)?;

    let join_submission = RequestId::new();
    let join_commit_path = format!("{scope_path}/mls-commits/{join_submission}");
    let join_commit_key = "compose-v30-approved-join-0001";
    let join_commit_body = mls_commit_body_v3(
        &owner,
        &candidate,
        scope,
        join_submission,
        1,
        bootstrap_head,
        vec![0x52; 48],
        dtx_membership_command::MembershipCommandId::new(approval_command_id),
        authorization_digest,
        join_request_digest,
        approval_request_digest,
        candidate_key_package_digest,
    )?;
    let committed = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::POST,
        &join_commit_path,
        MLS_COMMIT_V3_CONTENT_TYPE,
        join_commit_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
        join_commit_body.clone(),
    )
    .await?;
    assert_eq!(committed.status(), StatusCode::CREATED);
    assert_eq!(
        committed
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE)
    );
    let committed_receipt = committed.bytes().await?.to_vec();

    // Model a lost POST response after GM1 has already committed. The exact
    // replay must converge to the original signed receipt, not an expired
    // invite or missing-application error.
    let recovered_commit = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::POST,
        &join_commit_path,
        MLS_COMMIT_V3_CONTENT_TYPE,
        join_commit_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
        join_commit_body,
    )
    .await?;
    assert_eq!(recovered_commit.status(), StatusCode::OK);
    assert_eq!(recovered_commit.bytes().await?.as_ref(), committed_receipt);

    let (receipt_digest, committed_head) = mls_receipt_facts(&committed_receipt)?;
    let confirmation_path = format!("{join_commit_path}/confirmations/{}", candidate.device_id);
    let confirmation_body =
        mls_confirmation_body(&candidate, join_submission, receipt_digest, committed_head)?;
    let first_confirmation = send_network_federated_confirmation(
        &client,
        group_origin,
        &confirmation_path,
        candidate_identity_origin,
        mls_confirmation_proof(
            &candidate,
            candidate_identity_origin,
            scope,
            &confirmation_path,
            join_submission,
            &confirmation_body,
            now + 3,
        )?,
        confirmation_body.clone(),
    )
    .await?;
    assert_eq!(first_confirmation.status(), StatusCode::NO_CONTENT);
    let recovered_confirmation = send_network_federated_confirmation(
        &client,
        group_origin,
        &confirmation_path,
        candidate_identity_origin,
        mls_confirmation_proof(
            &candidate,
            candidate_identity_origin,
            scope,
            &confirmation_path,
            join_submission,
            &confirmation_body,
            now + 4,
        )?,
        confirmation_body,
    )
    .await?;
    assert_eq!(recovered_confirmation.status(), StatusCode::NO_CONTENT);
    let confirmation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM groups.mls_join_confirmations WHERE submission_id::text=$1",
    )
    .bind(join_submission.to_string())
    .fetch_one(&admin_a)
    .await?;
    assert_eq!(confirmation_count, 1, "fresh-proof replay keeps one leaf");

    let approval_receipt_path = format!("{scope_path}/membership-receipts/{approval_command_id}");
    let committed_membership = send_network_receipt_query(
        &client,
        group_origin,
        &approval_receipt_path,
        candidate_identity_origin,
        receipt_query_proof(
            &candidate,
            candidate_identity_origin,
            scope,
            &approval_receipt_path,
            approval_command_id,
            now + 5,
        )?,
    )
    .await?;
    assert_eq!(committed_membership.status(), StatusCode::OK);
    assert_membership_phase(&committed_membership.bytes().await?, 4)?;

    let scope_id = scope_path.rsplit('/').next().ok_or("scope ID")?;
    for (node, pool, expected) in [
        ("A", &admin_a, 1_i64),
        ("B", &admin_b, 0_i64),
        ("C", &admin_c, 0_i64),
    ] {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM groups.policy_heads WHERE scope_id=$1")
                .bind(scope_id)
                .fetch_one(pool)
                .await?;
        assert_eq!(count, expected, "group scope isolation on node {node}");
    }
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // The end-to-end recovery scenario intentionally keeps its user-visible sequence together.
async fn group_http_replays_refreshed_proofs_and_preserves_membership_intents()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let tenant_id = TenantId::new();
    let owner = enroll_active_device(&identity_store, 11, 12, 13, [14; 32]).await?;
    let candidate = enroll_active_device(&identity_store, 21, 22, 23, [24; 32]).await?;
    let (candidate_origin, identity_server) =
        start_identity_log_server(identity_store.clone()).await?;
    let app = group_router_with_state(
        GroupNodeState::with_clock(group_store, tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(SigningKey::from_bytes(&[99; 32]))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                [candidate_origin.clone()],
            )?,
    );
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_idempotency_key = "group-create-replay-0001";
    let first_create_body = create_body(&owner, scope, &scope_path, create_idempotency_key, 1_000)?;
    let first_create = send_mutation(
        app.clone(),
        "PUT",
        &scope_path,
        GROUP_CREATE_CONTENT_TYPE,
        create_idempotency_key,
        &owner,
        first_create_body,
    )
    .await?;
    assert_eq!(first_create.status(), StatusCode::CREATED);
    assert_content_type(&first_create, GROUP_ACTION_RECEIPT_CONTENT_TYPE);
    let first_create_receipt = response_bytes(first_create).await?;

    // The retry uses a freshly issued proof and signature but the same logical
    // action/key. The stored receipt must be replayed byte-for-byte instead
    // of being mistaken for a divergent command after a lost response.
    let refreshed_create = send_mutation(
        app.clone(),
        "PUT",
        &scope_path,
        GROUP_CREATE_CONTENT_TYPE,
        create_idempotency_key,
        &owner,
        create_body(&owner, scope, &scope_path, create_idempotency_key, 1_500)?,
    )
    .await?;
    assert_eq!(refreshed_create.status(), StatusCode::OK);
    assert_eq!(
        response_bytes(refreshed_create).await?,
        first_create_receipt
    );

    let bootstrap_submission = RequestId::new();
    let bootstrap_path = format!("{scope_path}/mls-commits/{bootstrap_submission}");
    let bootstrap_key = "mls-owner-bootstrap-0001";
    let bootstrap_body = mls_commit_body(
        &owner,
        &owner,
        scope,
        bootstrap_submission,
        bootstrap_key,
        0,
        Sha256Digest::from_bytes([0; 32]),
        vec![0x41; 48],
        MlsCommitAuthorization::OwnerBootstrap,
    )?;
    let bootstrap = send_mutation(
        app.clone(),
        "POST",
        &bootstrap_path,
        MLS_COMMIT_CONTENT_TYPE,
        bootstrap_key,
        &owner,
        bootstrap_body.clone(),
    )
    .await?;
    assert_eq!(bootstrap.status(), StatusCode::CREATED);
    assert_content_type(&bootstrap, MLS_COMMIT_RECEIPT_CONTENT_TYPE);
    let bootstrap_receipt = response_bytes(bootstrap).await?;
    let bootstrap_head = mls_receipt_head(&bootstrap_receipt)?;
    let bootstrap_replay = send_mutation(
        app.clone(),
        "POST",
        &bootstrap_path,
        MLS_COMMIT_CONTENT_TYPE,
        bootstrap_key,
        &owner,
        bootstrap_body,
    )
    .await?;
    assert_eq!(bootstrap_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(bootstrap_replay).await?, bootstrap_receipt);

    let invite_id = InviteCapabilityId::new();
    let invite_path = format!("{scope_path}/invites/{invite_id}");
    let invite_key = "group-issue-invite-0001";
    let invite_body = issue_invite_body(
        &owner,
        scope,
        &invite_path,
        invite_key,
        1_000,
        Revision::INITIAL,
        Some(candidate.identity_id),
        1,
        10_000,
    )?;
    let invite = send_mutation(
        app.clone(),
        "PUT",
        &invite_path,
        GROUP_ISSUE_INVITE_CONTENT_TYPE,
        invite_key,
        &owner,
        invite_body,
    )
    .await?;
    assert_eq!(invite.status(), StatusCode::CREATED);

    let join_request_id = JoinRequestId::new();
    let join_command_id = RequestId::new();
    let join_path = format!("{scope_path}/join-requests/{join_request_id}");
    let join_key = "group-join-request-0001";
    let candidate_key_package_digest = test_candidate_key_package_digest(&candidate);
    let join_body = join_request_body_v2(
        &candidate,
        scope,
        &join_path,
        join_key,
        1_000,
        join_command_id,
        invite_id,
        Revision::new(2)?,
        Sha256Digest::hash_domain(b"test-group-head\0", b"join"),
        candidate_key_package_digest,
    )?;
    let join = send_mutation(
        app.clone(),
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_V2_CONTENT_TYPE,
        join_key,
        &candidate,
        join_body.clone(),
    )
    .await?;
    assert_eq!(join.status(), StatusCode::ACCEPTED);
    let join_receipt = response_bytes(join).await?;
    assert_membership_phase(&join_receipt, 1)?;
    let join_request_digest = membership_receipt_request_digest(&join_receipt)?;
    let join_replay = send_mutation(
        app.clone(),
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_V2_CONTENT_TYPE,
        join_key,
        &candidate,
        join_body,
    )
    .await?;
    assert_eq!(join_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(join_replay).await?, join_receipt);

    let pending_target = format!("{scope_path}/join-requests?after=&limit=32");
    let pending_v2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&pending_target)
                .header(header::ACCEPT, GROUP_JOIN_REQUEST_PAGE_V2_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(owner.session_id, owner.session_secret),
                )
                .header(
                    GROUP_QUERY_PROOF_HEADER,
                    group_query_proof(&owner, AUDIENCE, scope, &pending_target, 1_100)?,
                )
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(pending_v2.status(), StatusCode::OK);
    assert_content_type(&pending_v2, GROUP_JOIN_REQUEST_PAGE_V2_CONTENT_TYPE);
    let (pending_join_request_id, pending_key_package_digest) =
        decode_v2_pending_package(&response_bytes(pending_v2).await?)?;
    assert_eq!(pending_join_request_id, join_request_id.to_string());
    assert_eq!(pending_key_package_digest, candidate_key_package_digest);

    let mismatched_accept = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&pending_target)
                .header(header::ACCEPT, MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(owner.session_id, owner.session_secret),
                )
                .header(
                    GROUP_QUERY_PROOF_HEADER,
                    group_query_proof(&owner, AUDIENCE, scope, &pending_target, 1_150)?,
                )
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(mismatched_accept.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let approval_command_id = RequestId::new();
    let approval_path = format!("{join_path}/approvals");
    let approval_key = "group-approve-join-0001";
    let approval_body = approve_join_body_v2(
        &owner,
        scope,
        &approval_path,
        approval_key,
        1_000,
        approval_command_id,
        candidate.identity_id,
        candidate.device_id,
        invite_id,
        Revision::new(3)?,
        bootstrap_head,
        candidate_key_package_digest,
    )?;
    let authorization_digest = action_proof_binding_digest(&approval_body)?;
    let approval = send_mutation(
        app.clone(),
        "POST",
        &approval_path,
        GROUP_APPROVE_JOIN_V2_CONTENT_TYPE,
        approval_key,
        &owner,
        approval_body.clone(),
    )
    .await?;
    assert_eq!(approval.status(), StatusCode::ACCEPTED);
    assert_content_type(&approval, MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE);
    let approval_receipt = response_bytes(approval).await?;
    assert_membership_phase(&approval_receipt, 2)?;
    let approval_request_digest = membership_receipt_request_digest(&approval_receipt)?;
    let approval_replay = send_mutation(
        app.clone(),
        "POST",
        &approval_path,
        GROUP_APPROVE_JOIN_V2_CONTENT_TYPE,
        approval_key,
        &owner,
        approval_body,
    )
    .await?;
    assert_eq!(approval_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(approval_replay).await?, approval_receipt);

    let membership_command_id =
        dtx_membership_command::MembershipCommandId::new(approval_command_id);
    let join_submission = RequestId::new();
    let join_commit_path = format!("{scope_path}/mls-commits/{join_submission}");
    let join_commit_key = "mls-approved-join-0001";
    let join_commit_body = mls_commit_body_v3(
        &owner,
        &candidate,
        scope,
        join_submission,
        1,
        bootstrap_head,
        vec![0x52; 48],
        membership_command_id,
        authorization_digest,
        join_request_digest,
        approval_request_digest,
        candidate_key_package_digest,
    )?;
    let committed = send_mutation(
        app.clone(),
        "POST",
        &join_commit_path,
        MLS_COMMIT_V3_CONTENT_TYPE,
        join_commit_key,
        &owner,
        join_commit_body.clone(),
    )
    .await?;
    assert_eq!(committed.status(), StatusCode::CREATED);
    assert_content_type(&committed, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE);
    let committed_receipt = response_bytes(committed).await?;
    let committed_replay = send_mutation(
        app.clone(),
        "POST",
        &join_commit_path,
        MLS_COMMIT_V3_CONTENT_TYPE,
        join_commit_key,
        &owner,
        join_commit_body,
    )
    .await?;
    assert_eq!(committed_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(committed_replay).await?, committed_receipt);

    let (receipt_digest, committed_head) = mls_receipt_facts(&committed_receipt)?;
    let confirmation_path = format!("{join_commit_path}/confirmations/{}", candidate.device_id);
    let confirmation_body =
        mls_confirmation_body(&candidate, join_submission, receipt_digest, committed_head)?;
    let first_confirmation = send_federated_confirmation(
        app.clone(),
        &confirmation_path,
        &candidate_origin,
        mls_confirmation_proof(
            &candidate,
            &candidate_origin,
            scope,
            &confirmation_path,
            join_submission,
            &confirmation_body,
            1_000,
        )?,
        confirmation_body.clone(),
    )
    .await?;
    assert_eq!(first_confirmation.status(), StatusCode::NO_CONTENT);
    let response_loss_replay = send_federated_confirmation(
        app.clone(),
        &confirmation_path,
        &candidate_origin,
        mls_confirmation_proof(
            &candidate,
            &candidate_origin,
            scope,
            &confirmation_path,
            join_submission,
            &confirmation_body,
            1_500,
        )?,
        confirmation_body.clone(),
    )
    .await?;
    assert_eq!(response_loss_replay.status(), StatusCode::NO_CONTENT);
    let confirmation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM groups.mls_join_confirmations
          WHERE tenant_id::text=$1 AND submission_id::text=$2",
    )
    .bind(tenant_id.to_string())
    .bind(join_submission.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(
        confirmation_count, 1,
        "fresh-proof replay must keep one leaf"
    );

    // Sequencer acceptance and the GM1 member/outbox resolution commit together.
    let receipt_path = GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE
        .replace("{scope_kind}", "private-conversation")
        .replace(
            "{scope_id}",
            scope_path.rsplit('/').next().ok_or("scope id")?,
        )
        .replace("{membership_command_id}", &approval_command_id.to_string());
    let receipt = send_get(app.clone(), &receipt_path, &candidate).await?;
    assert_eq!(receipt.status(), StatusCode::OK);
    assert_membership_phase(&response_bytes(receipt).await?, 4)?;

    revoke_device(&identity_store, &candidate, 30_000).await?;
    let revoked_confirmation = send_federated_confirmation(
        app.clone(),
        &confirmation_path,
        &candidate_origin,
        mls_confirmation_proof(
            &candidate,
            &candidate_origin,
            scope,
            &confirmation_path,
            join_submission,
            &confirmation_body,
            1_800,
        )?,
        confirmation_body,
    )
    .await?;
    assert_eq!(revoked_confirmation.status(), StatusCode::UNAUTHORIZED);
    identity_server.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // The coupled concurrent-create and five-admin invariants are clearest as one persistence scenario.
async fn group_control_persists_a_hard_five_admin_limit_under_serialized_writes()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    for privilege in ["SELECT", "INSERT"] {
        let granted: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user, 'groups.control_commands', $1)",
        )
        .bind(privilege)
        .fetch_one(harness.group_runtime_pool())
        .await?;
        assert!(
            granted,
            "group runtime is missing {privilege} on control receipts"
        );
    }
    let tenant_id = TenantId::new();
    let repository = GroupControlRepository;
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let first_owner = identity_from_seed(31)?;
    let competing_owner = identity_from_seed(32)?;
    let (first_create, competing_create) = tokio::join!(
        repository.execute(
            &store,
            tenant_id,
            control_command(
                first_owner,
                DeviceId::new(),
                GroupControlOperation::CreateGroup {
                    scope,
                    owner_identity_id: first_owner,
                },
                b"create-first-owner",
            ),
            NOW,
        ),
        repository.execute(
            &store,
            tenant_id,
            control_command(
                competing_owner,
                DeviceId::new(),
                GroupControlOperation::CreateGroup {
                    scope,
                    owner_identity_id: competing_owner,
                },
                b"create-competing-owner",
            ),
            NOW,
        )
    );
    let first_create = first_create?;
    let competing_create = competing_create?;
    let owner = match (first_create.disposition(), competing_create.disposition()) {
        (
            GroupControlDisposition::Applied { .. },
            GroupControlDisposition::Rejected(GroupControlRejection::GroupExists),
        ) => first_owner,
        (
            GroupControlDisposition::Rejected(GroupControlRejection::GroupExists),
            GroupControlDisposition::Applied { .. },
        ) => competing_owner,
        (left, right) => panic!(
            "competing group creation must yield one owner and one stable rejection: {left:?}, {right:?}"
        ),
    };

    for (index, administrator_identity_id) in (0_u8..5).map(identity_from_seed).enumerate() {
        let administrator_identity_id = administrator_identity_id?;
        let command_seed = u8::try_from(index)?;
        let receipt = repository
            .execute(
                &store,
                tenant_id,
                control_command(
                    owner,
                    DeviceId::new(),
                    GroupControlOperation::GrantAdmin {
                        scope,
                        expected_revision: Revision::new(u64::try_from(index + 1)?)?,
                        administrator_identity_id,
                    },
                    &[command_seed],
                ),
                NOW,
            )
            .await?;
        assert!(matches!(
            receipt.disposition(),
            GroupControlDisposition::Applied { .. }
        ));
    }

    let sixth = identity_from_seed(41)?;
    let seventh = identity_from_seed(42)?;
    let expected_revision = Revision::new(6)?;
    let (left, right) = tokio::join!(
        repository.execute(
            &store,
            tenant_id,
            control_command(
                owner,
                DeviceId::new(),
                GroupControlOperation::GrantAdmin {
                    scope,
                    expected_revision,
                    administrator_identity_id: sixth,
                },
                b"sixth",
            ),
            NOW,
        ),
        repository.execute(
            &store,
            tenant_id,
            control_command(
                owner,
                DeviceId::new(),
                GroupControlOperation::GrantAdmin {
                    scope,
                    expected_revision,
                    administrator_identity_id: seventh,
                },
                b"seventh",
            ),
            NOW,
        )
    );
    for receipt in [left?, right?] {
        assert_eq!(
            receipt.disposition(),
            GroupControlDisposition::Rejected(GroupControlRejection::AdminLimitReached)
        );
    }
    assert_eq!(
        GroupMembershipRepository
            .load_policy(&store, tenant_id, scope)
            .await?
            .admin_count(),
        5
    );
    Ok(())
}

struct ActiveDevice {
    identity_id: IdentityId,
    device_id: DeviceId,
    root: SigningKey,
    device: SigningKey,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
}

async fn enroll_active_device(
    store: &IdentityPgStore,
    root_seed: u8,
    recovery_seed: u8,
    device_seed: u8,
    session_secret: [u8; 32],
) -> Result<ActiveDevice, Box<dyn Error>> {
    enroll_active_device_at(
        store,
        root_seed,
        recovery_seed,
        device_seed,
        session_secret,
        NOW,
    )
    .await
}

async fn enroll_active_device_at(
    store: &IdentityPgStore,
    root_seed: u8,
    recovery_seed: u8,
    device_seed: u8,
    session_secret: [u8; 32],
    now: i64,
) -> Result<ActiveDevice, Box<dyn Error>> {
    let root = SigningKey::from_bytes(&[root_seed; 32]);
    let recovery = SigningKey::from_bytes(&[recovery_seed; 32]);
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let genesis = genesis(&root, &recovery, now - 1_000)?;
    let identity_id = genesis.identity_id();
    let repository = IdentityLogRepository::new();
    let bootstrap = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-group-bootstrap\0", &[root_seed]),
        None,
        genesis.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append_bootstrap(store, &bootstrap, UtcMillis::new(now - 800)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let device_id = DeviceId::new();
    let initial = device_add(
        &root,
        &device,
        identity_id,
        device_id,
        genesis.entry_hash()?,
        2,
        now - 700,
    )?;
    assert!(matches!(
        repository
            .append_initial_device(
                store,
                Sha256Digest::hash_domain(b"test-group-initial\0", &[root_seed]),
                genesis.entry_hash()?,
                initial.to_deterministic_cbor()?,
                UtcMillis::new(now - 500)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let challenge = DeviceSessionRepository
        .issue_challenge(
            store,
            identity_id,
            device_id,
            [device_seed; 32],
            AUDIENCE,
            UtcMillis::new(now)?,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let proof = signature(
        &device,
        &device_session_proof_input(
            identity_id,
            device_id,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            session_secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    let completion = DeviceSessionCompletionCommand::new(
        Sha256Digest::hash_domain(b"test-group-session\0", &[root_seed]),
        identity_id,
        device_id,
        challenge.challenge_id(),
        session_id,
        *challenge.nonce(),
        session_secret,
        proof,
    )?;
    assert!(matches!(
        DeviceSessionRepository
            .complete(store, &completion, UtcMillis::new(now)?)
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(ActiveDevice {
        identity_id,
        device_id,
        root,
        device,
        session_id,
        session_secret,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn admit_local_v30_member(
    app: axum::Router,
    owner: &ActiveDevice,
    candidate: &ActiveDevice,
    scope: GroupScope,
    scope_path: &str,
    expected_policy_revision: Revision,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    key_prefix: &str,
) -> Result<(Vec<u8>, Sha256Digest), Box<dyn Error>> {
    let invite_id = InviteCapabilityId::new();
    let invite_path = format!("{scope_path}/invites/{invite_id}");
    let invite_key = format!("{key_prefix}-invite-0001");
    let invite = send_mutation(
        app.clone(),
        "PUT",
        &invite_path,
        GROUP_ISSUE_INVITE_CONTENT_TYPE,
        &invite_key,
        owner,
        issue_invite_body(
            owner,
            scope,
            &invite_path,
            &invite_key,
            1_000,
            expected_policy_revision,
            Some(candidate.identity_id),
            1,
            10_000,
        )?,
    )
    .await?;
    assert_eq!(invite.status(), StatusCode::CREATED);

    let join_revision = Revision::new(
        expected_policy_revision
            .get()
            .checked_add(1)
            .ok_or("join revision overflow")?,
    )?;
    let join_request_id = JoinRequestId::new();
    let join_command_id = RequestId::new();
    let join_path = format!("{scope_path}/join-requests/{join_request_id}");
    let join_key = format!("{key_prefix}-join-0001");
    let candidate_key_package_digest = test_candidate_key_package_digest(candidate);
    let join = send_mutation(
        app.clone(),
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_V2_CONTENT_TYPE,
        &join_key,
        candidate,
        join_request_body_v2(
            candidate,
            scope,
            &join_path,
            &join_key,
            1_000,
            join_command_id,
            invite_id,
            join_revision,
            expected_head,
            candidate_key_package_digest,
        )?,
    )
    .await?;
    assert_eq!(join.status(), StatusCode::ACCEPTED);
    let join_request_digest = membership_receipt_request_digest(&response_bytes(join).await?)?;

    let approval_revision = Revision::new(
        expected_policy_revision
            .get()
            .checked_add(2)
            .ok_or("approval revision overflow")?,
    )?;
    let approval_command_id = RequestId::new();
    let approval_path = format!("{join_path}/approvals");
    let approval_key = format!("{key_prefix}-approval-0001");
    let approval_body = approve_join_body_v2(
        owner,
        scope,
        &approval_path,
        &approval_key,
        1_000,
        approval_command_id,
        candidate.identity_id,
        candidate.device_id,
        invite_id,
        approval_revision,
        expected_head,
        candidate_key_package_digest,
    )?;
    let authorization_digest = action_proof_binding_digest(&approval_body)?;
    let approval = send_mutation(
        app.clone(),
        "POST",
        &approval_path,
        GROUP_APPROVE_JOIN_V2_CONTENT_TYPE,
        &approval_key,
        owner,
        approval_body,
    )
    .await?;
    assert_eq!(approval.status(), StatusCode::ACCEPTED);
    let approval_request_digest =
        membership_receipt_request_digest(&response_bytes(approval).await?)?;

    let submission_id = RequestId::new();
    let commit_path = format!("{scope_path}/mls-commits/{submission_id}");
    let commit_key = format!("{key_prefix}-commit-0001");
    let commit = send_mutation(
        app.clone(),
        "POST",
        &commit_path,
        MLS_COMMIT_V3_CONTENT_TYPE,
        &commit_key,
        owner,
        mls_commit_body_v3(
            owner,
            candidate,
            scope,
            submission_id,
            expected_epoch,
            expected_head,
            commit_bytes,
            dtx_membership_command::MembershipCommandId::new(approval_command_id),
            authorization_digest,
            join_request_digest,
            approval_request_digest,
            candidate_key_package_digest,
        )?,
    )
    .await?;
    assert_eq!(commit.status(), StatusCode::CREATED);
    assert_content_type(&commit, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE);
    let receipt = response_bytes(commit).await?;
    let (receipt_digest, head_digest) = mls_receipt_facts(&receipt)?;
    let confirmation_path = format!("{commit_path}/confirmations/{}", candidate.device_id);
    let confirmation = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&confirmation_path)
                .header(header::CONTENT_TYPE, MLS_CONFIRMATION_V3_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(candidate.session_id, candidate.session_secret),
                )
                .body(Body::from(mls_confirmation_body(
                    candidate,
                    submission_id,
                    receipt_digest,
                    head_digest,
                )?))?,
        )
        .await?;
    assert_eq!(confirmation.status(), StatusCode::NO_CONTENT);
    Ok((receipt, head_digest))
}

async fn start_identity_log_server(
    store: IdentityPgStore,
) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, identity_bootstrap_router(store)).await;
    });
    Ok((origin, server))
}

async fn revoke_device(
    store: &IdentityPgStore,
    active: &ActiveDevice,
    occurred_at_ms: i64,
) -> Result<(), Box<dyn Error>> {
    let repository = IdentityLogRepository::new();
    let head = repository
        .load(store, active.identity_id)
        .await?
        .ok_or("identity missing before federated revoke")?
        .head();
    let revoke = signed_event(
        &active.root,
        active.identity_id,
        head.sequence().get() + 1,
        Some(head.hash()),
        occurred_at_ms,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: active.device_id,
        },
    )?;
    let command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(
            b"test-federated-device-revoke\0",
            active.identity_id.to_string().as_bytes(),
        ),
        Some(head),
        revoke.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(store, &command, UtcMillis::new(occurred_at_ms)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    Ok(())
}

fn create_body(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![CanonicalValue::Unsigned(1)]);
    let proof = action_proof(
        1,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![CanonicalValue::Unsigned(1), proof]))
}

fn grant_admin_body(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    expected_revision: Revision,
    _administrator_identity_id: IdentityId,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
    ]);
    let proof = action_proof(
        2,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn issue_invite_body(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    expected_revision: Revision,
    target_identity_id: Option<IdentityId>,
    max_uses: u32,
    expires_at_ms: i64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let target = target_identity_id.map_or(CanonicalValue::Null, |identity_id| {
        CanonicalValue::Text(identity_id.to_string())
    });
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
        target.clone(),
        CanonicalValue::Unsigned(u64::from(max_uses)),
        utc_value(expires_at_ms),
    ]);
    let proof = action_proof(
        4,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
        target,
        CanonicalValue::Unsigned(u64::from(max_uses)),
        utc_value(expires_at_ms),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn federated_issue_invite_body(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    expected_revision: Revision,
    target_identity_id: Option<IdentityId>,
    max_uses: u32,
    expires_at_ms: i64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let target = target_identity_id.map_or(CanonicalValue::Null, |identity_id| {
        CanonicalValue::Text(identity_id.to_string())
    });
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
        target.clone(),
        CanonicalValue::Unsigned(u64::from(max_uses)),
        utc_value(expires_at_ms),
    ]);
    let proof = federated_action_proof(
        4,
        active,
        identity_origin,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
        target,
        CanonicalValue::Unsigned(u64::from(max_uses)),
        utc_value(expires_at_ms),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn join_request_body(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
    ]);
    let proof = action_proof(
        6,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn join_request_body_v2(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
    candidate_key_package_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
    ]);
    let proof = action_proof(
        6,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn federated_join_request_body(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
    ]);
    let proof = federated_action_proof(
        6,
        active,
        identity_origin,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn federated_join_request_body_v2(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
    candidate_key_package_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
    ]);
    let proof = federated_action_proof(
        6,
        active,
        identity_origin,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn approve_join_body_v2(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
    candidate_key_package_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(candidate_identity_id.to_string()),
        CanonicalValue::Text(candidate_device_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
    ]);
    let proof = action_proof(
        7,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(candidate_identity_id.to_string()),
        CanonicalValue::Text(candidate_device_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn federated_approve_join_body(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(candidate_identity_id.to_string()),
        CanonicalValue::Text(candidate_device_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
    ]);
    let proof = federated_action_proof(
        7,
        active,
        identity_origin,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(candidate_identity_id.to_string()),
        CanonicalValue::Text(candidate_device_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
        proof,
    ]))
}

fn action_proof(
    action: u64,
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    signable: &CanonicalValue,
    issued_at: i64,
) -> Result<CanonicalValue, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("action proof expiry overflow")?;
    let idempotency_key_hash =
        Sha256Digest::hash_domain(IDEMPOTENCY_HASH_DOMAIN, idempotency_key.as_bytes());
    let business_fields_digest = Sha256Digest::hash_domain(
        BUSINESS_FIELDS_HASH_DOMAIN,
        &encode_deterministic_cbor(signable)?,
    );
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(action),
        CanonicalValue::Text(path.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(active.identity_id.to_string()),
        CanonicalValue::Text(active.device_id.to_string()),
        CanonicalValue::Bytes(idempotency_key_hash.as_bytes().to_vec()),
        CanonicalValue::Bytes(business_fields_digest.as_bytes().to_vec()),
        utc_value(issued_at),
        utc_value(expires_at),
    ]);
    let binding_digest = Sha256Digest::hash_domain(
        ACTION_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = ACTION_SIGNATURE_DOMAIN.to_vec();
    signature_input.extend_from_slice(binding_digest.as_bytes());
    let signature = active.device.sign(&signature_input).to_bytes();
    Ok(numbered_map(vec![
        CanonicalValue::Unsigned(1),
        binding,
        CanonicalValue::Bytes(signature.to_vec()),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn federated_action_proof(
    action: u64,
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    signable: &CanonicalValue,
    issued_at: i64,
) -> Result<CanonicalValue, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("federated action proof expiry overflow")?;
    let idempotency_key_hash =
        Sha256Digest::hash_domain(IDEMPOTENCY_HASH_DOMAIN, idempotency_key.as_bytes());
    let business_fields_digest = Sha256Digest::hash_domain(
        BUSINESS_FIELDS_HASH_DOMAIN,
        &encode_deterministic_cbor(signable)?,
    );
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Unsigned(action),
        CanonicalValue::Text(path.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(active.identity_id.to_string()),
        CanonicalValue::Text(active.device_id.to_string()),
        CanonicalValue::Bytes(idempotency_key_hash.as_bytes().to_vec()),
        CanonicalValue::Bytes(business_fields_digest.as_bytes().to_vec()),
        utc_value(issued_at),
        utc_value(expires_at),
        CanonicalValue::Text(identity_origin.to_owned()),
    ]);
    let binding_digest = Sha256Digest::hash_domain(
        FEDERATED_ACTION_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = FEDERATED_ACTION_SIGNATURE_DOMAIN.to_vec();
    signature_input.extend_from_slice(binding_digest.as_bytes());
    let signature = active.device.sign(&signature_input).to_bytes();
    Ok(numbered_map(vec![
        CanonicalValue::Unsigned(2),
        binding,
        CanonicalValue::Bytes(signature.to_vec()),
    ]))
}

fn receipt_query_proof(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    command_id: RequestId,
    issued_at: i64,
) -> Result<String, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("receipt query proof expiry overflow")?;
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Unsigned(8),
        CanonicalValue::Text(path.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(active.identity_id.to_string()),
        CanonicalValue::Text(active.device_id.to_string()),
        utc_value(issued_at),
        utc_value(expires_at),
        CanonicalValue::Text(identity_origin.to_owned()),
    ]);
    let binding_digest = Sha256Digest::hash_domain(
        b"dirextalk.membership-receipt-query-binding.v2\0",
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = b"dirextalk.membership-receipt-query-signature.v2\0".to_vec();
    signature_input.extend_from_slice(binding_digest.as_bytes());
    let proof = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        binding,
        CanonicalValue::Bytes(active.device.sign(&signature_input).to_bytes().to_vec()),
    ]);
    Ok(Base64UrlUnpadded::encode_string(
        &encode_deterministic_cbor(&proof)?,
    ))
}

fn group_query_proof(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    canonical_target: &str,
    issued_at: i64,
) -> Result<String, Box<dyn Error>> {
    group_query_proof_for_action(
        active,
        identity_origin,
        scope,
        canonical_target,
        1,
        issued_at,
    )
}

fn group_query_proof_for_action(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    canonical_target: &str,
    action: u64,
    issued_at: i64,
) -> Result<String, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("group query proof expiry overflow")?;
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(action),
        CanonicalValue::Text(canonical_target.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(active.identity_id.to_string()),
        CanonicalValue::Text(active.device_id.to_string()),
        utc_value(issued_at),
        utc_value(expires_at),
        CanonicalValue::Text(identity_origin.to_owned()),
    ]);
    let digest = Sha256Digest::hash_domain(
        GROUP_QUERY_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = GROUP_QUERY_SIGNATURE_DOMAIN.to_vec();
    signature_input.extend_from_slice(digest.as_bytes());
    let proof = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        binding,
        CanonicalValue::Bytes(active.device.sign(&signature_input).to_bytes().to_vec()),
    ]);
    Ok(Base64UrlUnpadded::encode_string(
        &encode_deterministic_cbor(&proof)?,
    ))
}

async fn send_mutation(
    app: axum::Router,
    method: &str,
    path: &str,
    content_type: &str,
    idempotency_key: &str,
    active: &ActiveDevice,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, content_type)
            .header("idempotency-key", idempotency_key)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(active.session_id, active.session_secret),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_mutation(
    app: axum::Router,
    method: &str,
    path: &str,
    content_type: &str,
    idempotency_key: &str,
    identity_origin: &str,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, content_type)
            .header("idempotency-key", idempotency_key)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_confirmation(
    app: axum::Router,
    path: &str,
    identity_origin: &str,
    proof: String,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, MLS_CONFIRMATION_V3_CONTENT_TYPE)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(MLS_CONFIRMATION_PROOF_HEADER, proof)
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_get(
    app: axum::Router,
    path: &str,
    identity_origin: &str,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(path)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(RECEIPT_QUERY_PROOF_HEADER, proof)
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

async fn send_group_query(
    app: axum::Router,
    target: &str,
    active: &ActiveDevice,
    identity_origin: &str,
    federated: bool,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut request = Request::builder()
        .method("GET")
        .uri(target)
        .header(GROUP_QUERY_PROOF_HEADER, proof);
    if federated {
        request = request.header(IDENTITY_ORIGIN_HEADER, identity_origin);
    } else {
        request = request.header(
            header::AUTHORIZATION,
            device_session_authorization(active.session_id, active.session_secret),
        );
    }
    app.oneshot(request.body(Body::empty())?)
        .await
        .map_err(Into::into)
}

async fn send_local_commit_feed(
    app: axum::Router,
    target: &str,
    active: &ActiveDevice,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(target)
            .header(header::ACCEPT, MLS_COMMIT_FEED_CONTENT_TYPE)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(active.session_id, active.session_secret),
            )
            .header(GROUP_QUERY_PROOF_HEADER, proof)
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
async fn send_network_mutation(
    client: &reqwest::Client,
    group_origin: &str,
    method: reqwest::Method,
    path: &str,
    content_type: &str,
    idempotency_key: &str,
    authorization: Option<String>,
    identity_origin: Option<&str>,
    body: Vec<u8>,
) -> Result<reqwest::Response, Box<dyn Error>> {
    if authorization.is_some() && identity_origin.is_some() {
        return Err(
            "network acceptance request cannot mix local and federated authentication".into(),
        );
    }
    let mut request = client
        .request(method, format!("{group_origin}{path}"))
        .header(header::CONTENT_TYPE.as_str(), content_type)
        .header("idempotency-key", idempotency_key)
        .body(body);
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION.as_str(), authorization);
    }
    if let Some(identity_origin) = identity_origin {
        request = request.header(IDENTITY_ORIGIN_HEADER, identity_origin);
    }
    Ok(request.send().await?)
}

async fn send_network_federated_confirmation(
    client: &reqwest::Client,
    group_origin: &str,
    path: &str,
    identity_origin: &str,
    proof: String,
    body: Vec<u8>,
) -> Result<reqwest::Response, Box<dyn Error>> {
    Ok(client
        .post(format!("{group_origin}{path}"))
        .header(
            header::CONTENT_TYPE.as_str(),
            MLS_CONFIRMATION_V3_CONTENT_TYPE,
        )
        .header(IDENTITY_ORIGIN_HEADER, identity_origin)
        .header(MLS_CONFIRMATION_PROOF_HEADER, proof)
        .body(body)
        .send()
        .await?)
}

async fn send_network_receipt_query(
    client: &reqwest::Client,
    group_origin: &str,
    path: &str,
    identity_origin: &str,
    proof: String,
) -> Result<reqwest::Response, Box<dyn Error>> {
    Ok(client
        .get(format!("{group_origin}{path}"))
        .header(header::ACCEPT.as_str(), MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE)
        .header(IDENTITY_ORIGIN_HEADER, identity_origin)
        .header(RECEIPT_QUERY_PROOF_HEADER, proof)
        .send()
        .await?)
}

async fn send_get(
    app: axum::Router,
    path: &str,
    active: &ActiveDevice,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(path)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(active.session_id, active.session_secret),
            )
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

fn control_command(
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    operation: GroupControlOperation,
    seed: &[u8],
) -> GroupControlCommand {
    GroupControlCommand::new(
        RequestId::new(),
        Sha256Digest::hash_domain(b"test-group-control-key\0", seed),
        actor_identity_id,
        actor_device_id,
        operation,
        Sha256Digest::hash_domain(b"test-group-control-request\0", seed),
        Sha256Digest::hash_domain(b"test-group-control-binding\0", seed),
    )
}

fn identity_from_seed(seed: u8) -> Result<IdentityId, Box<dyn Error>> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    Ok(IdentityId::derive(public_key(&key)?.as_domain_key()))
}

fn scope_path(scope: GroupScope) -> String {
    match scope {
        GroupScope::PrivateConversation(conversation_id) => GROUP_SCOPE_PATH_TEMPLATE
            .replace("{scope_kind}", "private-conversation")
            .replace("{scope_id}", &conversation_id.to_string()),
        GroupScope::ControlledPublicChannel(_) => unreachable!("test uses a private group"),
    }
}

fn scope_value(scope: GroupScope) -> CanonicalValue {
    match scope {
        GroupScope::PrivateConversation(conversation_id) => numbered_map(vec![
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text(conversation_id.to_string()),
        ]),
        GroupScope::ControlledPublicChannel(channel_id) => numbered_map(vec![
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(channel_id.to_string()),
        ]),
    }
}

#[allow(clippy::too_many_arguments)]
fn mls_commit_body(
    actor: &ActiveDevice,
    candidate: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    authorization: MlsCommitAuthorization,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let idempotency_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, idempotency_key.as_bytes());
    let key_package_digest = Sha256Digest::hash_domain(
        b"test-mls-key-package\0",
        candidate.device.verifying_key().as_bytes(),
    );
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    let welcome_digest = Sha256Digest::hash_domain(b"test-mls-welcome\0", &commit_bytes);
    let placeholder = Sha256Digest::from_bytes([0; 32]);
    let provisional = MlsCommitCommand::new(
        submission_id,
        scope,
        actor.identity_id,
        actor.device_id,
        candidate.identity_id,
        candidate.device_id,
        key_package_digest,
        placeholder,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        welcome_digest,
        authorization,
    )?;
    let candidate_digest = mls_candidate_proof_digest(&provisional)?;
    let command = MlsCommitCommand::new(
        submission_id,
        scope,
        actor.identity_id,
        actor.device_id,
        candidate.identity_id,
        candidate.device_id,
        key_package_digest,
        candidate_digest,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        welcome_digest,
        authorization,
    )?;
    let candidate_signature = candidate
        .device
        .sign(&mls_candidate_proof_signature_input(&command)?)
        .to_bytes();
    let candidate_proof = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Bytes(candidate_digest.as_bytes().to_vec()),
        CanonicalValue::Bytes(candidate_signature.to_vec()),
    ]);
    let authorization = match authorization {
        MlsCommitAuthorization::OwnerBootstrap => numbered_map(vec![CanonicalValue::Unsigned(1)]),
        MlsCommitAuthorization::ApprovedIdentityJoin {
            membership_command_id,
            authorization_digest,
        } => numbered_map(vec![
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(membership_command_id.request_id().to_string()),
            CanonicalValue::Bytes(authorization_digest.as_bytes().to_vec()),
        ]),
        MlsCommitAuthorization::ExistingMemberDeviceAdd { .. } => {
            return Err("device-add helper not needed by this acceptance".into());
        }
        MlsCommitAuthorization::ApprovedIdentityJoinV3 { .. } => {
            return Err("V3 approved-join uses the dedicated helper".into());
        }
    };
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(submission_id.to_string()),
        scope_value(scope),
        CanonicalValue::Text(actor.identity_id.to_string()),
        CanonicalValue::Text(actor.device_id.to_string()),
        CanonicalValue::Text(candidate.identity_id.to_string()),
        CanonicalValue::Text(candidate.device_id.to_string()),
        CanonicalValue::Bytes(key_package_digest.as_bytes().to_vec()),
        candidate_proof,
        CanonicalValue::Unsigned(expected_epoch),
        CanonicalValue::Bytes(expected_head.as_bytes().to_vec()),
        CanonicalValue::Bytes(commit_bytes),
        CanonicalValue::Bytes(commit_digest.as_bytes().to_vec()),
        CanonicalValue::Bytes(welcome_digest.as_bytes().to_vec()),
        authorization,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn mls_commit_body_v3(
    actor: &ActiveDevice,
    candidate: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    membership_command_id: dtx_membership_command::MembershipCommandId,
    authorization_digest: Sha256Digest,
    join_request_digest: Sha256Digest,
    approval_request_digest: Sha256Digest,
    candidate_key_package_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    let welcome_digest = Sha256Digest::hash_domain(b"test-mls-welcome\0", &commit_bytes);
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(3),
        CanonicalValue::Text(submission_id.to_string()),
        scope_value(scope),
        CanonicalValue::Text(actor.identity_id.to_string()),
        CanonicalValue::Text(actor.device_id.to_string()),
        CanonicalValue::Text(candidate.identity_id.to_string()),
        CanonicalValue::Text(candidate.device_id.to_string()),
        candidate_key_package_digest.to_canonical_value(),
        CanonicalValue::Null,
        CanonicalValue::Unsigned(expected_epoch),
        expected_head.to_canonical_value(),
        CanonicalValue::Bytes(commit_bytes),
        commit_digest.to_canonical_value(),
        welcome_digest.to_canonical_value(),
        numbered_map(vec![
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(membership_command_id.request_id().to_string()),
            authorization_digest.to_canonical_value(),
            join_request_digest.to_canonical_value(),
            approval_request_digest.to_canonical_value(),
        ]),
    ]))
}

fn mls_receipt_head(bytes: &[u8]) -> Result<Sha256Digest, Box<dyn Error>> {
    let CanonicalValue::Map(outer) = decode_deterministic_cbor(bytes)? else {
        return Err("MLS receipt wrapper must be a map".into());
    };
    let CanonicalValue::Map(inner) = &outer[0].1 else {
        return Err("MLS receipt payload must be a map".into());
    };
    let CanonicalValue::Bytes(head) = &inner[5].1 else {
        return Err("MLS receipt head must be bytes".into());
    };
    let exact: [u8; 32] = head.as_slice().try_into()?;
    Ok(Sha256Digest::from_bytes(exact))
}

fn mls_receipt_facts(bytes: &[u8]) -> Result<(Sha256Digest, Sha256Digest), Box<dyn Error>> {
    let CanonicalValue::Map(outer) = decode_deterministic_cbor(bytes)? else {
        return Err("MLS receipt wrapper must be a map".into());
    };
    let CanonicalValue::Map(inner) = &outer[0].1 else {
        return Err("MLS receipt payload must be a map".into());
    };
    if inner.first().map(|field| &field.1) != Some(&CanonicalValue::Unsigned(3)) {
        return Err("MLS receipt must use V3 inner facts".into());
    }
    let CanonicalValue::Bytes(receipt_digest) = &outer[1].1 else {
        return Err("MLS receipt digest must be bytes".into());
    };
    let CanonicalValue::Bytes(head_digest) = &inner[5].1 else {
        return Err("MLS receipt head must be bytes".into());
    };
    Ok((
        Sha256Digest::from_bytes(receipt_digest.as_slice().try_into()?),
        Sha256Digest::from_bytes(head_digest.as_slice().try_into()?),
    ))
}

fn mls_receipt_epoch(bytes: &[u8]) -> Result<u64, Box<dyn Error>> {
    let CanonicalValue::Map(outer) = decode_deterministic_cbor(bytes)? else {
        return Err("MLS receipt wrapper must be a map".into());
    };
    let CanonicalValue::Map(inner) = &outer[0].1 else {
        return Err("MLS receipt payload must be a map".into());
    };
    match &inner[4].1 {
        CanonicalValue::Unsigned(epoch) => Ok(*epoch),
        _ => Err("MLS receipt epoch must be unsigned".into()),
    }
}

fn decode_commit_feed(
    bytes: &[u8],
    expected_after_epoch: u64,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("MLS commit feed must be a map".into());
    };
    if fields.len() != 3
        || fields[0] != (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1))
        || fields[1]
            != (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Unsigned(expected_after_epoch),
            )
        || fields[2].0 != CanonicalValue::Unsigned(3)
    {
        return Err("MLS commit feed fields are not exact".into());
    }
    let CanonicalValue::Array(items) = &fields[2].1 else {
        return Err("MLS commit feed items must be an array".into());
    };
    items
        .iter()
        .map(|item| {
            let CanonicalValue::Array(parts) = item else {
                return Err("MLS commit feed item must be an array".into());
            };
            if parts.len() != 2 {
                return Err("MLS commit feed item must contain receipt and commit only".into());
            }
            let CanonicalValue::Bytes(receipt) = &parts[0] else {
                return Err("MLS commit feed receipt must be bytes".into());
            };
            let CanonicalValue::Bytes(commit) = &parts[1] else {
                return Err("MLS commit feed commit must be bytes".into());
            };
            Ok((receipt.clone(), commit.clone()))
        })
        .collect()
}

fn mls_confirmation_body(
    candidate: &ActiveDevice,
    submission_id: RequestId,
    receipt_digest: Sha256Digest,
    head_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let unsigned = MlsDeviceJoinConfirmation {
        submission_id,
        identity_id: candidate.identity_id,
        device_id: candidate.device_id,
        receipt_digest,
        head_digest,
        signature: Ed25519Signature::from_bytes([0; 64]),
    };
    let signature = candidate
        .device
        .sign(&mls_device_confirmation_signature_input(&unsigned)?)
        .to_bytes();
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(submission_id.to_string()),
        CanonicalValue::Text(candidate.identity_id.to_string()),
        CanonicalValue::Text(candidate.device_id.to_string()),
        receipt_digest.to_canonical_value(),
        head_digest.to_canonical_value(),
        CanonicalValue::Bytes(signature.to_vec()),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn mls_confirmation_proof(
    candidate: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    submission_id: RequestId,
    confirmation_body: &[u8],
    issued_at: i64,
) -> Result<String, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("confirmation proof expiry overflow")?;
    let body_digest =
        Sha256Digest::hash_domain(MLS_CONFIRMATION_BODY_HASH_DOMAIN, confirmation_body);
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(3),
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(path.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(submission_id.to_string()),
        CanonicalValue::Text(candidate.identity_id.to_string()),
        CanonicalValue::Text(candidate.device_id.to_string()),
        body_digest.to_canonical_value(),
        utc_value(issued_at),
        utc_value(expires_at),
        CanonicalValue::Text(identity_origin.to_owned()),
    ]);
    let digest = Sha256Digest::hash_domain(
        MLS_CONFIRMATION_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = MLS_CONFIRMATION_PROOF_SIGNATURE_DOMAIN.to_vec();
    signature_input.extend_from_slice(digest.as_bytes());
    let proof = numbered_map(vec![
        CanonicalValue::Unsigned(3),
        binding,
        CanonicalValue::Bytes(candidate.device.sign(&signature_input).to_bytes().to_vec()),
    ]);
    Ok(Base64UrlUnpadded::encode_string(
        &encode_deterministic_cbor(&proof)?,
    ))
}

fn action_proof_binding_digest(body: &[u8]) -> Result<Sha256Digest, Box<dyn Error>> {
    let CanonicalValue::Map(body_fields) = decode_deterministic_cbor(body)? else {
        return Err("approval body must be a map".into());
    };
    let CanonicalValue::Map(proof_fields) = &body_fields.last().ok_or("approval body is empty")?.1
    else {
        return Err("approval proof must be a map".into());
    };
    Ok(Sha256Digest::hash_domain(
        ACTION_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&proof_fields[1].1)?,
    ))
}

fn numbered_map(values: Vec<CanonicalValue>) -> CanonicalValue {
    CanonicalValue::Map(
        values
            .into_iter()
            .enumerate()
            .map(|(index, value)| (CanonicalValue::Unsigned((index + 1) as u64), value))
            .collect(),
    )
}

fn utc_value(value: i64) -> CanonicalValue {
    if value >= 0 {
        CanonicalValue::Unsigned(u64::try_from(value).expect("non-negative test time fits u64"))
    } else {
        CanonicalValue::Negative(value)
    }
}

fn encode(value: &CanonicalValue) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(value)?)
}

fn device_session_authorization(session_id: DeviceSessionId, session_secret: [u8; 32]) -> String {
    format!(
        "{DEVICE_SESSION_AUTHORIZATION_SCHEME} {session_id}.{}",
        Base64UrlUnpadded::encode_string(&session_secret)
    )
}

fn assert_content_type(response: &axum::response::Response, expected: &str) {
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(expected)
    );
}

async fn response_bytes(response: axum::response::Response) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(to_bytes(response.into_body(), 64_000).await?.to_vec())
}

type DecodedDiscoveryPage = (Vec<(String, String)>, Option<String>);

fn decode_discovery_page(bytes: &[u8]) -> Result<DecodedDiscoveryPage, Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("discovery page must be a map".into());
    };
    if fields.len() != 7 || fields[0].1 != CanonicalValue::Unsigned(1) {
        return Err("discovery page fields are invalid".into());
    }
    let CanonicalValue::Array(items) = &fields[5].1 else {
        return Err("discovery items must be an array".into());
    };
    let items = items
        .iter()
        .map(|item| {
            let CanonicalValue::Map(item) = item else {
                return Err("discovery item must be a map".into());
            };
            let CanonicalValue::Text(join_request_id) = &item[0].1 else {
                return Err("discovery request ID must be text".into());
            };
            let CanonicalValue::Text(origin) = &item[3].1 else {
                return Err("discovery candidate origin must be text".into());
            };
            Ok((join_request_id.clone(), origin.clone()))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let next_after = match &fields[6].1 {
        CanonicalValue::Null => None,
        CanonicalValue::Text(value) => {
            let decoded = Base64UrlUnpadded::decode_vec(value)?;
            let CanonicalValue::Map(cursor) = decode_deterministic_cbor(&decoded)? else {
                return Err("discovery cursor must be a canonical map".into());
            };
            if cursor.len() != 2 {
                return Err("discovery cursor field count is invalid".into());
            }
            Some(value.clone())
        }
        _ => return Err("discovery next_after must be text or null".into()),
    };
    Ok((items, next_after))
}

fn decode_v2_pending_package(bytes: &[u8]) -> Result<(String, Sha256Digest), Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("V2 discovery page must be a map".into());
    };
    if fields.len() != 7 || fields[0].1 != CanonicalValue::Unsigned(2) {
        return Err("V2 discovery page fields are invalid".into());
    }
    let CanonicalValue::Array(items) = &fields[5].1 else {
        return Err("V2 discovery items must be an array".into());
    };
    let [CanonicalValue::Map(item)] = items.as_slice() else {
        return Err("V2 discovery page must contain exactly one item".into());
    };
    if item.len() != 9 {
        return Err("V2 discovery item fields are invalid".into());
    }
    let CanonicalValue::Text(join_request_id) = &item[0].1 else {
        return Err("V2 discovery request ID must be text".into());
    };
    let CanonicalValue::Bytes(candidate_key_package_digest) = &item[8].1 else {
        return Err("V2 candidate KeyPackage digest must be bytes".into());
    };
    Ok((
        join_request_id.clone(),
        Sha256Digest::from_bytes(candidate_key_package_digest.as_slice().try_into()?),
    ))
}

fn assert_membership_phase(bytes: &[u8], expected_phase: u64) -> Result<(), Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("membership receipt must be a map".into());
    };
    assert!(matches!(fields[0].1, CanonicalValue::Unsigned(1 | 2)));
    assert_eq!(fields[3].1, CanonicalValue::Unsigned(expected_phase));
    Ok(())
}

fn membership_receipt_request_digest(bytes: &[u8]) -> Result<Sha256Digest, Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("membership receipt must be a map".into());
    };
    let CanonicalValue::Bytes(digest) = &fields[2].1 else {
        return Err("membership request digest must be bytes".into());
    };
    Ok(Sha256Digest::from_bytes(digest.as_slice().try_into()?))
}

fn test_candidate_key_package_digest(candidate: &ActiveDevice) -> Sha256Digest {
    Sha256Digest::hash_domain(
        b"test-mls-key-package\0",
        candidate.device.verifying_key().as_bytes(),
    )
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
    signed_event(
        root,
        identity_id,
        1,
        None,
        occurred_at,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn device_add(
    root: &SigningKey,
    device: &SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    previous_hash: Sha256Digest,
    sequence: u64,
    occurred_at: i64,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let root_key = public_key(root)?;
    let device_key = public_key(device)?;
    let certificate_unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        device_id,
        device_key,
        DeviceEncryptionPublicKey::try_from([7_u8; 32])?,
        root_key,
        UtcMillis::new(occurred_at - 1)?,
    )?;
    let certificate = DeviceCertificateV1::signed(
        certificate_unsigned.clone(),
        signature(
            root,
            &device_certificate_signature_input(certificate_unsigned.signing_digest()?),
        ),
    )?;
    signed_event(
        root,
        identity_id,
        sequence,
        Some(previous_hash),
        occurred_at,
        IdentityLogEventPayloadV1::DeviceAdd { certificate },
    )
}

fn signed_event(
    signer: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous_hash: Option<Sha256Digest>,
    occurred_at: i64,
    payload: IdentityLogEventPayloadV1,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let signer_key = public_key(signer)?;
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        dtx_wire::SafeUint::new(sequence)?,
        previous_hash,
        UtcMillis::new(occurred_at)?,
        payload,
        signer_key,
    )?;
    Ok(IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            signer,
            &identity_log_signature_input(unsigned.signing_digest()?),
        ),
    )?)
}

fn public_key(key: &SigningKey) -> Result<SigningPublicKey, Box<dyn Error>> {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).map_err(Into::into)
}

fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now_utc_millis(&self) -> Result<i64, ClockError> {
        Ok(self.0)
    }
}
