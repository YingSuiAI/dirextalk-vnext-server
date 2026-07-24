#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{
    error::Error,
    net::SocketAddr,
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
    Clock, ClockError, ConversationId, DeviceEnrollmentChallengeId, DeviceId, DeviceSessionId,
    IdentityId, InviteCapabilityId, JoinRequestId, KeyPackageId, RequestId, Revision, TenantId,
};
use dtx_federated_identity::{
    MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE, MlsV5RecoveryAuthorizationQuery,
};
use dtx_group_node::{
    DEVICE_SESSION_AUTHORIZATION_SCHEME, GROUP_ACTION_RECEIPT_CONTENT_TYPE,
    GROUP_APPROVE_JOIN_CONTENT_TYPE, GROUP_APPROVE_JOIN_V2_CONTENT_TYPE, GROUP_CREATE_CONTENT_TYPE,
    GROUP_GRANT_ADMIN_CONTENT_TYPE, GROUP_ISSUE_INVITE_CONTENT_TYPE,
    GROUP_JOIN_REQUEST_CONTENT_TYPE, GROUP_JOIN_REQUEST_PAGE_CONTENT_TYPE,
    GROUP_JOIN_REQUEST_PAGE_V2_CONTENT_TYPE, GROUP_JOIN_REQUEST_V2_CONTENT_TYPE,
    GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE, GROUP_QUERY_PROOF_HEADER, GROUP_SCOPE_PATH_TEMPLATE,
    GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE, GROUP_SERVICE_DESCRIPTOR_PATH, GroupNodeState,
    IDENTITY_ORIGIN_HEADER, MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE, MLS_COMMIT_CONTENT_TYPE,
    MLS_COMMIT_FEED_CONTENT_TYPE, MLS_COMMIT_FEED_V2_CONTENT_TYPE, MLS_COMMIT_FEED_V3_CONTENT_TYPE,
    MLS_COMMIT_PROOF_HEADER, MLS_COMMIT_RECEIPT_CONTENT_TYPE, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE,
    MLS_COMMIT_RECEIPT_V4_CONTENT_TYPE, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE,
    MLS_COMMIT_V3_CONTENT_TYPE, MLS_COMMIT_V4_CONTENT_TYPE, MLS_COMMIT_V5_CONTENT_TYPE,
    MLS_CONFIRMATION_CONTENT_TYPE, MLS_CONFIRMATION_PROOF_HEADER, MLS_CONFIRMATION_V3_CONTENT_TYPE,
    RECEIPT_QUERY_PROOF_HEADER, group_router_with_state,
};
use dtx_group_persistence::{
    GroupControlCommand, GroupControlDisposition, GroupControlOperation, GroupControlRejection,
    GroupControlRepository, GroupMembershipRepository, GroupPgStore,
    MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, MlsCommitAuthorization, MlsCommitCommand,
    MlsDeviceJoinConfirmation, mls_candidate_proof_digest, mls_candidate_proof_signature_input,
    mls_device_confirmation_signature_input, mls_opaque_commit_digest, mls_recovery_scope_digest,
    mls_v5_controller_consent_digest, mls_v5_controller_consent_signature_input,
};
use dtx_group_policy::GroupScope;
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_node::{
    DEVICE_ENROLLMENT_CHALLENGE_PATH, DEVICE_ENROLLMENT_CONTENT_TYPE, DEVICE_ENROLLMENT_PATH,
    DEVICE_REVOKE_PATH_TEMPLATE, HISTORY_RECOVERY_REQUEST_CONTENT_TYPE,
    IDENTITY_LOG_EVENT_CONTENT_TYPE, IdentityBootstrapState, KEY_PACKAGE_CLAIM_PATH,
    KEY_PACKAGE_CLAIM_V2_CONTENT_TYPE, KEY_PACKAGE_PUBLISH_PATH_TEMPLATE,
    KEY_PACKAGE_PUBLISH_V2_CONTENT_TYPE, MLS_V5_RECOVERY_AUTHORIZATION_PATH_TEMPLATE,
    identity_bootstrap_router, identity_bootstrap_router_with_state,
};
use dtx_identity_persistence::{
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceSessionCompletionCommand, DeviceSessionOutcome,
    DeviceSessionRepository, HISTORY_RECOVERY_REQUEST_HASH_DOMAIN, IdentityAppendCommand,
    IdentityAppendOutcome, IdentityLogHead, IdentityLogRepository, IdentityPgStore,
    KEY_PACKAGE_BYTES_HASH_DOMAIN, device_session_proof_input,
    history_recovery_request_signature_input, history_recovery_request_unsigned_canonical_bytes,
    key_package_publish_signature_input,
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
const MLS_COMMIT_REQUEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-commit-request.v3\0";
const MLS_COMMIT_FEDERATED_BINDING_HASH_DOMAIN: &[u8] =
    b"dirextalk.mls-commit-federated-binding.v3\0";
const MLS_COMMIT_FEDERATED_PROOF_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.mls-commit-federated-proof-signature.v3\0";

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
    let wrong_join_action = send_group_query(
        app.clone(),
        &first_target,
        &remote_admin,
        &remote_origin,
        true,
        group_query_proof_for_action(
            &remote_admin,
            &remote_origin,
            scope,
            &first_target,
            2,
            1_000,
        )?,
    )
    .await?;
    assert_eq!(wrong_join_action.status(), StatusCode::UNPROCESSABLE_ENTITY);
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
async fn active_member_fetches_consecutive_v30_v32_feed_and_removed_member_converges()
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
    let bootstrap_receipt = response_bytes(bootstrap).await?;
    let (bootstrap_receipt_digest, bootstrap_head) = mls_receipt_facts(&bootstrap_receipt)?;
    let bootstrap_confirmation_path = format!("{bootstrap_path}/confirmations/{}", owner.device_id);
    let bootstrap_confirmation = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&bootstrap_confirmation_path)
                .header(header::CONTENT_TYPE, MLS_CONFIRMATION_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(owner.session_id, owner.session_secret),
                )
                .body(Body::from(mls_confirmation_body(
                    &owner,
                    bootstrap_submission,
                    bootstrap_receipt_digest,
                    bootstrap_head,
                )?))?,
        )
        .await?;
    assert_eq!(bootstrap_confirmation.status(), StatusCode::NO_CONTENT);

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
    let grant_revision = GroupMembershipRepository
        .load_policy(&group_store, tenant_id, scope)
        .await?
        .revision();
    let grant_path = format!("{scope_path}/admins/{}", member.identity_id);
    let grant_key = "commit-feed-grant-admin-0001";
    let grant = send_mutation(
        app.clone(),
        "PUT",
        &grant_path,
        GROUP_GRANT_ADMIN_CONTENT_TYPE,
        grant_key,
        &owner,
        grant_admin_body(
            &owner,
            scope,
            &grant_path,
            grant_key,
            1_050,
            grant_revision,
            member.identity_id,
        )?,
    )
    .await?;
    assert_eq!(grant.status(), StatusCode::CREATED);
    let next_revision = GroupMembershipRepository
        .load_policy(&group_store, tenant_id, scope)
        .await?
        .revision();
    let peer_commit = vec![0x63; 48];
    let (peer_receipt, peer_head) = admit_local_v30_member(
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
    let wrong_feed_action = send_local_commit_feed(
        app.clone(),
        &target,
        &member,
        group_query_proof_for_action(&member, AUDIENCE, scope, &target, 1, 1_100)?,
    )
    .await?;
    assert_eq!(wrong_feed_action.status(), StatusCode::UNPROCESSABLE_ENTITY);
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
    let items = decode_commit_feed(&feed_bytes, 1, 2)?;
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
    assert!(decode_commit_feed(&response_bytes(caught_up).await?, 1, 3)?.is_empty());

    let denied = send_local_commit_feed(
        app.clone(),
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

    let removal_revision = GroupMembershipRepository
        .load_policy(&group_store, tenant_id, scope)
        .await?
        .revision();
    let scope_id = scope_path.rsplit('/').next().ok_or("scope id")?;
    let removal_preconditions: (i64, String, bool, i64, bool, i64, Vec<u8>) = sqlx::query_as(
        "SELECT policy.policy_revision,policy.owner_identity_id,
                EXISTS (SELECT 1 FROM groups.members member
                         WHERE member.tenant_id=policy.tenant_id
                           AND member.scope_kind=policy.scope_kind
                           AND member.scope_id=policy.scope_id AND member.identity_id=$3),
                (SELECT count(*) FROM groups.mls_device_members leaf
                  WHERE leaf.tenant_id=policy.tenant_id AND leaf.scope_kind=policy.scope_kind
                    AND leaf.scope_id=policy.scope_id AND leaf.identity_id=$3
                    AND leaf.state IN ('pending_confirmation','active')),
                EXISTS (SELECT 1 FROM groups.mls_device_members leaf
                         WHERE leaf.tenant_id=policy.tenant_id
                           AND leaf.scope_kind=policy.scope_kind
                           AND leaf.scope_id=policy.scope_id AND leaf.identity_id=$3
                           AND leaf.device_id=$4 AND leaf.state='active'),
                head.epoch,head.head_digest
           FROM groups.policy_heads policy
           JOIN groups.mls_heads head USING (tenant_id,scope_kind,scope_id)
          WHERE policy.tenant_id=$1 AND policy.scope_kind='private_conversation'
            AND policy.scope_id=$2",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .bind(scope_id)
    .bind(peer.identity_id.to_string())
    .bind(uuid::Uuid::from(peer.device_id))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(
        removal_preconditions.0,
        i64::try_from(removal_revision.get())?
    );
    assert_eq!(removal_preconditions.1, owner.identity_id.to_string());
    assert!(removal_preconditions.2);
    assert_eq!(removal_preconditions.3, 1);
    assert!(removal_preconditions.4);
    assert_eq!(removal_preconditions.5, 3);
    assert_eq!(removal_preconditions.6, peer_head.as_bytes());
    let admin_submission = RequestId::new();
    let admin_path = format!("{scope_path}/mls-commits/{admin_submission}");
    let admin_attempt = send_mutation(
        app.clone(),
        "POST",
        &admin_path,
        MLS_COMMIT_V4_CONTENT_TYPE,
        "commit-feed-admin-remove-0001",
        &member,
        mls_commit_body_v4(
            &member,
            &peer,
            scope,
            admin_submission,
            3,
            peer_head,
            removal_revision,
            vec![0x74; 48],
        )?,
    )
    .await?;
    assert_eq!(admin_attempt.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let removal_submission = RequestId::new();
    let removal_path = format!("{scope_path}/mls-commits/{removal_submission}");
    let removal_key = "commit-feed-owner-remove-0001";
    let removal_body = mls_commit_body_v4(
        &owner,
        &peer,
        scope,
        removal_submission,
        3,
        peer_head,
        removal_revision,
        vec![0x75; 48],
    )?;
    let removed = send_mutation(
        app.clone(),
        "POST",
        &removal_path,
        MLS_COMMIT_V4_CONTENT_TYPE,
        removal_key,
        &owner,
        removal_body.clone(),
    )
    .await?;
    assert_eq!(removed.status(), StatusCode::CREATED);
    assert_content_type(&removed, MLS_COMMIT_RECEIPT_V4_CONTENT_TYPE);
    let removal_receipt = response_bytes(removed).await?;
    assert_eq!(mls_receipt_epoch(&removal_receipt)?, 4);

    let replay = send_mutation(
        app.clone(),
        "POST",
        &removal_path,
        MLS_COMMIT_V4_CONTENT_TYPE,
        removal_key,
        &owner,
        removal_body,
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(replay).await?, removal_receipt);
    let conflict = send_mutation(
        app.clone(),
        "POST",
        &removal_path,
        MLS_COMMIT_V4_CONTENT_TYPE,
        removal_key,
        &owner,
        mls_commit_body_v4(
            &owner,
            &peer,
            scope,
            removal_submission,
            3,
            peer_head,
            removal_revision,
            vec![0x76; 48],
        )?,
    )
    .await?;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    let removal_target = format!("{scope_path}/mls-commits?after_epoch=3&limit=64");
    let legacy_feed = send_local_commit_feed(
        app.clone(),
        &removal_target,
        &owner,
        group_query_proof_for_action(&owner, AUDIENCE, scope, &removal_target, 2, 1_400)?,
    )
    .await?;
    assert_eq!(legacy_feed.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let final_feed = send_local_commit_feed_v2(
        app.clone(),
        &removal_target,
        &peer,
        group_query_proof_for_action(&peer, AUDIENCE, scope, &removal_target, 2, 1_500)?,
    )
    .await?;
    assert_eq!(final_feed.status(), StatusCode::OK);
    assert_content_type(&final_feed, MLS_COMMIT_FEED_V2_CONTENT_TYPE);
    let final_items = decode_commit_feed(&response_bytes(final_feed).await?, 2, 3)?;
    assert_eq!(final_items.len(), 1);
    assert_eq!(final_items[0].0, removal_receipt);
    let after_removal_target = format!("{scope_path}/mls-commits?after_epoch=4&limit=64");
    let removed_access = send_local_commit_feed_v2(
        app,
        &after_removal_target,
        &peer,
        group_query_proof_for_action(&peer, AUDIENCE, scope, &after_removal_target, 2, 1_600)?,
    )
    .await?;
    assert_eq!(removed_access.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one V40 boundary test keeps identity-head freshness, scoped package consumption, confirmation, revocation, replay, and feed order coherent"
)]
async fn v5_recovery_add_and_revoked_leaf_removal_are_http_replay_safe()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let owner = enroll_active_device(&identity_store, 131, 132, 133, [134; 32]).await?;
    let identity_app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            identity_store.clone(),
            Arc::new(FixedClock(NOW)),
            AUDIENCE,
        ),
    );
    let tenant_id = TenantId::new();
    let group_app = group_router_with_state(
        GroupNodeState::with_clock(group_store.clone(), tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(SigningKey::from_bytes(&[135; 32]))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                std::iter::empty::<String>(),
            )?,
    );
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_key = "v5-recovery-group-create-0001";
    let create = send_mutation(
        group_app.clone(),
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
    let bootstrap_key = "v5-recovery-bootstrap-0001";
    let bootstrap = send_mutation(
        group_app.clone(),
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
    let bootstrap_receipt = response_bytes(bootstrap).await?;
    let (bootstrap_receipt_digest, bootstrap_head) = mls_receipt_facts(&bootstrap_receipt)?;
    let bootstrap_confirmation = group_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "{bootstrap_path}/confirmations/{}",
                    owner.device_id
                ))
                .header(header::CONTENT_TYPE, MLS_CONFIRMATION_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(owner.session_id, owner.session_secret),
                )
                .body(Body::from(mls_confirmation_body(
                    &owner,
                    bootstrap_submission,
                    bootstrap_receipt_digest,
                    bootstrap_head,
                )?))?,
        )
        .await?;
    assert_eq!(bootstrap_confirmation.status(), StatusCode::NO_CONTENT);

    let recovery_a = prepare_scoped_history_recovery(
        identity_app.clone(),
        &identity_store,
        &owner,
        scope,
        136,
        137,
        [138; 32],
        [139; 32],
        "v5-history-recovery-a",
        NOW - 200,
    )
    .await?;
    let recovery_b = prepare_scoped_history_recovery(
        identity_app.clone(),
        &identity_store,
        &owner,
        scope,
        140,
        141,
        [142; 32],
        [143; 32],
        "v5-history-recovery-b",
        NOW - 100,
    )
    .await?;
    let current_identity_head = IdentityLogRepository::new()
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing after recovery approvals")?
        .head();
    assert_ne!(recovery_a.approved_head, current_identity_head);
    assert_eq!(recovery_b.approved_head, current_identity_head);

    // Both packages are deliberately published at B's current identity head.
    // A can therefore fail only because its approved recovery head is stale.
    let package_a = publish_scoped_recovery_key_package(
        identity_app.clone(),
        &owner,
        &recovery_a,
        scope,
        current_identity_head,
        vec![0xa1; 64],
        "v5-scoped-package-a-0001",
    )
    .await?;
    let package_b = publish_scoped_recovery_key_package(
        identity_app.clone(),
        &owner,
        &recovery_b,
        scope,
        current_identity_head,
        vec![0xb1; 64],
        "v5-scoped-package-b-0001",
    )
    .await?;

    let stale_submission = RequestId::new();
    let stale_path = format!("{scope_path}/mls-commits/{stale_submission}");
    let stale_key = "v5-stale-recovery-add-0001";
    let stale = send_mutation(
        group_app.clone(),
        "POST",
        &stale_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        stale_key,
        &owner,
        mls_recovery_add_body_v5(
            &owner,
            &recovery_a.device,
            scope,
            stale_submission,
            stale_key,
            1,
            bootstrap_head,
            vec![0xa2; 48],
            package_a,
            recovery_a.request_id,
            recovery_a.request_digest,
        )?,
    )
    .await?;
    assert_eq!(stale.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_safe_group_error(stale, "GROUP_ACTION_PROOF_INVALID").await?;
    assert_eq!(v5_intent_count(harness.admin_pool(), tenant_id).await?, 0);

    let add_submission = RequestId::new();
    let add_path = format!("{scope_path}/mls-commits/{add_submission}");
    let add_key = "v5-current-recovery-add-0001";
    let add_commit = vec![0xb2; 48];
    let add_body = mls_recovery_add_body_v5(
        &owner,
        &recovery_b.device,
        scope,
        add_submission,
        add_key,
        1,
        bootstrap_head,
        add_commit.clone(),
        package_b,
        recovery_b.request_id,
        recovery_b.request_digest,
    )?;
    let added = send_mutation(
        group_app.clone(),
        "POST",
        &add_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        add_key,
        &owner,
        add_body.clone(),
    )
    .await?;
    assert_eq!(added.status(), StatusCode::CREATED);
    assert_content_type(&added, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE);
    let add_receipt = response_bytes(added).await?;
    assert_eq!(mls_receipt_epoch(&add_receipt)?, 2);
    let (add_receipt_digest, add_head) = mls_receipt_facts(&add_receipt)?;

    let add_replay = send_mutation(
        group_app.clone(),
        "POST",
        &add_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        add_key,
        &owner,
        add_body,
    )
    .await?;
    assert_eq!(add_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(add_replay).await?, add_receipt);
    let add_conflict = send_mutation(
        group_app.clone(),
        "POST",
        &add_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        add_key,
        &owner,
        mls_recovery_add_body_v5(
            &owner,
            &recovery_b.device,
            scope,
            add_submission,
            add_key,
            1,
            bootstrap_head,
            vec![0xb3; 48],
            package_b,
            recovery_b.request_id,
            recovery_b.request_digest,
        )?,
    )
    .await?;
    assert_eq!(add_conflict.status(), StatusCode::CONFLICT);

    let add_confirmation_path = format!("{add_path}/confirmations/{}", recovery_b.device.device_id);
    let add_confirmation = group_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&add_confirmation_path)
                .header(header::CONTENT_TYPE, MLS_CONFIRMATION_V3_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(
                        recovery_b.device.session_id,
                        recovery_b.device.session_secret,
                    ),
                )
                .body(Body::from(mls_confirmation_body(
                    &recovery_b.device,
                    add_submission,
                    add_receipt_digest,
                    add_head,
                )?))?,
        )
        .await?;
    assert_eq!(add_confirmation.status(), StatusCode::NO_CONTENT);
    let scope_id = scope_path.rsplit('/').next().ok_or("scope id")?;
    let recovered_leaf_state: String = sqlx::query_scalar(
        "SELECT state FROM groups.mls_device_members
          WHERE tenant_id=$1 AND scope_kind='private_conversation' AND scope_id=$2
            AND identity_id=$3 AND device_id=$4",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .bind(scope_id)
    .bind(owner.identity_id.to_string())
    .bind(uuid::Uuid::from(recovery_b.device.device_id))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(recovered_leaf_state, "active");

    let pre_revoke_identity_head = IdentityLogRepository::new()
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing before recovery leaf revoke")?
        .head();
    let before_revoke_submission = RequestId::new();
    let before_revoke_path = format!("{scope_path}/mls-commits/{before_revoke_submission}");
    let before_revoke_key = "v5-remove-before-revoke-0001";
    let before_revoke = send_mutation(
        group_app.clone(),
        "POST",
        &before_revoke_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        before_revoke_key,
        &owner,
        mls_device_remove_body_v5(
            &owner,
            &recovery_b.device,
            scope,
            before_revoke_submission,
            before_revoke_key,
            2,
            add_head,
            vec![0xc1; 48],
            pre_revoke_identity_head.hash(),
        )?,
    )
    .await?;
    assert_eq!(before_revoke.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_safe_group_error(before_revoke, "GROUP_ACTION_PROOF_INVALID").await?;
    assert_eq!(v5_intent_count(harness.admin_pool(), tenant_id).await?, 1);

    let revoke_head = revoke_device_over_http(
        identity_app,
        &identity_store,
        &owner,
        recovery_b.device.device_id,
        "v5-revoke-recovered-device-0001",
        NOW,
    )
    .await?;

    let mismatched_submission = RequestId::new();
    let mismatched_path = format!("{scope_path}/mls-commits/{mismatched_submission}");
    let mismatched_key = "v5-remove-mismatched-target-0001";
    let mismatched = send_mutation(
        group_app.clone(),
        "POST",
        &mismatched_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        mismatched_key,
        &owner,
        mls_device_remove_body_v5(
            &owner,
            &recovery_a.device,
            scope,
            mismatched_submission,
            mismatched_key,
            2,
            add_head,
            vec![0xc2; 48],
            revoke_head,
        )?,
    )
    .await?;
    assert_eq!(mismatched.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_safe_group_error(mismatched, "GROUP_ACTION_PROOF_INVALID").await?;
    assert_eq!(v5_intent_count(harness.admin_pool(), tenant_id).await?, 1);

    let remove_submission = RequestId::new();
    let remove_path = format!("{scope_path}/mls-commits/{remove_submission}");
    let remove_key = "v5-remove-current-target-0001";
    let remove_commit = vec![0xc3; 48];
    let remove_body = mls_device_remove_body_v5(
        &owner,
        &recovery_b.device,
        scope,
        remove_submission,
        remove_key,
        2,
        add_head,
        remove_commit.clone(),
        revoke_head,
    )?;
    let removed = send_mutation(
        group_app.clone(),
        "POST",
        &remove_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        remove_key,
        &owner,
        remove_body.clone(),
    )
    .await?;
    assert_eq!(removed.status(), StatusCode::CREATED);
    assert_content_type(&removed, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE);
    let remove_receipt = response_bytes(removed).await?;
    assert_eq!(mls_receipt_epoch(&remove_receipt)?, 3);

    let remove_replay = send_mutation(
        group_app.clone(),
        "POST",
        &remove_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        remove_key,
        &owner,
        remove_body,
    )
    .await?;
    assert_eq!(remove_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(remove_replay).await?, remove_receipt);
    let remove_conflict = send_mutation(
        group_app.clone(),
        "POST",
        &remove_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        remove_key,
        &owner,
        mls_device_remove_body_v5(
            &owner,
            &recovery_b.device,
            scope,
            remove_submission,
            remove_key,
            2,
            add_head,
            vec![0xc4; 48],
            revoke_head,
        )?,
    )
    .await?;
    assert_eq!(remove_conflict.status(), StatusCode::CONFLICT);

    let feed_target = format!("{scope_path}/mls-commits?after_epoch=1&limit=64");
    let feed = send_local_commit_feed_v3(
        group_app,
        &feed_target,
        &owner,
        group_query_proof_for_action(&owner, AUDIENCE, scope, &feed_target, 2, 1_900)?,
    )
    .await?;
    assert_eq!(feed.status(), StatusCode::OK);
    assert_content_type(&feed, MLS_COMMIT_FEED_V3_CONTENT_TYPE);
    assert_eq!(
        decode_commit_feed(&response_bytes(feed).await?, 3, 1)?,
        vec![(add_receipt, add_commit), (remove_receipt, remove_commit)]
    );
    assert_eq!(v5_intent_count(harness.admin_pool(), tenant_id).await?, 2);
    let v5_receipt_rows: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM groups.mls_commit_receipts AS receipt
           JOIN groups.mls_commit_intents AS intent
             USING (tenant_id,submission_id)
          WHERE receipt.tenant_id=$1 AND intent.protocol_version=5",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(v5_receipt_rows, 2);
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the two-database acceptance keeps the complete externally observable V5 recovery workflow together"
)]
async fn federated_v5_recovery_and_removal_use_only_fresh_origin_identity_facts()
-> Result<(), Box<dyn Error>> {
    let origin_harness = support::PostgresHarness::start().await?;
    let group_harness = support::PostgresHarness::start().await?;
    let origin_store =
        IdentityPgStore::connect(origin_harness.identity_runtime_options(), 8).await?;
    let group_identity_store =
        IdentityPgStore::connect(group_harness.identity_runtime_options(), 4).await?;
    let group_store = GroupPgStore::connect(group_harness.group_runtime_options(), 4).await?;

    let origin_controller = enroll_active_device(&origin_store, 151, 152, 153, [154; 32]).await?;
    replicate_initial_identity(&group_identity_store, &origin_controller, 152, NOW).await?;
    let group_controller = issue_same_identity_device_session(
        &group_identity_store,
        &origin_controller,
        SigningKey::from_bytes(&origin_controller.device.to_bytes()),
        origin_controller.device_id,
        [155; 32],
        "federated-v5-group-controller",
        156,
    )
    .await?;
    let identity_app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            origin_store.clone(),
            Arc::new(FixedClock(NOW)),
            AUDIENCE,
        ),
    );
    let (identity_origin, identity_server) =
        start_identity_server_at(origin_store.clone(), NOW).await?;
    let tenant_id = TenantId::new();
    let group_app = group_router_with_state(
        GroupNodeState::with_clock(group_store, tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(SigningKey::from_bytes(&[157; 32]))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                [identity_origin.clone()],
            )?,
    );
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_key = "federated-v5-create-0001";
    let create = send_mutation(
        group_app.clone(),
        "PUT",
        &scope_path,
        GROUP_CREATE_CONTENT_TYPE,
        create_key,
        &group_controller,
        create_body(&group_controller, scope, &scope_path, create_key, 1_000)?,
    )
    .await?;
    assert_eq!(create.status(), StatusCode::CREATED);

    let bootstrap_submission = RequestId::new();
    let bootstrap_path = format!("{scope_path}/mls-commits/{bootstrap_submission}");
    let bootstrap_key = "federated-v5-bootstrap-0001";
    let bootstrap = send_mutation(
        group_app.clone(),
        "POST",
        &bootstrap_path,
        MLS_COMMIT_CONTENT_TYPE,
        bootstrap_key,
        &group_controller,
        mls_commit_body(
            &group_controller,
            &group_controller,
            scope,
            bootstrap_submission,
            bootstrap_key,
            0,
            Sha256Digest::from_bytes([0; 32]),
            vec![0xd1; 48],
            MlsCommitAuthorization::OwnerBootstrap,
        )?,
    )
    .await?;
    assert_eq!(bootstrap.status(), StatusCode::CREATED);
    let bootstrap_receipt = response_bytes(bootstrap).await?;
    let (bootstrap_receipt_digest, bootstrap_head) = mls_receipt_facts(&bootstrap_receipt)?;
    let bootstrap_confirmation = group_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "{bootstrap_path}/confirmations/{}",
                    group_controller.device_id
                ))
                .header(header::CONTENT_TYPE, MLS_CONFIRMATION_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(
                        group_controller.session_id,
                        group_controller.session_secret,
                    ),
                )
                .body(Body::from(mls_confirmation_body(
                    &group_controller,
                    bootstrap_submission,
                    bootstrap_receipt_digest,
                    bootstrap_head,
                )?))?,
        )
        .await?;
    assert_eq!(bootstrap_confirmation.status(), StatusCode::NO_CONTENT);

    let stale_recovery = prepare_scoped_history_recovery(
        identity_app.clone(),
        &origin_store,
        &origin_controller,
        scope,
        158,
        159,
        [160; 32],
        [161; 32],
        "federated-v5-history-recovery",
        NOW - 200,
    )
    .await?;
    let recovery = prepare_scoped_history_recovery(
        identity_app.clone(),
        &origin_store,
        &origin_controller,
        scope,
        162,
        163,
        [164; 32],
        [165; 32],
        "federated-v5-current-history-recovery",
        NOW - 100,
    )
    .await?;
    let current_origin_head = IdentityLogRepository::new()
        .load(&origin_store, origin_controller.identity_id)
        .await?
        .ok_or("origin identity missing after recovery approval")?
        .head();
    assert_ne!(stale_recovery.approved_head, current_origin_head);
    assert_eq!(recovery.approved_head, current_origin_head);
    let stale_package_digest = publish_scoped_recovery_key_package(
        identity_app.clone(),
        &origin_controller,
        &stale_recovery,
        scope,
        current_origin_head,
        vec![0xd0; 64],
        "federated-v5-stale-package-0001",
    )
    .await?;
    let package_digest = publish_scoped_recovery_key_package(
        identity_app.clone(),
        &origin_controller,
        &recovery,
        scope,
        current_origin_head,
        vec![0xd2; 64],
        "federated-v5-package-0001",
    )
    .await?;
    seed_recovery_authorization_artifacts(
        origin_harness.admin_pool(),
        &origin_controller,
        &stale_recovery,
        stale_package_digest,
    )
    .await?;
    seed_recovery_authorization_artifacts(
        origin_harness.admin_pool(),
        &origin_controller,
        &recovery,
        package_digest,
    )
    .await?;
    let stale_group_identity = IdentityLogRepository::new()
        .load(&group_identity_store, origin_controller.identity_id)
        .await?
        .ok_or("group-side controller identity missing")?;
    assert_eq!(
        stale_group_identity
            .projection()
            .device_status(recovery.device.device_id),
        None,
        "the group database must not receive the recovered identity leaf"
    );

    let authorization_query = MlsV5RecoveryAuthorizationQuery::new(
        origin_controller.identity_id,
        recovery.request_id,
        recovery.device.device_id,
        origin_controller.device_id,
        current_origin_head.hash(),
        package_digest,
        recovery.request_digest,
        recovery.scope_digest,
    );
    let authorization_path = format!(
        "{}?{}",
        MLS_V5_RECOVERY_AUTHORIZATION_PATH_TEMPLATE
            .replace("{identity_id}", &origin_controller.identity_id.to_string())
            .replace("{request_id}", &recovery.request_id.to_string()),
        authorization_query.canonical_query(),
    );
    let wrong_media = identity_app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&authorization_path)
                .header(header::ACCEPT, "application/octet-stream")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(wrong_media.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let invented_proof = identity_app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&authorization_path)
                .header(header::ACCEPT, MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE)
                .header(header::AUTHORIZATION, "Bearer invented-portable-proof")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(invented_proof.status(), StatusCode::UNPROCESSABLE_ENTITY);
    sqlx::query(
        "UPDATE messaging.history_recovery_offers
            SET expires_at_ms=$3
          WHERE identity_id=$1 AND request_id=$2",
    )
    .bind(origin_controller.identity_id.to_string())
    .bind(*recovery.request_id.as_uuid())
    .bind(NOW)
    .execute(origin_harness.admin_pool())
    .await?;
    let expired = identity_app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&authorization_path)
                .header(header::ACCEPT, MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(expired.status(), StatusCode::NOT_FOUND);
    sqlx::query(
        "UPDATE messaging.history_recovery_offers
            SET expires_at_ms=$3
          WHERE identity_id=$1 AND request_id=$2",
    )
    .bind(origin_controller.identity_id.to_string())
    .bind(*recovery.request_id.as_uuid())
    .bind(NOW + 60_000)
    .execute(origin_harness.admin_pool())
    .await?;

    let stale_submission = RequestId::new();
    let stale_path = format!("{scope_path}/mls-commits/{stale_submission}");
    let stale_key = "federated-v5-stale-head-0001";
    let stale_commit = vec![0xcf; 48];
    let stale_body = mls_recovery_add_body_v5(
        &origin_controller,
        &stale_recovery.device,
        scope,
        stale_submission,
        stale_key,
        1,
        bootstrap_head,
        stale_commit.clone(),
        stale_package_digest,
        stale_recovery.request_id,
        stale_recovery.request_digest,
    )?;
    let stale_request_digest = mls_recovery_add_request_digest_v5(
        &origin_controller,
        &stale_recovery.device,
        scope,
        stale_submission,
        stale_key,
        1,
        bootstrap_head,
        stale_commit,
        stale_package_digest,
        stale_recovery.request_id,
        stale_recovery.request_digest,
    )?;
    let stale = send_federated_mls_commit_v5(
        group_app.clone(),
        &stale_path,
        stale_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &stale_path,
            stale_submission,
            stale_request_digest,
            Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, stale_key.as_bytes()),
            900,
        )?,
        stale_body,
    )
    .await?;
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        v5_intent_count(group_harness.admin_pool(), tenant_id).await?,
        0
    );

    for (index, (candidate_package, request_digest, scope_digest)) in [
        (
            Sha256Digest::from_bytes([0xc1; 32]),
            recovery.request_digest,
            recovery.scope_digest,
        ),
        (
            package_digest,
            Sha256Digest::from_bytes([0xc2; 32]),
            recovery.scope_digest,
        ),
        (
            package_digest,
            recovery.request_digest,
            Sha256Digest::from_bytes([0xc3; 32]),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let submission_id = RequestId::new();
        let path = format!("{scope_path}/mls-commits/{submission_id}");
        let key = format!("federated-v5-mismatch-{index:04}");
        let commit = vec![0xc4_u8.saturating_add(u8::try_from(index)?); 48];
        let body = mls_recovery_add_body_v5_with_scope_digest(
            &origin_controller,
            &recovery.device,
            scope,
            submission_id,
            &key,
            1,
            bootstrap_head,
            commit.clone(),
            candidate_package,
            recovery.request_id,
            request_digest,
            scope_digest,
        )?;
        let request = mls_recovery_add_request_digest_v5_with_scope_digest(
            &origin_controller,
            &recovery.device,
            scope,
            submission_id,
            &key,
            1,
            bootstrap_head,
            commit,
            candidate_package,
            recovery.request_id,
            request_digest,
            scope_digest,
        )?;
        let rejected = send_federated_mls_commit_v5(
            group_app.clone(),
            &path,
            &key,
            &identity_origin,
            mls_commit_federated_proof(
                &origin_controller,
                &identity_origin,
                1,
                scope,
                &path,
                submission_id,
                request,
                Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, key.as_bytes()),
                950,
            )?,
            body,
        )
        .await?;
        assert!(
            matches!(
                rejected.status(),
                StatusCode::UNAUTHORIZED | StatusCode::UNPROCESSABLE_ENTITY
            ),
            "mismatch case {index} must fail closed"
        );
        assert_eq!(
            v5_intent_count(group_harness.admin_pool(), tenant_id).await?,
            0
        );
    }

    let add_submission = RequestId::new();
    let add_path = format!("{scope_path}/mls-commits/{add_submission}");
    let add_key = "federated-v5-add-0001";
    let add_commit = vec![0xd3; 48];
    let add_body = mls_recovery_add_body_v5(
        &origin_controller,
        &recovery.device,
        scope,
        add_submission,
        add_key,
        1,
        bootstrap_head,
        add_commit.clone(),
        package_digest,
        recovery.request_id,
        recovery.request_digest,
    )?;
    let add_request_digest = mls_recovery_add_request_digest_v5(
        &origin_controller,
        &recovery.device,
        scope,
        add_submission,
        add_key,
        1,
        bootstrap_head,
        add_commit,
        package_digest,
        recovery.request_id,
        recovery.request_digest,
    )?;
    let add_idempotency_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, add_key.as_bytes());
    let added = send_federated_mls_commit_v5(
        group_app.clone(),
        &add_path,
        add_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &add_path,
            add_submission,
            add_request_digest,
            add_idempotency_hash,
            1_000,
        )?,
        add_body.clone(),
    )
    .await?;
    assert_eq!(added.status(), StatusCode::CREATED);
    assert_content_type(&added, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE);
    let add_receipt = response_bytes(added).await?;
    let (add_receipt_digest, add_head) = mls_receipt_facts(&add_receipt)?;

    let add_replay = send_federated_mls_commit_v5(
        group_app.clone(),
        &add_path,
        add_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &add_path,
            add_submission,
            add_request_digest,
            add_idempotency_hash,
            1_100,
        )?,
        add_body,
    )
    .await?;
    assert_eq!(add_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(add_replay).await?, add_receipt);
    let add_readback = send_federated_mls_receipt_query_v5(
        group_app.clone(),
        &add_path,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            2,
            scope,
            &add_path,
            add_submission,
            add_request_digest,
            add_idempotency_hash,
            1_200,
        )?,
    )
    .await?;
    assert_eq!(add_readback.status(), StatusCode::OK);
    assert_eq!(response_bytes(add_readback).await?, add_receipt);

    let confirmation_path = format!("{add_path}/confirmations/{}", recovery.device.device_id);
    let confirmation_body = mls_confirmation_body(
        &recovery.device,
        add_submission,
        add_receipt_digest,
        add_head,
    )?;
    let confirmation = send_federated_confirmation(
        group_app.clone(),
        &confirmation_path,
        &identity_origin,
        mls_confirmation_proof(
            &recovery.device,
            &identity_origin,
            scope,
            &confirmation_path,
            add_submission,
            &confirmation_body,
            1_300,
        )?,
        confirmation_body,
    )
    .await?;
    assert_eq!(confirmation.status(), StatusCode::NO_CONTENT);

    let revoke_head = revoke_device_over_http(
        identity_app,
        &origin_store,
        &origin_controller,
        recovery.device.device_id,
        "federated-v5-revoke-0001",
        NOW,
    )
    .await?;
    let wrong_remove_submission = RequestId::new();
    let wrong_remove_path = format!("{scope_path}/mls-commits/{wrong_remove_submission}");
    let wrong_remove_key = "federated-v5-wrong-revoke-target-0001";
    let wrong_remove_commit = vec![0xce; 48];
    let wrong_remove_body = mls_device_remove_body_v5(
        &origin_controller,
        &stale_recovery.device,
        scope,
        wrong_remove_submission,
        wrong_remove_key,
        2,
        add_head,
        wrong_remove_commit.clone(),
        revoke_head,
    )?;
    let wrong_remove_request = mls_device_remove_request_digest_v5(
        &origin_controller,
        &stale_recovery.device,
        scope,
        wrong_remove_submission,
        wrong_remove_key,
        2,
        add_head,
        wrong_remove_commit,
        revoke_head,
    )?;
    let wrong_remove = send_federated_mls_commit_v5(
        group_app.clone(),
        &wrong_remove_path,
        wrong_remove_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &wrong_remove_path,
            wrong_remove_submission,
            wrong_remove_request,
            Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, wrong_remove_key.as_bytes()),
            1_350,
        )?,
        wrong_remove_body,
    )
    .await?;
    assert_eq!(wrong_remove.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        v5_intent_count(group_harness.admin_pool(), tenant_id).await?,
        1
    );
    let remove_submission = RequestId::new();
    let remove_path = format!("{scope_path}/mls-commits/{remove_submission}");
    let remove_key = "federated-v5-remove-0001";
    let remove_commit = vec![0xd4; 48];
    let remove_body = mls_device_remove_body_v5(
        &origin_controller,
        &recovery.device,
        scope,
        remove_submission,
        remove_key,
        2,
        add_head,
        remove_commit.clone(),
        revoke_head,
    )?;
    let remove_request_digest = mls_device_remove_request_digest_v5(
        &origin_controller,
        &recovery.device,
        scope,
        remove_submission,
        remove_key,
        2,
        add_head,
        remove_commit,
        revoke_head,
    )?;
    let remove_idempotency_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, remove_key.as_bytes());
    let removed = send_federated_mls_commit_v5(
        group_app.clone(),
        &remove_path,
        remove_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &remove_path,
            remove_submission,
            remove_request_digest,
            remove_idempotency_hash,
            1_400,
        )?,
        remove_body.clone(),
    )
    .await?;
    assert_eq!(removed.status(), StatusCode::CREATED);
    assert_content_type(&removed, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE);
    let remove_receipt = response_bytes(removed).await?;
    let remove_replay = send_federated_mls_commit_v5(
        group_app.clone(),
        &remove_path,
        remove_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &remove_path,
            remove_submission,
            remove_request_digest,
            remove_idempotency_hash,
            1_500,
        )?,
        remove_body,
    )
    .await?;
    assert_eq!(remove_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(remove_replay).await?, remove_receipt);
    let remove_readback = send_federated_mls_receipt_query_v5(
        group_app,
        &remove_path,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            2,
            scope,
            &remove_path,
            remove_submission,
            remove_request_digest,
            remove_idempotency_hash,
            1_600,
        )?,
    )
    .await?;
    assert_eq!(remove_readback.status(), StatusCode::OK);
    assert_eq!(response_bytes(remove_readback).await?, remove_receipt);

    let group_identity_after = IdentityLogRepository::new()
        .load(&group_identity_store, origin_controller.identity_id)
        .await?
        .ok_or("group-side identity disappeared")?;
    assert_eq!(group_identity_after.head().sequence().get(), 2);
    assert_eq!(
        group_identity_after
            .projection()
            .device_status(recovery.device.device_id),
        None
    );
    assert_eq!(
        v5_intent_count(group_harness.admin_pool(), tenant_id).await?,
        2
    );
    identity_server.abort();
    Ok(())
}

#[tokio::test]
async fn v5_parser_rejects_add_remove_nullability_matrix_without_rows() -> Result<(), Box<dyn Error>>
{
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let owner = enroll_active_device(&identity_store, 144, 145, 146, [147; 32]).await?;
    let target = synthetic_same_identity_device(&owner, 148);
    let tenant_id = TenantId::new();
    let app = group_router_with_state(
        GroupNodeState::with_clock(group_store, tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(SigningKey::from_bytes(&[149; 32]))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                std::iter::empty::<String>(),
            )?,
    );
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);
    let nonzero = Sha256Digest::from_bytes([0x55; 32]);

    for (index, (recovery_add, field, replacement)) in [
        (true, 8_u64, CanonicalValue::Null),
        (true, 14_u64, CanonicalValue::Null),
        (false, 8_u64, nonzero.to_canonical_value()),
        (false, 14_u64, nonzero.to_canonical_value()),
    ]
    .into_iter()
    .enumerate()
    {
        let submission_id = RequestId::new();
        let path = format!("{scope_path}/mls-commits/{submission_id}");
        let idempotency_key = format!("v5-parser-nullability-{index:04}");
        let valid_body = if recovery_add {
            mls_recovery_add_body_v5(
                &owner,
                &target,
                scope,
                submission_id,
                &idempotency_key,
                0,
                Sha256Digest::from_bytes([0; 32]),
                vec![0xd1; 48],
                Sha256Digest::from_bytes([0x44; 32]),
                DeviceEnrollmentChallengeId::new(),
                Sha256Digest::from_bytes([0x45; 32]),
            )?
        } else {
            mls_device_remove_body_v5(
                &owner,
                &target,
                scope,
                submission_id,
                &idempotency_key,
                0,
                Sha256Digest::from_bytes([0; 32]),
                vec![0xd2; 48],
                Sha256Digest::from_bytes([0x46; 32]),
            )?
        };
        let response = send_mutation(
            app.clone(),
            "POST",
            &path,
            MLS_COMMIT_V5_CONTENT_TYPE,
            &idempotency_key,
            &owner,
            replace_numbered_map_field(&valid_body, field, replacement)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_safe_group_error(response, "GROUP_REQUEST_INVALID").await?;
        assert_eq!(v5_intent_count(harness.admin_pool(), tenant_id).await?, 0);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires the disposable three-node Docker Compose cluster"]
#[allow(clippy::too_many_lines)]
async fn three_node_compose_runs_v30_peer_admission_and_exact_recovery_over_tls()
-> Result<(), Box<dyn Error>> {
    if std::env::var("DTX_THREE_NODE_COMPOSE_ACCEPTANCE").as_deref() != Ok("1") {
        return Err(
            "set DTX_THREE_NODE_COMPOSE_ACCEPTANCE=1 for the disposable local cluster".into(),
        );
    }

    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let postgres_port = std::env::var("DTX_THREE_NODE_POSTGRES_PORT")
        .unwrap_or_else(|_| "15432".to_owned())
        .parse::<u16>()?;
    let admin_a = sqlx::PgPool::connect(&format!(
        "postgres://postgres@127.0.0.1:{postgres_port}/dtx_node_a?sslmode=disable"
    ))
    .await?;
    let admin_b = sqlx::PgPool::connect(&format!(
        "postgres://postgres@127.0.0.1:{postgres_port}/dtx_node_b?sslmode=disable"
    ))
    .await?;
    let admin_c = sqlx::PgPool::connect(&format!(
        "postgres://postgres@127.0.0.1:{postgres_port}/dtx_node_c?sslmode=disable"
    ))
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
        PgConnectOptions::from_str(&format!(
            "postgres://dtx_identity_node@127.0.0.1:{postgres_port}/dtx_node_a?sslmode=disable"
        ))?,
        2,
    )
    .await?;
    let identity_b = IdentityPgStore::connect(
        PgConnectOptions::from_str(&format!(
            "postgres://dtx_identity_node@127.0.0.1:{postgres_port}/dtx_node_b?sslmode=disable"
        ))?,
        2,
    )
    .await?;
    let owner = enroll_active_device_at(&identity_a, 151, 152, 153, [154; 32], now).await?;
    let candidate = enroll_active_device_at(&identity_b, 161, 162, 163, [164; 32], now).await?;

    let ca_file = std::env::var("DTX_THREE_NODE_TLS_CA_FILE").map_err(|_| {
        "set DTX_THREE_NODE_TLS_CA_FILE to the local Compose CA emitted by scripts/local-cluster.ps1"
    })?;
    let local_test_ca = reqwest::Certificate::from_pem(&std::fs::read(ca_file)?)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .add_root_certificate(local_test_ca)
        .resolve("node-a", "127.0.0.1:18443".parse::<SocketAddr>()?)
        .resolve("node-b", "127.0.0.1:18444".parse::<SocketAddr>()?)
        .resolve("node-c", "127.0.0.1:18445".parse::<SocketAddr>()?)
        .build()?;
    for (host, port, expected_origin) in [
        ("node-a", 18_443, "https://node-a:8443"),
        ("node-b", 18_444, "https://node-b:8443"),
        ("node-c", 18_445, "https://node-c:8443"),
    ] {
        let health = client
            .get(format!("https://{host}:{port}/local/live"))
            .send()
            .await?;
        assert_eq!(health.status(), StatusCode::NO_CONTENT);
        let response = client
            .get(format!(
                "https://{host}:{port}{GROUP_SERVICE_DESCRIPTOR_PATH}"
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
    let group_origin = "https://node-a:18443";
    let candidate_identity_origin = "https://node-b:8443";
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
    let join_commit_request_digest = mls_v3_request_digest(&join_commit_body)?;
    let join_commit_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, join_commit_key.as_bytes());

    // Every signed mismatch is rejected before any sequencer state can be
    // written. This protects exact body/request/path/origin/action binding.
    let mut tampered_body = join_commit_body.clone();
    let CanonicalValue::Map(tampered_fields) = decode_deterministic_cbor(&tampered_body)? else {
        return Err("V3 MLS commit body must be a map".into());
    };
    let mut tampered_fields = tampered_fields;
    tampered_fields[13].1 = Sha256Digest::from_bytes([0x29; 32]).to_canonical_value();
    tampered_body = encode(&CanonicalValue::Map(tampered_fields))?;
    let valid_submit_proof = mls_commit_federated_proof(
        &owner,
        &candidate_origin,
        1,
        scope,
        &join_commit_path,
        join_submission,
        join_commit_request_digest,
        join_commit_key_hash,
        1_000,
    )?;
    for (label, body, proof) in [
        ("body", tampered_body, valid_submit_proof.clone()),
        (
            "request digest",
            join_commit_body.clone(),
            mls_commit_federated_proof(
                &owner,
                &candidate_origin,
                1,
                scope,
                &join_commit_path,
                join_submission,
                Sha256Digest::from_bytes([0x31; 32]),
                join_commit_key_hash,
                1_000,
            )?,
        ),
        (
            "path",
            join_commit_body.clone(),
            mls_commit_federated_proof(
                &owner,
                &candidate_origin,
                1,
                scope,
                &format!("{join_commit_path}/tampered"),
                join_submission,
                join_commit_request_digest,
                join_commit_key_hash,
                1_000,
            )?,
        ),
        (
            "origin",
            join_commit_body.clone(),
            mls_commit_federated_proof(
                &owner,
                "https://tampered.invalid",
                1,
                scope,
                &join_commit_path,
                join_submission,
                join_commit_request_digest,
                join_commit_key_hash,
                1_000,
            )?,
        ),
        (
            "action",
            join_commit_body.clone(),
            mls_commit_federated_proof(
                &owner,
                &candidate_origin,
                2,
                scope,
                &join_commit_path,
                join_submission,
                join_commit_request_digest,
                join_commit_key_hash,
                1_000,
            )?,
        ),
    ] {
        let rejected = send_federated_mls_commit(
            app.clone(),
            &join_commit_path,
            join_commit_key,
            &candidate_origin,
            proof,
            body,
        )
        .await?;
        assert_eq!(
            rejected.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "signed {label} mismatch must fail closed"
        );
    }

    let mixed_authorization = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&join_commit_path)
                .header(header::CONTENT_TYPE, MLS_COMMIT_V3_CONTENT_TYPE)
                .header("idempotency-key", join_commit_key)
                .header(IDENTITY_ORIGIN_HEADER, &candidate_origin)
                .header(MLS_COMMIT_PROOF_HEADER, valid_submit_proof.clone())
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(owner.session_id, owner.session_secret),
                )
                .body(Body::from(join_commit_body.clone()))?,
        )
        .await?;
    assert_eq!(
        mixed_authorization.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let committed = send_federated_mls_commit(
        app.clone(),
        &join_commit_path,
        join_commit_key,
        &candidate_origin,
        valid_submit_proof,
        join_commit_body.clone(),
    )
    .await?;
    assert_eq!(committed.status(), StatusCode::CREATED);
    assert_content_type(&committed, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE);
    let committed_receipt = response_bytes(committed).await?;
    let committed_replay = send_federated_mls_commit(
        app.clone(),
        &join_commit_path,
        join_commit_key,
        &candidate_origin,
        mls_commit_federated_proof(
            &owner,
            &candidate_origin,
            1,
            scope,
            &join_commit_path,
            join_submission,
            join_commit_request_digest,
            join_commit_key_hash,
            1_500,
        )?,
        join_commit_body,
    )
    .await?;
    assert_eq!(committed_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(committed_replay).await?, committed_receipt);

    let readback = send_federated_mls_receipt_query(
        app.clone(),
        &join_commit_path,
        &candidate_origin,
        mls_commit_federated_proof(
            &owner,
            &candidate_origin,
            2,
            scope,
            &join_commit_path,
            join_submission,
            join_commit_request_digest,
            join_commit_key_hash,
            1_600,
        )?,
    )
    .await?;
    assert_eq!(readback.status(), StatusCode::OK);
    assert_content_type(&readback, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE);
    assert_eq!(response_bytes(readback).await?, committed_receipt);

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

struct PreparedHistoryRecovery {
    device: ActiveDevice,
    request_id: DeviceEnrollmentChallengeId,
    request_digest: Sha256Digest,
    approved_head: IdentityLogHead,
    scope_digest: Sha256Digest,
}

#[allow(clippy::too_many_arguments)]
async fn prepare_scoped_history_recovery(
    app: axum::Router,
    store: &IdentityPgStore,
    controller: &ActiveDevice,
    scope: GroupScope,
    device_seed: u8,
    encryption_seed: u8,
    capability: [u8; 32],
    session_secret: [u8; 32],
    key_prefix: &str,
    occurred_at: i64,
) -> Result<PreparedHistoryRecovery, Box<dyn Error>> {
    let repository = IdentityLogRepository::new();
    let observed_head = repository
        .load(store, controller.identity_id)
        .await?
        .ok_or("identity missing before history recovery request")?
        .head();
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let device_id = DeviceId::new();
    let request_id = DeviceEnrollmentChallengeId::new();
    let encryption_key = DeviceEncryptionPublicKey::try_from([encryption_seed; 32])?;
    let (request_body, exact_signed_request) = history_recovery_request_body(
        &device,
        request_id,
        controller.identity_id,
        device_id,
        encryption_key,
        observed_head,
        UtcMillis::new(NOW - 10)?,
        UtcMillis::new(NOW + 60_000)?,
        capability,
    )?;
    let request = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(DEVICE_ENROLLMENT_CHALLENGE_PATH)
                .header(header::CONTENT_TYPE, HISTORY_RECOVERY_REQUEST_CONTENT_TYPE)
                .header("idempotency-key", format!("{key_prefix}-request-0001"))
                .body(Body::from(request_body))?,
        )
        .await?;
    assert_eq!(request.status(), StatusCode::CREATED);

    let device_add = device_add_with_encryption(
        &controller.root,
        &device,
        controller.identity_id,
        device_id,
        observed_head.hash(),
        observed_head
            .sequence()
            .get()
            .checked_add(1)
            .ok_or("identity sequence overflow")?,
        occurred_at,
        encryption_key,
    )?;
    let approval_body = encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(request_id.to_string()),
        CanonicalValue::Bytes(capability.to_vec()),
        CanonicalValue::Bytes(device_add.to_deterministic_cbor()?),
    ]))?;
    let approval = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(DEVICE_ENROLLMENT_PATH)
                .header(header::CONTENT_TYPE, DEVICE_ENROLLMENT_CONTENT_TYPE)
                .header("idempotency-key", format!("{key_prefix}-approval-0001"))
                .header(header::IF_MATCH, format!("\"{}\"", observed_head.hash()))
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(controller.session_id, controller.session_secret),
                )
                .body(Body::from(approval_body))?,
        )
        .await?;
    assert_eq!(approval.status(), StatusCode::CREATED);
    let approved_head = repository
        .load(store, controller.identity_id)
        .await?
        .ok_or("identity missing after history recovery approval")?
        .head();
    assert_eq!(
        approved_head.sequence().get(),
        observed_head.sequence().get() + 1
    );
    let active = issue_same_identity_device_session(
        store,
        controller,
        device,
        device_id,
        session_secret,
        key_prefix,
        device_seed,
    )
    .await?;
    Ok(PreparedHistoryRecovery {
        device: active,
        request_id,
        request_digest: Sha256Digest::hash_domain(
            HISTORY_RECOVERY_REQUEST_HASH_DOMAIN,
            &exact_signed_request,
        ),
        approved_head,
        scope_digest: mls_recovery_scope_digest(scope)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn history_recovery_request_body(
    candidate: &SigningKey,
    request_id: DeviceEnrollmentChallengeId,
    identity_id: IdentityId,
    candidate_device_id: DeviceId,
    recipient_encryption_key: DeviceEncryptionPublicKey,
    observed_head: IdentityLogHead,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    capability: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let unsigned = history_recovery_request_unsigned_canonical_bytes(
        request_id,
        identity_id,
        candidate_device_id,
        public_key(candidate)?,
        recipient_encryption_key,
        observed_head,
        issued_at,
        expires_at,
    )?;
    let candidate_signature = signature(
        candidate,
        &history_recovery_request_signature_input(&unsigned),
    );
    let CanonicalValue::Map(mut fields) = decode_deterministic_cbor(&unsigned)? else {
        return Err("unsigned history recovery request must be a map".into());
    };
    fields.push((
        CanonicalValue::Unsigned(12),
        candidate_signature.to_canonical_value(),
    ));
    let exact_signed_request = encode_deterministic_cbor(&CanonicalValue::Map(fields.clone()))?;
    fields.push((
        CanonicalValue::Unsigned(13),
        CanonicalValue::Bytes(capability.to_vec()),
    ));
    Ok((
        encode_deterministic_cbor(&CanonicalValue::Map(fields))?,
        exact_signed_request,
    ))
}

async fn issue_same_identity_device_session(
    store: &IdentityPgStore,
    controller: &ActiveDevice,
    device: SigningKey,
    device_id: DeviceId,
    session_secret: [u8; 32],
    key_prefix: &str,
    nonce_seed: u8,
) -> Result<ActiveDevice, Box<dyn Error>> {
    let challenge = DeviceSessionRepository
        .issue_challenge(
            store,
            controller.identity_id,
            device_id,
            [nonce_seed; 32],
            AUDIENCE,
            UtcMillis::new(NOW)?,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let proof = signature(
        &device,
        &device_session_proof_input(
            controller.identity_id,
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
        Sha256Digest::hash_domain(b"test-group-recovery-session\0", key_prefix.as_bytes()),
        controller.identity_id,
        device_id,
        challenge.challenge_id(),
        session_id,
        *challenge.nonce(),
        session_secret,
        proof,
    )?;
    assert!(matches!(
        DeviceSessionRepository
            .complete(store, &completion, UtcMillis::new(NOW)?)
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(ActiveDevice {
        identity_id: controller.identity_id,
        device_id,
        root: SigningKey::from_bytes(&controller.root.to_bytes()),
        device,
        session_id,
        session_secret,
    })
}

async fn publish_scoped_recovery_key_package(
    app: axum::Router,
    controller: &ActiveDevice,
    recovery: &PreparedHistoryRecovery,
    scope: GroupScope,
    published_head: IdentityLogHead,
    opaque_key_package: Vec<u8>,
    idempotency_key: &str,
) -> Result<Sha256Digest, Box<dyn Error>> {
    let scope_digest = mls_recovery_scope_digest(scope)?;
    assert_eq!(scope_digest, recovery.scope_digest);
    let package_id = KeyPackageId::new();
    let expires_at = UtcMillis::new(NOW + 60_000)?;
    let mut signature_input = key_package_publish_signature_input(
        recovery.device.identity_id,
        recovery.device.device_id,
        package_id,
        published_head.sequence(),
        published_head.hash(),
        expires_at,
        &opaque_key_package,
    )?;
    signature_input.extend_from_slice(recovery.request_digest.as_bytes());
    signature_input.extend_from_slice(scope_digest.as_bytes());
    signature_input.extend_from_slice(b"history_recovery");
    let detached_signature = signature(&recovery.device.device, &signature_input);
    let body = encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(recovery.device.identity_id.to_string()),
        CanonicalValue::Text(recovery.device.device_id.to_string()),
        CanonicalValue::Text(package_id.to_string()),
        published_head.sequence().to_canonical_value(),
        published_head.hash().to_canonical_value(),
        expires_at.to_canonical_value(),
        CanonicalValue::Bytes(opaque_key_package.clone()),
        detached_signature.to_canonical_value(),
        recovery.request_digest.to_canonical_value(),
        scope_digest.to_canonical_value(),
        CanonicalValue::Unsigned(1),
    ]))?;
    let path = KEY_PACKAGE_PUBLISH_PATH_TEMPLATE.replace("{package_id}", &package_id.to_string());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::CONTENT_TYPE, KEY_PACKAGE_PUBLISH_V2_CONTENT_TYPE)
                .header("idempotency-key", idempotency_key)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(
                        recovery.device.session_id,
                        recovery.device.session_secret,
                    ),
                )
                .body(Body::from(body))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let claim_body = encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(recovery.device.identity_id.to_string()),
        CanonicalValue::Text(recovery.device.device_id.to_string()),
        recovery.request_digest.to_canonical_value(),
        scope_digest.to_canonical_value(),
        CanonicalValue::Unsigned(1),
    ]))?;
    let claim = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(KEY_PACKAGE_CLAIM_PATH)
                .header(header::CONTENT_TYPE, KEY_PACKAGE_CLAIM_V2_CONTENT_TYPE)
                .header("idempotency-key", format!("{idempotency_key}-claim"))
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(controller.session_id, controller.session_secret),
                )
                .body(Body::from(claim_body))?,
        )
        .await?;
    assert_eq!(claim.status(), StatusCode::CREATED);
    Ok(Sha256Digest::hash_domain(
        KEY_PACKAGE_BYTES_HASH_DOMAIN,
        &opaque_key_package,
    ))
}

async fn revoke_device_over_http(
    app: axum::Router,
    store: &IdentityPgStore,
    controller: &ActiveDevice,
    target_device_id: DeviceId,
    idempotency_key: &str,
    occurred_at: i64,
) -> Result<Sha256Digest, Box<dyn Error>> {
    let repository = IdentityLogRepository::new();
    let head = repository
        .load(store, controller.identity_id)
        .await?
        .ok_or("identity missing before HTTP device revoke")?
        .head();
    let event = signed_event(
        &controller.root,
        controller.identity_id,
        head.sequence()
            .get()
            .checked_add(1)
            .ok_or("identity sequence overflow")?,
        Some(head.hash()),
        occurred_at,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: target_device_id,
        },
    )?;
    let path = DEVICE_REVOKE_PATH_TEMPLATE
        .replace("{identity_id}", &controller.identity_id.to_string())
        .replace("{device_id}", &target_device_id.to_string());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, IDENTITY_LOG_EVENT_CONTENT_TYPE)
                .header("idempotency-key", idempotency_key)
                .header(header::IF_MATCH, format!("\"{}\"", head.hash()))
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(controller.session_id, controller.session_secret),
                )
                .body(Body::from(event.to_deterministic_cbor()?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let current = repository
        .load(store, controller.identity_id)
        .await?
        .ok_or("identity missing after HTTP device revoke")?
        .head();
    assert_eq!(current.hash(), event.entry_hash()?);
    Ok(current.hash())
}

fn synthetic_same_identity_device(controller: &ActiveDevice, seed: u8) -> ActiveDevice {
    ActiveDevice {
        identity_id: controller.identity_id,
        device_id: DeviceId::new(),
        root: SigningKey::from_bytes(&controller.root.to_bytes()),
        device: SigningKey::from_bytes(&[seed; 32]),
        session_id: DeviceSessionId::new(),
        session_secret: [seed; 32],
    }
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

async fn start_identity_server_at(
    store: IdentityPgStore,
    now_ms: i64,
) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let state = IdentityBootstrapState::with_clock_and_device_session_audience(
        store,
        Arc::new(FixedClock(now_ms)),
        AUDIENCE,
    );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, identity_bootstrap_router_with_state(state)).await;
    });
    Ok((origin, server))
}

async fn replicate_initial_identity(
    store: &IdentityPgStore,
    active: &ActiveDevice,
    recovery_seed: u8,
    now_ms: i64,
) -> Result<(), Box<dyn Error>> {
    let recovery = SigningKey::from_bytes(&[recovery_seed; 32]);
    let genesis = genesis(&active.root, &recovery, now_ms - 1_000)?;
    if genesis.identity_id() != active.identity_id {
        return Err("replicated identity ID mismatch".into());
    }
    let repository = IdentityLogRepository::new();
    let bootstrap = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-group-cross-db-bootstrap\0", &[recovery_seed]),
        None,
        genesis.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append_bootstrap(store, &bootstrap, UtcMillis::new(now_ms - 800)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let initial = device_add(
        &active.root,
        &active.device,
        active.identity_id,
        active.device_id,
        genesis.entry_hash()?,
        2,
        now_ms - 700,
    )?;
    assert!(matches!(
        repository
            .append_initial_device(
                store,
                Sha256Digest::hash_domain(
                    b"test-group-cross-db-initial\0",
                    active.device_id.to_string().as_bytes(),
                ),
                genesis.entry_hash()?,
                initial.to_deterministic_cbor()?,
                UtcMillis::new(now_ms - 500)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    Ok(())
}

async fn seed_recovery_authorization_artifacts(
    pool: &sqlx::PgPool,
    controller: &ActiveDevice,
    recovery: &PreparedHistoryRecovery,
    package_digest: Sha256Digest,
) -> Result<(), Box<dyn Error>> {
    let mailbox_id = uuid::Uuid::now_v7();
    let envelope_id = uuid::Uuid::now_v7();
    let object_id = uuid::Uuid::now_v7();
    let attachment_digest = Sha256Digest::from_bytes([0xa5; 32]);
    let grant_digest = Sha256Digest::from_bytes([0xa6; 32]);
    sqlx::query(
        "INSERT INTO messaging.mailboxes
             (mailbox_id,owner_identity_id,owner_device_id,write_capability_hash,
              expires_at_ms,next_delivery_sequence,active_envelope_count,
              active_envelope_bytes,created_at_ms)
         VALUES ($1,$2,$3,$4,$5,1,1,32,$6)",
    )
    .bind(mailbox_id)
    .bind(controller.identity_id.to_string())
    .bind(uuid::Uuid::from(controller.device_id))
    .bind([0xa1_u8; 32].as_slice())
    .bind(NOW + 60_000)
    .bind(NOW - 100)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO messaging.mailbox_envelopes
             (mailbox_id,envelope_id,delivery_sequence,opaque_ciphertext,
              request_digest,receipt_bytes,receipt_hash,expires_at_ms,state,created_at_ms)
         VALUES ($1,$2,1,$3,$4,$5,$6,$7,'available',$8)",
    )
    .bind(mailbox_id)
    .bind(envelope_id)
    .bind([0xa2_u8; 32].as_slice())
    .bind([0xa3_u8; 32].as_slice())
    .bind([0x01_u8].as_slice())
    .bind([0xa4_u8; 32].as_slice())
    .bind(NOW + 60_000)
    .bind(NOW - 100)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO messaging.attachment_objects
             (object_id,owner_identity_id,owner_device_id,upload_capability_hash,
              read_capability_hash,expected_manifest_digest,expected_chunk_count,
              expected_ciphertext_bytes,uploaded_chunk_count,uploaded_ciphertext_bytes,
              manifest_bytes,state,expires_at_ms,created_at_ms,updated_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,1,17,1,17,$7,'ready',$8,$9,$9)",
    )
    .bind(object_id)
    .bind(controller.identity_id.to_string())
    .bind(uuid::Uuid::from(controller.device_id))
    .bind([0xb1_u8; 32].as_slice())
    .bind([0xb2_u8; 32].as_slice())
    .bind(attachment_digest.as_bytes().as_slice())
    .bind([0xb3_u8; 17].as_slice())
    .bind(NOW + 60_000)
    .bind(NOW - 100)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO messaging.history_recovery_offers
             (identity_id,request_id,recovery_request_digest,approved_head_hash,
              candidate_device_id,provider_device_id,authority_kind,authority_id,
              mailbox_id,envelope_id,provider_highwater,earliest_sequence,
              recipient_package_digest,attachment_digest,offer_digest,exact_grant,
              request_digest,idempotency_key_hash,provider_signature,authority_signature,
              granted_at_ms,expires_at_ms,receipt_bytes,receipt_hash)
         VALUES ($1,$2,$3,$4,$5,$6,'active_device',$7,$8,$9,0,1,$10,$11,$12,$13,
                 $14,$15,$16,$17,$18,$19,$20,$21)",
    )
    .bind(controller.identity_id.to_string())
    .bind(*recovery.request_id.as_uuid())
    .bind(recovery.request_digest.as_bytes().as_slice())
    .bind(recovery.approved_head.hash().as_bytes().as_slice())
    .bind(uuid::Uuid::from(recovery.device.device_id))
    .bind(uuid::Uuid::from(controller.device_id))
    .bind(recovery.device.device_id.to_string())
    .bind(mailbox_id)
    .bind(envelope_id)
    .bind(package_digest.as_bytes().as_slice())
    .bind(attachment_digest.as_bytes().as_slice())
    .bind([0xa7_u8; 32].as_slice())
    .bind([0x01_u8].as_slice())
    .bind(grant_digest.as_bytes().as_slice())
    .bind(recovery.request_digest.as_bytes().as_slice())
    .bind([0xa9_u8; 64].as_slice())
    .bind([0xaa_u8; 64].as_slice())
    .bind(NOW - 50)
    .bind(NOW + 60_000)
    .bind([0x01_u8].as_slice())
    .bind([0xab_u8; 32].as_slice())
    .execute(pool)
    .await?;
    Ok(())
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

async fn send_federated_mls_commit(
    app: axum::Router,
    path: &str,
    idempotency_key: &str,
    identity_origin: &str,
    proof: String,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, MLS_COMMIT_V3_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(MLS_COMMIT_PROOF_HEADER, proof)
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_mls_commit_v5(
    app: axum::Router,
    path: &str,
    idempotency_key: &str,
    identity_origin: &str,
    proof: String,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, MLS_COMMIT_V5_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(MLS_COMMIT_PROOF_HEADER, proof)
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_mls_receipt_query(
    app: axum::Router,
    path: &str,
    identity_origin: &str,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(path)
            .header(header::ACCEPT, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(MLS_COMMIT_PROOF_HEADER, proof)
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_mls_receipt_query_v5(
    app: axum::Router,
    path: &str,
    identity_origin: &str,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(path)
            .header(header::ACCEPT, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(MLS_COMMIT_PROOF_HEADER, proof)
            .body(Body::empty())?,
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

async fn send_local_commit_feed_v2(
    app: axum::Router,
    target: &str,
    active: &ActiveDevice,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(target)
            .header(header::ACCEPT, MLS_COMMIT_FEED_V2_CONTENT_TYPE)
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

async fn send_local_commit_feed_v3(
    app: axum::Router,
    target: &str,
    active: &ActiveDevice,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(target)
            .header(header::ACCEPT, MLS_COMMIT_FEED_V3_CONTENT_TYPE)
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
        MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd { .. } => {
            return Err("V5 recovery-add uses the dedicated helper".into());
        }
        MlsCommitAuthorization::ExistingMemberDeviceRemove { .. } => {
            return Err("V5 device-removal uses the dedicated helper".into());
        }
        MlsCommitAuthorization::ApprovedIdentityJoinV3 { .. } => {
            return Err("V3 approved-join uses the dedicated helper".into());
        }
        MlsCommitAuthorization::MemberRemovalV4 { .. } => {
            return Err("V4 removal uses the dedicated helper".into());
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

#[allow(clippy::too_many_arguments)]
fn mls_commit_body_v4(
    actor: &ActiveDevice,
    target: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    expected_policy_revision: Revision,
    commit_bytes: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(4),
        CanonicalValue::Text(submission_id.to_string()),
        scope_value(scope),
        CanonicalValue::Text(actor.identity_id.to_string()),
        CanonicalValue::Text(actor.device_id.to_string()),
        CanonicalValue::Text(target.identity_id.to_string()),
        CanonicalValue::Text(target.device_id.to_string()),
        CanonicalValue::Null,
        CanonicalValue::Null,
        CanonicalValue::Unsigned(expected_epoch),
        expected_head.to_canonical_value(),
        CanonicalValue::Bytes(commit_bytes),
        commit_digest.to_canonical_value(),
        CanonicalValue::Null,
        numbered_map(vec![
            CanonicalValue::Unsigned(4),
            CanonicalValue::Unsigned(expected_policy_revision.get()),
        ]),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn mls_recovery_add_body_v5(
    controller: &ActiveDevice,
    recovery_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    key_package_digest: Sha256Digest,
    recovery_request_id: DeviceEnrollmentChallengeId,
    recovery_request_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    mls_recovery_add_body_v5_with_scope_digest(
        controller,
        recovery_device,
        scope,
        submission_id,
        idempotency_key,
        expected_epoch,
        expected_head,
        commit_bytes,
        key_package_digest,
        recovery_request_id,
        recovery_request_digest,
        mls_recovery_scope_digest(scope)?,
    )
}

#[allow(clippy::too_many_arguments)]
fn mls_recovery_add_body_v5_with_scope_digest(
    controller: &ActiveDevice,
    recovery_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    key_package_digest: Sha256Digest,
    recovery_request_id: DeviceEnrollmentChallengeId,
    recovery_request_digest: Sha256Digest,
    scope_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if controller.identity_id != recovery_device.identity_id {
        return Err("V5 recovery controller and device must share one identity".into());
    }
    let idempotency_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, idempotency_key.as_bytes());
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    let welcome_digest = Sha256Digest::hash_domain(b"test-mls-welcome\0", &commit_bytes);
    let provisional = MlsCommitCommand::new_v5_existing_member_device_recovery_add(
        submission_id,
        scope,
        controller.identity_id,
        controller.device_id,
        recovery_device.device_id,
        key_package_digest,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        welcome_digest,
        recovery_request_id,
        recovery_request_digest,
        scope_digest,
        Sha256Digest::from_bytes([0; 32]),
    )?;
    let consent_digest = mls_v5_controller_consent_digest(&provisional)?;
    let command = MlsCommitCommand::new_v5_existing_member_device_recovery_add(
        submission_id,
        scope,
        controller.identity_id,
        controller.device_id,
        recovery_device.device_id,
        key_package_digest,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        welcome_digest,
        recovery_request_id,
        recovery_request_digest,
        scope_digest,
        consent_digest,
    )?;
    let consent_signature = signature(
        &controller.device,
        &mls_v5_controller_consent_signature_input(&command)?,
    );
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(5),
        CanonicalValue::Text(submission_id.to_string()),
        scope_value(scope),
        CanonicalValue::Text(controller.identity_id.to_string()),
        CanonicalValue::Text(controller.device_id.to_string()),
        CanonicalValue::Text(recovery_device.identity_id.to_string()),
        CanonicalValue::Text(recovery_device.device_id.to_string()),
        key_package_digest.to_canonical_value(),
        CanonicalValue::Null,
        CanonicalValue::Unsigned(expected_epoch),
        expected_head.to_canonical_value(),
        CanonicalValue::Bytes(commit_bytes),
        commit_digest.to_canonical_value(),
        welcome_digest.to_canonical_value(),
        numbered_map(vec![
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(controller.device_id.to_string()),
            consent_digest.to_canonical_value(),
            CanonicalValue::Text(recovery_request_id.to_string()),
            recovery_request_digest.to_canonical_value(),
            scope_digest.to_canonical_value(),
            numbered_map(vec![
                CanonicalValue::Unsigned(5),
                consent_digest.to_canonical_value(),
                consent_signature.to_canonical_value(),
            ]),
        ]),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn mls_device_remove_body_v5(
    controller: &ActiveDevice,
    revoked_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    identity_revoke_head_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if controller.identity_id != revoked_device.identity_id {
        return Err("V5 removal controller and device must share one identity".into());
    }
    let idempotency_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, idempotency_key.as_bytes());
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    let provisional = MlsCommitCommand::new_v5_existing_member_device_remove(
        submission_id,
        scope,
        controller.identity_id,
        controller.device_id,
        revoked_device.device_id,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        identity_revoke_head_digest,
    )?;
    let consent_digest = mls_v5_controller_consent_digest(&provisional)?;
    let consent_signature = signature(
        &controller.device,
        &mls_v5_controller_consent_signature_input(&provisional)?,
    );
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(5),
        CanonicalValue::Text(submission_id.to_string()),
        scope_value(scope),
        CanonicalValue::Text(controller.identity_id.to_string()),
        CanonicalValue::Text(controller.device_id.to_string()),
        CanonicalValue::Text(revoked_device.identity_id.to_string()),
        CanonicalValue::Text(revoked_device.device_id.to_string()),
        CanonicalValue::Null,
        CanonicalValue::Null,
        CanonicalValue::Unsigned(expected_epoch),
        expected_head.to_canonical_value(),
        CanonicalValue::Bytes(commit_bytes),
        commit_digest.to_canonical_value(),
        CanonicalValue::Null,
        numbered_map(vec![
            CanonicalValue::Unsigned(6),
            identity_revoke_head_digest.to_canonical_value(),
            numbered_map(vec![
                CanonicalValue::Unsigned(5),
                consent_digest.to_canonical_value(),
                consent_signature.to_canonical_value(),
            ]),
        ]),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn mls_recovery_add_request_digest_v5(
    controller: &ActiveDevice,
    recovery_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    key_package_digest: Sha256Digest,
    recovery_request_id: DeviceEnrollmentChallengeId,
    recovery_request_digest: Sha256Digest,
) -> Result<Sha256Digest, Box<dyn Error>> {
    mls_recovery_add_request_digest_v5_with_scope_digest(
        controller,
        recovery_device,
        scope,
        submission_id,
        idempotency_key,
        expected_epoch,
        expected_head,
        commit_bytes,
        key_package_digest,
        recovery_request_id,
        recovery_request_digest,
        mls_recovery_scope_digest(scope)?,
    )
}

#[allow(clippy::too_many_arguments)]
fn mls_recovery_add_request_digest_v5_with_scope_digest(
    controller: &ActiveDevice,
    recovery_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    key_package_digest: Sha256Digest,
    recovery_request_id: DeviceEnrollmentChallengeId,
    recovery_request_digest: Sha256Digest,
    recovery_scope_digest: Sha256Digest,
) -> Result<Sha256Digest, Box<dyn Error>> {
    let idempotency_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, idempotency_key.as_bytes());
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    let welcome_digest = Sha256Digest::hash_domain(b"test-mls-welcome\0", &commit_bytes);
    let provisional = MlsCommitCommand::new_v5_existing_member_device_recovery_add(
        submission_id,
        scope,
        controller.identity_id,
        controller.device_id,
        recovery_device.device_id,
        key_package_digest,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        welcome_digest,
        recovery_request_id,
        recovery_request_digest,
        recovery_scope_digest,
        Sha256Digest::from_bytes([0; 32]),
    )?;
    let controller_consent_digest = mls_v5_controller_consent_digest(&provisional)?;
    Ok(
        MlsCommitCommand::new_v5_existing_member_device_recovery_add(
            submission_id,
            scope,
            controller.identity_id,
            controller.device_id,
            recovery_device.device_id,
            key_package_digest,
            idempotency_key_hash,
            expected_epoch,
            expected_head,
            commit_bytes,
            commit_digest,
            welcome_digest,
            recovery_request_id,
            recovery_request_digest,
            recovery_scope_digest,
            controller_consent_digest,
        )?
        .request_digest(),
    )
}

#[allow(clippy::too_many_arguments)]
fn mls_device_remove_request_digest_v5(
    controller: &ActiveDevice,
    revoked_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    identity_revoke_head_digest: Sha256Digest,
) -> Result<Sha256Digest, Box<dyn Error>> {
    let idempotency_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, idempotency_key.as_bytes());
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    Ok(MlsCommitCommand::new_v5_existing_member_device_remove(
        submission_id,
        scope,
        controller.identity_id,
        controller.device_id,
        revoked_device.device_id,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes,
        commit_digest,
        identity_revoke_head_digest,
    )?
    .request_digest())
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
    if !matches!(
        inner.first().map(|field| &field.1),
        Some(CanonicalValue::Unsigned(1 | 3 | 4 | 5))
    ) {
        return Err("MLS receipt must use a supported inner version".into());
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

type EncodedCommitFeedItem = (Vec<u8>, Vec<u8>);

fn decode_commit_feed(
    bytes: &[u8],
    expected_version: u64,
    expected_after_epoch: u64,
) -> Result<Vec<EncodedCommitFeedItem>, Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("MLS commit feed must be a map".into());
    };
    if fields.len() != 3
        || fields[0]
            != (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Unsigned(expected_version),
            )
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

fn mls_v3_request_digest(body: &[u8]) -> Result<Sha256Digest, Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(body)? else {
        return Err("V3 MLS commit body must be a map".into());
    };
    if fields.len() != 15
        || fields.iter().enumerate().any(|(index, (key, _))| {
            *key != CanonicalValue::Unsigned(u64::try_from(index + 1).expect("small field index"))
        })
    {
        return Err("V3 MLS commit body fields must be exact".into());
    }
    let CanonicalValue::Map(authorization) = &fields[14].1 else {
        return Err("V3 MLS authorization must be a map".into());
    };
    if authorization.len() != 5
        || authorization.iter().enumerate().any(|(index, (key, _))| {
            *key != CanonicalValue::Unsigned(u64::try_from(index + 1).expect("small field index"))
        })
        || authorization[0].1 != CanonicalValue::Unsigned(2)
    {
        return Err("V3 MLS approval authorization must be exact".into());
    }
    let request = numbered_map(vec![
        fields[0].1.clone(),
        fields[1].1.clone(),
        fields[2].1.clone(),
        fields[3].1.clone(),
        fields[4].1.clone(),
        fields[5].1.clone(),
        fields[6].1.clone(),
        fields[7].1.clone(),
        Sha256Digest::from_bytes([0; 32]).to_canonical_value(),
        fields[9].1.clone(),
        fields[10].1.clone(),
        fields[12].1.clone(),
        fields[13].1.clone(),
        CanonicalValue::Unsigned(1),
        authorization[1].1.clone(),
        authorization[2].1.clone(),
        CanonicalValue::Null,
        CanonicalValue::Null,
        authorization[3].1.clone(),
        authorization[4].1.clone(),
    ]);
    Ok(Sha256Digest::hash_domain(
        MLS_COMMIT_REQUEST_DIGEST_DOMAIN,
        &encode_deterministic_cbor(&request)?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn mls_commit_federated_proof(
    actor: &ActiveDevice,
    identity_origin: &str,
    action: u64,
    scope: GroupScope,
    path: &str,
    submission_id: RequestId,
    request_digest: Sha256Digest,
    idempotency_key_hash: Sha256Digest,
    issued_at: i64,
) -> Result<String, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("MLS commit proof expiry overflow")?;
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(3),
        CanonicalValue::Unsigned(action),
        CanonicalValue::Text(path.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(submission_id.to_string()),
        CanonicalValue::Text(actor.identity_id.to_string()),
        CanonicalValue::Text(actor.device_id.to_string()),
        request_digest.to_canonical_value(),
        idempotency_key_hash.to_canonical_value(),
        utc_value(issued_at),
        utc_value(expires_at),
        CanonicalValue::Text(identity_origin.to_owned()),
    ]);
    let digest = Sha256Digest::hash_domain(
        MLS_COMMIT_FEDERATED_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = MLS_COMMIT_FEDERATED_PROOF_SIGNATURE_DOMAIN.to_vec();
    signature_input.extend_from_slice(digest.as_bytes());
    let proof = numbered_map(vec![
        CanonicalValue::Unsigned(3),
        binding,
        CanonicalValue::Bytes(actor.device.sign(&signature_input).to_bytes().to_vec()),
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

async fn assert_safe_group_error(
    response: axum::response::Response,
    expected_code: &str,
) -> Result<(), Box<dyn Error>> {
    assert_content_type(&response, "application/json");
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
    let body = to_bytes(response.into_body(), 16_384).await?;
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    let object = value
        .as_object()
        .ok_or("Group error must be a JSON object")?;
    assert_eq!(object.len(), 1);
    let error = object
        .get("error")
        .and_then(serde_json::Value::as_object)
        .ok_or("Group error must contain one error object")?;
    assert_eq!(error.len(), 3);
    assert_eq!(
        error.get("code").and_then(serde_json::Value::as_str),
        Some(expected_code)
    );
    assert!(
        error
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .is_some()
    );
    assert_eq!(
        error.get("retryable").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    Ok(())
}

fn replace_numbered_map_field(
    bytes: &[u8],
    field: u64,
    replacement: CanonicalValue,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let CanonicalValue::Map(mut fields) = decode_deterministic_cbor(bytes)? else {
        return Err("canonical request must be a map".into());
    };
    let value = fields
        .iter_mut()
        .find(|(key, _)| key == &CanonicalValue::Unsigned(field))
        .map(|(_, value)| value)
        .ok_or("canonical request field missing")?;
    *value = replacement;
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

async fn v5_intent_count(pool: &sqlx::PgPool, tenant_id: TenantId) -> Result<i64, Box<dyn Error>> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM groups.mls_commit_intents
          WHERE tenant_id=$1 AND protocol_version=5",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .fetch_one(pool)
    .await?)
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
    device_add_with_encryption(
        root,
        device,
        identity_id,
        device_id,
        previous_hash,
        sequence,
        occurred_at,
        DeviceEncryptionPublicKey::try_from([7_u8; 32])?,
    )
}

#[allow(clippy::too_many_arguments)]
fn device_add_with_encryption(
    root: &SigningKey,
    device: &SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    previous_hash: Sha256Digest,
    sequence: u64,
    occurred_at: i64,
    encryption_key: DeviceEncryptionPublicKey,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let root_key = public_key(root)?;
    let device_key = public_key(device)?;
    let certificate_unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        device_id,
        device_key,
        encryption_key,
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
