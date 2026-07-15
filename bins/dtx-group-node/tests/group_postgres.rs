#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, sync::Arc};

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
    GROUP_APPROVE_JOIN_CONTENT_TYPE, GROUP_CREATE_CONTENT_TYPE, GROUP_ISSUE_INVITE_CONTENT_TYPE,
    GROUP_JOIN_REQUEST_CONTENT_TYPE, GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE,
    GROUP_SCOPE_PATH_TEMPLATE, GroupNodeState, MEMBERSHIP_RECEIPT_CONTENT_TYPE,
    group_router_with_state,
};
use dtx_group_persistence::{
    GroupControlCommand, GroupControlDisposition, GroupControlOperation, GroupControlRejection,
    GroupControlRepository, GroupMembershipRepository, GroupPgStore,
};
use dtx_group_policy::GroupScope;
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_persistence::{
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceSessionCompletionCommand, DeviceSessionOutcome,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogRepository,
    IdentityPgStore, device_session_proof_input,
};
use dtx_wire::{
    CanonicalValue, Ed25519Signature, Sha256Digest, SigningPublicKey, UtcMillis,
    decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use tower::ServiceExt;

const AUDIENCE: &str = "https://group.test";
const NOW: i64 = 2_000;
const PROOF_EXPIRES: i64 = 20_000;
const IDEMPOTENCY_HASH_DOMAIN: &[u8] = b"dirextalk.membership-idempotency-key.v1\0";
const BUSINESS_FIELDS_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-business-fields.v1\0";
const ACTION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-binding.v1\0";
const ACTION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-action-signature.v1\0";

#[tokio::test]
#[allow(clippy::too_many_lines)] // The end-to-end recovery scenario intentionally keeps its user-visible sequence together.
async fn group_http_replays_refreshed_proofs_and_preserves_membership_intents()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let tenant_id = TenantId::new();
    let app = group_router_with_state(GroupNodeState::with_clock(
        group_store,
        tenant_id,
        Arc::new(FixedClock(NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 11, 12, 13, [14; 32]).await?;
    let candidate = enroll_active_device(&identity_store, 21, 22, 23, [24; 32]).await?;
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

    let invite_id = InviteCapabilityId::new();
    let invite_path = format!("{scope_path}/invites/{invite_id}");
    let invite_key = "group-issue-invite-0001";
    let invite_body = issue_invite_body(
        &owner,
        scope,
        &invite_path,
        invite_key,
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
    let join_body = join_request_body(
        &candidate,
        scope,
        &join_path,
        join_key,
        join_command_id,
        invite_id,
        Revision::new(2)?,
        Sha256Digest::hash_domain(b"test-group-head\0", b"join"),
    )?;
    let join = send_mutation(
        app.clone(),
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_CONTENT_TYPE,
        join_key,
        &candidate,
        join_body.clone(),
    )
    .await?;
    assert_eq!(join.status(), StatusCode::ACCEPTED);
    let join_receipt = response_bytes(join).await?;
    assert_membership_phase(&join_receipt, 1)?;
    let join_replay = send_mutation(
        app.clone(),
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_CONTENT_TYPE,
        join_key,
        &candidate,
        join_body,
    )
    .await?;
    assert_eq!(join_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(join_replay).await?, join_receipt);

    let approval_command_id = RequestId::new();
    let approval_path = format!("{join_path}/approvals");
    let approval_key = "group-approve-join-0001";
    let approval_body = approve_join_body(
        &owner,
        scope,
        &approval_path,
        approval_key,
        approval_command_id,
        candidate.identity_id,
        candidate.device_id,
        invite_id,
        Revision::new(3)?,
        Sha256Digest::hash_domain(b"test-group-head\0", b"approval"),
    )?;
    let approval = send_mutation(
        app.clone(),
        "POST",
        &approval_path,
        GROUP_APPROVE_JOIN_CONTENT_TYPE,
        approval_key,
        &owner,
        approval_body.clone(),
    )
    .await?;
    assert_eq!(approval.status(), StatusCode::ACCEPTED);
    assert_content_type(&approval, MEMBERSHIP_RECEIPT_CONTENT_TYPE);
    let approval_receipt = response_bytes(approval).await?;
    assert_membership_phase(&approval_receipt, 2)?;
    let approval_replay = send_mutation(
        app.clone(),
        "POST",
        &approval_path,
        GROUP_APPROVE_JOIN_CONTENT_TYPE,
        approval_key,
        &owner,
        approval_body,
    )
    .await?;
    assert_eq!(approval_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(approval_replay).await?, approval_receipt);

    // The candidate may recover the admin-created approval receipt. It remains
    // pending_commit until a real MLS Sequencer adapter supplies evidence.
    let receipt_path = GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE
        .replace("{scope_kind}", "private-conversation")
        .replace(
            "{scope_id}",
            scope_path.rsplit('/').next().ok_or("scope id")?,
        )
        .replace("{membership_command_id}", &approval_command_id.to_string());
    let receipt = send_get(app, &receipt_path, &candidate).await?;
    assert_eq!(receipt.status(), StatusCode::OK);
    assert_membership_phase(&response_bytes(receipt).await?, 2)?;
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
    let root = SigningKey::from_bytes(&[root_seed; 32]);
    let recovery = SigningKey::from_bytes(&[recovery_seed; 32]);
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let genesis = genesis(&root, &recovery, 1_000)?;
    let identity_id = genesis.identity_id();
    let repository = IdentityLogRepository::new();
    let bootstrap = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-group-bootstrap\0", &[root_seed]),
        None,
        genesis.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append_bootstrap(store, &bootstrap, UtcMillis::new(1_200)?)
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
        1_100,
    )?;
    assert!(matches!(
        repository
            .append_initial_device(
                store,
                Sha256Digest::hash_domain(b"test-group-initial\0", &[root_seed]),
                genesis.entry_hash()?,
                initial.to_deterministic_cbor()?,
                UtcMillis::new(1_300)?,
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
            UtcMillis::new(NOW)?,
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
            .complete(store, &completion, UtcMillis::new(NOW)?)
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(ActiveDevice {
        identity_id,
        device_id,
        device,
        session_id,
        session_secret,
    })
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

#[allow(clippy::too_many_arguments)]
fn issue_invite_body(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
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
    let proof = action_proof(4, active, scope, path, idempotency_key, &signable, 1_000)?;
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
    let proof = action_proof(6, active, scope, path, idempotency_key, &signable, 1_000)?;
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
fn approve_join_body(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
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
    let proof = action_proof(7, active, scope, path, idempotency_key, &signable, 1_000)?;
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
        utc_value(PROOF_EXPIRES),
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

fn assert_membership_phase(bytes: &[u8], expected_phase: u64) -> Result<(), Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("membership receipt must be a map".into());
    };
    assert_eq!(fields[0].1, CanonicalValue::Unsigned(1));
    assert_eq!(fields[3].1, CanonicalValue::Unsigned(expected_phase));
    Ok(())
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
