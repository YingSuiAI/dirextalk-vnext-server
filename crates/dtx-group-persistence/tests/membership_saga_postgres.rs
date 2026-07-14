#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, str::FromStr};

use dtx_domain::{
    ConversationId, DeviceId, IdentityId, InviteCapabilityId, JoinRequestId, RequestId, Revision,
    TenantId,
};
use dtx_group_persistence::{GroupMembershipRepository, GroupPersistenceError, GroupPgStore};
use dtx_group_policy::{GroupPolicy, GroupScope};
use dtx_membership_command::{
    ApproveJoinCommand, CandidateMembership, JoinRequestCommand, MembershipAdmission,
    MembershipCommandContext, MembershipCommandId, MembershipCommandPhase,
    MembershipCommitReference, MembershipFence, MembershipRejection, SequencerAction,
    SequencerResolution,
};
use dtx_wire::Sha256Digest;

const OWNER: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

fn identity(slot: u8) -> IdentityId {
    let value = format!("dtxi1{}{}", char::from(b'a' + slot), "a".repeat(51));
    IdentityId::from_str(&value).expect("fixture identity ID is canonical")
}

fn owner() -> IdentityId {
    IdentityId::from_str(OWNER).expect("fixture owner ID is canonical")
}

fn uuid(slot: u8) -> &'static str {
    match slot {
        0 => "0190f2a5-7b1c-7abc-8def-0123456789a0",
        1 => "0190f2a5-7b1c-7abc-8def-0123456789a1",
        2 => "0190f2a5-7b1c-7abc-8def-0123456789a2",
        3 => "0190f2a5-7b1c-7abc-8def-0123456789a3",
        4 => "0190f2a5-7b1c-7abc-8def-0123456789a4",
        5 => "0190f2a5-7b1c-7abc-8def-0123456789a5",
        6 => "0190f2a5-7b1c-7abc-8def-0123456789a6",
        7 => "0190f2a5-7b1c-7abc-8def-0123456789a7",
        8 => "0190f2a5-7b1c-7abc-8def-0123456789a8",
        9 => "0190f2a5-7b1c-7abc-8def-0123456789a9",
        _ => panic!("fixture slot is bounded"),
    }
}

fn request_id(slot: u8) -> RequestId {
    RequestId::from_str(uuid(slot)).expect("fixture request ID is canonical")
}

fn device_id(slot: u8) -> DeviceId {
    DeviceId::from_str(uuid(slot)).expect("fixture device ID is canonical")
}

fn join_request_id(slot: u8) -> JoinRequestId {
    JoinRequestId::from_str(uuid(slot)).expect("fixture join request ID is canonical")
}

fn invite_id(slot: u8) -> InviteCapabilityId {
    InviteCapabilityId::from_str(uuid(slot)).expect("fixture invite ID is canonical")
}

fn tenant_id(slot: u8) -> TenantId {
    TenantId::from_str(uuid(slot)).expect("fixture tenant ID is canonical")
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

#[allow(clippy::too_many_arguments)]
fn context(
    command_slot: u8,
    key_byte: u8,
    scope: GroupScope,
    actor: IdentityId,
    actor_device_slot: u8,
    join_slot: u8,
    candidate: IdentityId,
    candidate_device_slot: u8,
    invite_slot: u8,
    policy_revision: Revision,
) -> MembershipCommandContext {
    MembershipCommandContext::new(
        MembershipCommandId::new(request_id(command_slot)),
        digest(key_byte),
        scope,
        actor,
        device_id(actor_device_slot),
        join_request_id(join_slot),
        candidate,
        device_id(candidate_device_slot),
        invite_id(invite_slot),
        MembershipFence::new(policy_revision, digest(0x91)),
    )
}

async fn seeded_group(
    repository: GroupMembershipRepository,
    store: &GroupPgStore,
    tenant_id: TenantId,
    candidate: IdentityId,
) -> Result<(GroupScope, InviteCapabilityId, Revision), GroupPersistenceError> {
    let scope = GroupScope::PrivateConversation(
        ConversationId::from_str(uuid(9)).expect("fixture conversation ID is canonical"),
    );
    let mut policy = GroupPolicy::new(scope, owner());
    let invite = invite_id(4);
    policy.issue_invite(
        policy.revision(),
        owner(),
        invite,
        Some(candidate),
        1,
        100_000,
        1_000,
    )?;
    let revision = policy.revision();
    repository
        .bootstrap(store, tenant_id, &policy, 1_000)
        .await?;
    Ok((scope, invite, revision))
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One response-loss contract keeps the complete recovery path visible.
async fn response_loss_restarts_with_query_and_finalizes_the_original_reservation()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let repository = GroupMembershipRepository;
    let store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let tenant_id = tenant_id(8);
    let candidate = identity(1);
    let (scope, invite, bootstrap_revision) =
        seeded_group(repository, &store, tenant_id, candidate).await?;
    let join_context = context(
        0,
        0x11,
        scope,
        candidate,
        1,
        2,
        candidate,
        3,
        4,
        bootstrap_revision,
    );
    let request = JoinRequestCommand::new(join_context);
    let request_receipt = repository
        .request_join(
            &store,
            tenant_id,
            request,
            CandidateMembership::NotMember,
            2_000,
        )
        .await?;
    assert_eq!(
        request_receipt.phase(),
        MembershipCommandPhase::PendingApproval
    );

    let policy_after_request = repository.load_policy(&store, tenant_id, scope).await?;
    let approval_context = context(
        5,
        0x22,
        scope,
        owner(),
        5,
        2,
        candidate,
        3,
        4,
        policy_after_request.revision(),
    );
    let approval = ApproveJoinCommand::new(approval_context, digest(0x33));
    let approval_receipt = repository
        .approve_join(
            &store,
            tenant_id,
            approval,
            CandidateMembership::NotMember,
            2_100,
        )
        .await?;
    assert_eq!(
        approval_receipt.phase(),
        MembershipCommandPhase::PendingCommit
    );
    let reserved = repository.load_policy(&store, tenant_id, scope).await?;
    assert!(
        reserved
            .reserved_join(join_context.join_request_id())
            .is_some()
    );
    assert!(!reserved.is_member(candidate));
    assert_eq!(
        reserved.invite(invite).expect("invite exists").use_count(),
        0
    );
    assert_eq!(
        reserved
            .invite(invite)
            .expect("invite exists")
            .reserved_use_count(),
        1
    );

    let submit = repository
        .prepare_next_action(&store, tenant_id, 2_200, 500)
        .await?
        .expect("approval produces a submit action");
    let SequencerAction::Submit(payload) = &submit.action else {
        return Err("first outbox dispatch must submit".into());
    };
    let (submitted_command_id, submitted_digest) = payload.idempotency();
    assert!(matches!(
        repository
            .resolve_action(
                &store,
                tenant_id,
                submit.lease,
                SequencerResolution::Absent,
                2_201,
            )
            .await,
        Err(GroupPersistenceError::CorruptData(_))
    ));
    assert!(matches!(
        repository
            .resolve_action(
                &store,
                tenant_id,
                submit.lease,
                SequencerResolution::Unknown,
                2_700,
            )
            .await,
        Err(GroupPersistenceError::LeaseLost)
    ));

    // The original submit lease expires. Recovery starts from a query, whose
    // linearizable absence is the only path that may re-arm the same submit.
    drop(store);
    let restarted = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let query = repository
        .prepare_next_action(&restarted, tenant_id, 2_800, 500)
        .await?
        .expect("restarted recovery must retain an action");
    let SequencerAction::Query(query_payload) = &query.action else {
        return Err("response loss must recover by query, not another submit".into());
    };
    assert_eq!(
        query_payload.idempotency(),
        (submitted_command_id, submitted_digest)
    );
    let rearmed = repository
        .resolve_action(
            &restarted,
            tenant_id,
            query.lease,
            SequencerResolution::Absent,
            2_801,
        )
        .await?;
    assert_eq!(rearmed.phase(), MembershipCommandPhase::PendingCommit);
    let rearmed_submit = repository
        .prepare_next_action(&restarted, tenant_id, 2_802, 500)
        .await?
        .expect("linearizable absence re-arms the original submit");
    let SequencerAction::Submit(rearmed_payload) = &rearmed_submit.action else {
        return Err("linearizable absence must re-arm a submit".into());
    };
    assert_eq!(
        rearmed_payload.idempotency(),
        (submitted_command_id, submitted_digest)
    );
    let remote_commit = MembershipCommitReference::new(
        rearmed_payload.scope(),
        submitted_command_id,
        submitted_digest,
        digest(0x44),
    );
    let reconciling = repository
        .resolve_action(
            &restarted,
            tenant_id,
            rearmed_submit.lease,
            SequencerResolution::Unknown,
            2_803,
        )
        .await?;
    assert_eq!(reconciling.phase(), MembershipCommandPhase::Reconciling);
    let final_query = repository
        .prepare_next_action(&restarted, tenant_id, 2_804, 500)
        .await?
        .expect("uncertain re-armed submit must query before finalization");
    let SequencerAction::Query(final_query_payload) = &final_query.action else {
        return Err("uncertain re-armed submit must recover by query".into());
    };
    assert_eq!(
        final_query_payload.idempotency(),
        (submitted_command_id, submitted_digest)
    );

    let resolved = repository
        .resolve_action(
            &restarted,
            tenant_id,
            final_query.lease,
            SequencerResolution::Committed(remote_commit),
            2_900,
        )
        .await?;
    assert!(matches!(
        resolved.phase(),
        MembershipCommandPhase::Committed(MembershipAdmission::Applied(_))
    ));
    assert_eq!(resolved.command_id(), approval_receipt.command_id());
    assert_eq!(resolved.request_digest(), approval_receipt.request_digest());

    let final_policy = repository.load_policy(&restarted, tenant_id, scope).await?;
    assert!(final_policy.is_member(candidate));
    assert!(
        final_policy
            .reserved_join(join_context.join_request_id())
            .is_none()
    );
    assert_eq!(
        final_policy
            .invite(invite)
            .expect("invite exists")
            .use_count(),
        1
    );
    assert_eq!(
        final_policy
            .invite(invite)
            .expect("invite exists")
            .reserved_use_count(),
        0
    );
    assert!(
        repository
            .prepare_next_action(&restarted, tenant_id, 3_000, 500)
            .await?
            .is_none()
    );

    let replay = repository
        .approve_join(
            &restarted,
            tenant_id,
            approval,
            CandidateMembership::NotMember,
            3_100,
        )
        .await?;
    assert_eq!(replay, resolved);
    Ok(())
}

#[tokio::test]
async fn expired_invite_persists_a_terminal_rejection_before_exact_replay()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let repository = GroupMembershipRepository;
    let store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let tenant_id = tenant_id(8);
    let candidate = identity(1);
    let scope = GroupScope::PrivateConversation(
        ConversationId::from_str(uuid(9)).expect("fixture conversation ID is canonical"),
    );
    let invite = invite_id(4);
    let mut policy = GroupPolicy::new(scope, owner());
    policy.issue_invite(
        policy.revision(),
        owner(),
        invite,
        Some(candidate),
        1,
        1_500,
        1_000,
    )?;
    let revision = policy.revision();
    repository
        .bootstrap(&store, tenant_id, &policy, 1_000)
        .await?;
    let request = JoinRequestCommand::new(context(
        0, 0x51, scope, candidate, 1, 2, candidate, 3, 4, revision,
    ));

    let rejected = repository
        .request_join(
            &store,
            tenant_id,
            request,
            CandidateMembership::NotMember,
            2_000,
        )
        .await?;
    assert_eq!(
        rejected.phase(),
        MembershipCommandPhase::Rejected(MembershipRejection::PolicyDenied)
    );

    drop(store);
    let restarted = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    // `now_ms` is controlled in this contract test: exact replay must return
    // the saved rejection before reevaluating an invite that would be valid.
    let replay = repository
        .request_join(
            &restarted,
            tenant_id,
            request,
            CandidateMembership::NotMember,
            1_200,
        )
        .await?;
    assert_eq!(replay, rejected);
    assert!(
        repository
            .load_policy(&restarted, tenant_id, scope)
            .await?
            .pending_join(request.context().join_request_id())
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn tenant_rows_are_isolated_for_the_same_scope_and_command_identity()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let repository = GroupMembershipRepository;
    let store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let first_tenant = tenant_id(7);
    let second_tenant = tenant_id(8);
    let candidate = identity(1);
    let scope = GroupScope::PrivateConversation(
        ConversationId::from_str(uuid(9)).expect("fixture conversation ID is canonical"),
    );
    let mut policy = GroupPolicy::new(scope, owner());
    policy.issue_invite(
        policy.revision(),
        owner(),
        invite_id(4),
        Some(candidate),
        1,
        100_000,
        1_000,
    )?;
    let revision = policy.revision();
    repository
        .bootstrap(&store, first_tenant, &policy, 1_000)
        .await?;
    repository
        .bootstrap(&store, second_tenant, &policy, 1_000)
        .await?;
    let request = JoinRequestCommand::new(context(
        0, 0x61, scope, candidate, 1, 2, candidate, 3, 4, revision,
    ));

    let first_receipt = repository
        .request_join(
            &store,
            first_tenant,
            request,
            CandidateMembership::NotMember,
            2_000,
        )
        .await?;
    assert_eq!(
        first_receipt.phase(),
        MembershipCommandPhase::PendingApproval
    );
    assert!(
        repository
            .load_policy(&store, second_tenant, scope)
            .await?
            .pending_join(request.context().join_request_id())
            .is_none()
    );

    let second_receipt = repository
        .request_join(
            &store,
            second_tenant,
            request,
            CandidateMembership::NotMember,
            2_000,
        )
        .await?;
    assert_eq!(second_receipt, first_receipt);
    for tenant_id in [first_tenant, second_tenant] {
        assert!(
            repository
                .load_policy(&store, tenant_id, scope)
                .await?
                .pending_join(request.context().join_request_id())
                .is_some()
        );
    }
    Ok(())
}

#[tokio::test]
async fn failed_outbox_write_rolls_back_the_reservation_and_allows_exact_retry()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let repository = GroupMembershipRepository;
    let store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let tenant_id = tenant_id(8);
    let candidate = identity(2);
    let (scope, invite, bootstrap_revision) =
        seeded_group(repository, &store, tenant_id, candidate).await?;
    let join_context = context(
        0,
        0x41,
        scope,
        candidate,
        1,
        2,
        candidate,
        3,
        4,
        bootstrap_revision,
    );
    repository
        .request_join(
            &store,
            tenant_id,
            JoinRequestCommand::new(join_context),
            CandidateMembership::NotMember,
            2_000,
        )
        .await?;
    let current = repository.load_policy(&store, tenant_id, scope).await?;
    let approval = ApproveJoinCommand::new(
        context(
            5,
            0x42,
            scope,
            owner(),
            5,
            2,
            candidate,
            3,
            4,
            current.revision(),
        ),
        digest(0x43),
    );

    sqlx::query("REVOKE INSERT ON groups.sequencer_outbox FROM dtx_group_runtime")
        .execute(harness.admin_pool())
        .await?;
    let failed = repository
        .approve_join(
            &store,
            tenant_id,
            approval,
            CandidateMembership::NotMember,
            2_100,
        )
        .await;
    sqlx::query("GRANT INSERT ON groups.sequencer_outbox TO dtx_group_runtime")
        .execute(harness.admin_pool())
        .await?;
    assert!(matches!(failed, Err(GroupPersistenceError::Database(_))));

    let rolled_back = repository.load_policy(&store, tenant_id, scope).await?;
    assert!(
        rolled_back
            .pending_join(join_context.join_request_id())
            .is_some()
    );
    assert!(
        rolled_back
            .reserved_join(join_context.join_request_id())
            .is_none()
    );
    assert_eq!(
        rolled_back
            .invite(invite)
            .expect("invite exists")
            .reserved_use_count(),
        0
    );

    let retried = repository
        .approve_join(
            &store,
            tenant_id,
            approval,
            CandidateMembership::NotMember,
            2_200,
        )
        .await?;
    assert_eq!(retried.phase(), MembershipCommandPhase::PendingCommit);
    assert!(
        repository
            .prepare_next_action(&store, tenant_id, 2_300, 500)
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn group_writer_rejects_tenant_and_identity_runtime_roles() -> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let valid = GroupPgStore::connect(harness.group_runtime_options(), 1).await?;
    drop(valid);
    let tenant_runtime = GroupPgStore::connect(harness.runtime_options(), 1).await;
    assert!(
        matches!(
            tenant_runtime,
            Err(GroupPersistenceError::RuntimeRoleUnauthorized
                | GroupPersistenceError::RuntimeRoleOverprivileged)
        ),
        "unexpected tenant runtime result: {tenant_runtime:?}"
    );
    let identity_runtime = GroupPgStore::connect(harness.identity_runtime_options(), 1).await;
    assert!(
        matches!(
            identity_runtime,
            Err(GroupPersistenceError::RuntimeRoleUnauthorized
                | GroupPersistenceError::RuntimeRoleOverprivileged)
        ),
        "unexpected identity runtime result: {identity_runtime:?}"
    );
    Ok(())
}
