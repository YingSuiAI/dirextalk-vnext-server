use std::str::FromStr;

use dtx_domain::{
    ConversationId, DeviceId, IdentityId, InviteCapabilityId, JoinRequestId, RequestId, Revision,
};
use dtx_group_policy::GroupScope;
use dtx_membership_command::{
    ApproveJoinCommand, CandidateMembership, JoinRequestCommand, MembershipAdmission,
    MembershipCommandBook, MembershipCommandContext, MembershipCommandError, MembershipCommandId,
    MembershipCommandKind, MembershipCommandPhase, MembershipCommitReference, MembershipFence,
    MembershipRejection, MembershipWorkflowPersistencePhase, SequencerAction, SequencerResolution,
};
use dtx_wire::Sha256Digest;

const OWNER: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

fn identity(slot: u8) -> IdentityId {
    let value = format!("dtxi1{}{}", char::from(b'a' + slot), "a".repeat(51));
    IdentityId::from_str(&value).expect("fixture identity ID is canonical")
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

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn fence() -> MembershipFence {
    MembershipFence::new(Revision::new(7).expect("fixture revision"), digest(0x11))
}

#[allow(clippy::too_many_arguments)]
fn context(
    command_slot: u8,
    key_byte: u8,
    actor: IdentityId,
    actor_device_slot: u8,
    join_slot: u8,
    candidate: IdentityId,
    candidate_device_slot: u8,
    invite_slot: u8,
) -> MembershipCommandContext {
    MembershipCommandContext::new(
        MembershipCommandId::new(request_id(command_slot)),
        digest(key_byte),
        GroupScope::PrivateConversation(
            ConversationId::from_str(uuid(9)).expect("fixture conversation ID is canonical"),
        ),
        actor,
        device_id(actor_device_slot),
        join_request_id(join_slot),
        candidate,
        device_id(candidate_device_slot),
        invite_id(invite_slot),
        fence(),
    )
}

fn with_fence(
    context: MembershipCommandContext,
    replacement: MembershipFence,
) -> MembershipCommandContext {
    MembershipCommandContext::new(
        context.command_id(),
        context.idempotency_key_hash(),
        context.scope(),
        context.actor_identity_id(),
        context.actor_device_id(),
        context.join_request_id(),
        context.candidate_identity_id(),
        context.candidate_device_id(),
        context.invite_id(),
        replacement,
    )
}

fn commit_reference(
    scope: GroupScope,
    command_id: MembershipCommandId,
    request_digest: Sha256Digest,
    byte: u8,
) -> MembershipCommitReference {
    MembershipCommitReference::new(scope, command_id, request_digest, digest(byte))
}

fn assert_durable_rejection(
    book: &MembershipCommandBook,
    command_id: MembershipCommandId,
    rejection: MembershipRejection,
) {
    let receipt = book
        .receipt(command_id)
        .expect("rejected command retains a receipt");
    assert_eq!(receipt.phase(), MembershipCommandPhase::Rejected(rejection));
    let restored = MembershipCommandBook::try_from_snapshot(
        book.snapshot().expect("valid rejected command snapshots"),
    )
    .expect("rejected command rehydrates");
    assert_eq!(
        restored
            .receipt(command_id)
            .expect("restored rejection retains a receipt"),
        receipt
    );
}

#[test]
fn request_digest_is_stable_and_binds_each_membership_coordinate() {
    let candidate = identity(1);
    let base = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let same = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let changed_invite = context(0, 0x22, candidate, 1, 2, candidate, 3, 5);
    let changed_actor = context(0, 0x22, identity(2), 1, 2, candidate, 3, 4);

    assert_eq!(base.join_request_digest(), same.join_request_digest());
    assert_ne!(
        base.join_request_digest(),
        changed_invite.join_request_digest()
    );
    assert_ne!(
        base.join_request_digest(),
        changed_actor.join_request_digest()
    );
}

#[test]
fn request_join_replays_exactly_and_rejects_key_or_command_reuse_with_new_digest() {
    let candidate = identity(1);
    let command = JoinRequestCommand::new(context(0, 0x22, candidate, 1, 2, candidate, 3, 4));
    let mut book = MembershipCommandBook::new();

    let first = book
        .record_join_request(command, CandidateMembership::NotMember)
        .expect("first request records");
    let replay = book
        .record_join_request(command, CandidateMembership::NotMember)
        .expect("same request replays");
    assert_eq!(first, replay);
    assert_eq!(first.phase(), MembershipCommandPhase::PendingApproval);

    let same_key_different_body =
        JoinRequestCommand::new(context(5, 0x22, candidate, 1, 2, candidate, 3, 4));
    assert_eq!(
        book.record_join_request(same_key_different_body, CandidateMembership::NotMember),
        Err(MembershipCommandError::IdempotencyConflict)
    );

    let same_command_different_body =
        JoinRequestCommand::new(context(0, 0x33, candidate, 1, 2, candidate, 3, 5));
    assert_eq!(
        book.record_join_request(same_command_different_body, CandidateMembership::NotMember),
        Err(MembershipCommandError::CommandIdConflict)
    );
}

#[test]
fn request_join_requires_the_candidate_to_be_the_authenticated_actor() {
    let candidate = identity(1);
    let command = JoinRequestCommand::new(context(0, 0x22, identity(2), 1, 2, candidate, 3, 4));

    assert_eq!(
        MembershipCommandBook::new().record_join_request(command, CandidateMembership::NotMember),
        Err(MembershipCommandError::ActorCandidateMismatch)
    );
}

#[test]
fn a_new_join_command_returns_already_member_instead_of_a_second_pending_request() {
    let candidate = identity(1);
    let command = JoinRequestCommand::new(context(0, 0x22, candidate, 1, 2, candidate, 3, 4));
    let existing = commit_reference(
        command.context().scope(),
        MembershipCommandId::new(request_id(5)),
        digest(0x66),
        0x77,
    );
    let mut book = MembershipCommandBook::new();

    let receipt = book
        .record_join_request(command, CandidateMembership::AlreadyMember(existing))
        .expect("member-set lookup resolves the new command");
    assert!(matches!(
        receipt.phase(),
        MembershipCommandPhase::Committed(_)
    ));
    assert_eq!(
        book.record_join_request(command, CandidateMembership::AlreadyMember(existing))
            .expect("exact replay returns the stored receipt"),
        receipt
    );
}

#[test]
fn only_one_approval_can_create_a_pending_commit_for_a_join_request() {
    let candidate = identity(1);
    let owner = IdentityId::from_str(OWNER).expect("fixture owner ID is canonical");
    let admin = identity(2);
    let join = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let approve =
        ApproveJoinCommand::new(context(5, 0x33, owner, 5, 2, candidate, 3, 4), digest(0x44));
    let competing =
        ApproveJoinCommand::new(context(6, 0x55, admin, 6, 2, candidate, 3, 4), digest(0x66));
    let mut book = MembershipCommandBook::new();
    book.record_join_request(
        JoinRequestCommand::new(join),
        CandidateMembership::NotMember,
    )
    .expect("request records");

    let receipt = book
        .approve_join(approve, CandidateMembership::NotMember)
        .expect("approval creates one intent");
    assert_eq!(receipt.phase(), MembershipCommandPhase::PendingCommit);
    assert!(matches!(
        book.next_sequencer_action(approve.context().command_id())
            .expect("known approval"),
        Some(SequencerAction::Submit(_))
    ));
    assert_eq!(
        book.approve_join(competing, CandidateMembership::NotMember),
        Err(MembershipCommandError::JoinCommitInFlight)
    );
}

#[test]
fn approval_uses_its_current_fence_without_requiring_the_pending_request_fence() {
    let candidate = identity(1);
    let owner = IdentityId::from_str(OWNER).expect("fixture owner ID is canonical");
    let join = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let approval_context = with_fence(
        context(5, 0x33, owner, 5, 2, candidate, 3, 4),
        MembershipFence::new(Revision::new(8).expect("fixture revision"), digest(0x12)),
    );
    let approval = ApproveJoinCommand::new(approval_context, digest(0x44));
    let mut book = MembershipCommandBook::new();
    book.record_join_request(
        JoinRequestCommand::new(join),
        CandidateMembership::NotMember,
    )
    .expect("request records");

    assert_eq!(
        book.approve_join(approval, CandidateMembership::NotMember)
            .expect("current approval fence creates the durable intent")
            .phase(),
        MembershipCommandPhase::PendingCommit
    );
    let Some(SequencerAction::Submit(submit)) = book
        .next_sequencer_action(approval_context.command_id())
        .expect("approval is known")
    else {
        panic!("approval must produce a Sequencer submit");
    };
    assert_eq!(submit.actor_identity_id(), owner);
    assert_eq!(submit.actor_device_id(), device_id(5));
    assert_eq!(submit.fence(), approval_context.fence());
}

#[test]
fn response_loss_reconciles_by_query_without_a_second_submit() {
    let candidate = identity(1);
    let owner = IdentityId::from_str(OWNER).expect("fixture owner ID is canonical");
    let join = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let approve =
        ApproveJoinCommand::new(context(5, 0x33, owner, 5, 2, candidate, 3, 4), digest(0x44));
    let mut book = MembershipCommandBook::new();
    book.record_join_request(
        JoinRequestCommand::new(join),
        CandidateMembership::NotMember,
    )
    .expect("request records");
    let pending = book
        .approve_join(approve, CandidateMembership::NotMember)
        .expect("approval records intent");

    let reconciling = book
        .observe_sequencer_resolution(approve.context().command_id(), SequencerResolution::Unknown)
        .expect("lost submit response enters reconciliation");
    assert_eq!(reconciling.phase(), MembershipCommandPhase::Reconciling);
    assert!(matches!(
        book.next_sequencer_action(approve.context().command_id())
            .expect("known approval"),
        Some(SequencerAction::Query(_))
    ));

    let reference = commit_reference(
        approve.context().scope(),
        approve.context().command_id(),
        pending.request_digest(),
        0x77,
    );
    let committed = book
        .observe_sequencer_resolution(
            approve.context().command_id(),
            SequencerResolution::Committed(reference),
        )
        .expect("query discovers remote commit");
    assert!(matches!(
        committed.phase(),
        MembershipCommandPhase::Committed(_)
    ));
    assert_eq!(
        book.next_sequencer_action(approve.context().command_id())
            .expect("known approval"),
        None
    );
    assert_eq!(
        book.approve_join(approve, CandidateMembership::NotMember)
            .expect("approval retry returns the same receipt"),
        committed
    );
}

#[test]
fn already_member_is_a_committed_success_without_sequencer_submission() {
    let candidate = identity(1);
    let owner = IdentityId::from_str(OWNER).expect("fixture owner ID is canonical");
    let join = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let approve =
        ApproveJoinCommand::new(context(5, 0x33, owner, 5, 2, candidate, 3, 4), digest(0x44));
    let mut book = MembershipCommandBook::new();
    book.record_join_request(
        JoinRequestCommand::new(join),
        CandidateMembership::NotMember,
    )
    .expect("request records");
    let existing = commit_reference(
        approve.context().scope(),
        MembershipCommandId::new(request_id(6)),
        digest(0x66),
        0x88,
    );

    let receipt = book
        .approve_join(approve, CandidateMembership::AlreadyMember(existing))
        .expect("existing membership remains a successful receipt");
    assert!(matches!(
        receipt.phase(),
        MembershipCommandPhase::Committed(_)
    ));
    assert_eq!(
        book.next_sequencer_action(approve.context().command_id())
            .expect("known approval"),
        None
    );
    assert_eq!(
        MembershipCommandBook::try_from_snapshot(
            book.snapshot()
                .expect("valid already-member workflow snapshots"),
        )
        .expect("already-member workflow rehydrates"),
        book
    );
    let mut missing_terminal_origin = book
        .snapshot()
        .expect("valid already-member workflow snapshots");
    missing_terminal_origin
        .commands
        .retain(|command| command.workflow_id.is_some());
    assert_eq!(
        MembershipCommandBook::try_from_snapshot(missing_terminal_origin),
        Err(MembershipCommandError::InvariantViolation)
    );
}

#[test]
fn discovered_member_finalizes_an_older_pending_commit_without_another_submit() {
    let candidate = identity(1);
    let owner = IdentityId::from_str(OWNER).expect("fixture owner ID is canonical");
    let admin = identity(2);
    let join = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let first_approval =
        ApproveJoinCommand::new(context(5, 0x33, owner, 5, 2, candidate, 3, 4), digest(0x44));
    let retried_approval =
        ApproveJoinCommand::new(context(6, 0x55, admin, 6, 2, candidate, 3, 4), digest(0x66));
    let mut book = MembershipCommandBook::new();
    book.record_join_request(
        JoinRequestCommand::new(join),
        CandidateMembership::NotMember,
    )
    .expect("request records");
    let first_pending = book
        .approve_join(first_approval, CandidateMembership::NotMember)
        .expect("first approval records intent");
    let remote_commit = commit_reference(
        first_approval.context().scope(),
        first_approval.context().command_id(),
        first_pending.request_digest(),
        0x88,
    );

    let retry = book
        .approve_join(
            retried_approval,
            CandidateMembership::AlreadyMember(remote_commit),
        )
        .expect("current member set resolves the new approval as a success");
    assert!(matches!(
        retry.phase(),
        MembershipCommandPhase::Committed(_)
    ));
    assert!(matches!(
        book.receipt(first_approval.context().command_id())
            .expect("old receipt is repaired")
            .phase(),
        MembershipCommandPhase::Committed(_)
    ));
    assert_eq!(
        book.next_sequencer_action(first_approval.context().command_id())
            .expect("old approval is known"),
        None
    );
    assert_eq!(
        MembershipCommandBook::try_from_snapshot(
            book.snapshot()
                .expect("valid already-member workflow snapshots"),
        )
        .expect("already-member workflow rehydrates"),
        book
    );
}

#[test]
fn explicit_rejection_is_terminal_and_never_consumes_a_later_commit_result() {
    let candidate = identity(1);
    let owner = IdentityId::from_str(OWNER).expect("fixture owner ID is canonical");
    let join = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let approve =
        ApproveJoinCommand::new(context(5, 0x33, owner, 5, 2, candidate, 3, 4), digest(0x44));
    let mut book = MembershipCommandBook::new();
    book.record_join_request(
        JoinRequestCommand::new(join),
        CandidateMembership::NotMember,
    )
    .expect("request records");
    book.approve_join(approve, CandidateMembership::NotMember)
        .expect("approval records intent");

    let rejected = book
        .observe_sequencer_resolution(
            approve.context().command_id(),
            SequencerResolution::Rejected(MembershipRejection::PolicyDenied),
        )
        .expect("explicit remote rejection is terminal");
    assert!(matches!(
        rejected.phase(),
        MembershipCommandPhase::Rejected(_)
    ));
    let reference = commit_reference(
        approve.context().scope(),
        approve.context().command_id(),
        rejected.request_digest(),
        0x99,
    );
    assert_eq!(
        book.observe_sequencer_resolution(
            approve.context().command_id(),
            SequencerResolution::Committed(reference),
        ),
        Err(MembershipCommandError::TerminalResolutionConflict)
    );
}

#[test]
fn local_rejection_persists_pending_request_and_never_dispatched_approval() {
    let candidate = identity(1);
    let owner = IdentityId::from_str(OWNER).expect("fixture owner ID is canonical");
    let join = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let approval =
        ApproveJoinCommand::new(context(5, 0x33, owner, 5, 2, candidate, 3, 4), digest(0x44));

    let mut pending_request = MembershipCommandBook::new();
    pending_request
        .record_join_request(
            JoinRequestCommand::new(join),
            CandidateMembership::NotMember,
        )
        .expect("request records");
    let request_receipt = pending_request
        .reject_locally(join.command_id(), MembershipRejection::AdmissionDenied)
        .expect("pending request can be rejected locally");
    assert_eq!(
        request_receipt.phase(),
        MembershipCommandPhase::Rejected(MembershipRejection::AdmissionDenied)
    );
    assert_durable_rejection(
        &pending_request,
        join.command_id(),
        MembershipRejection::AdmissionDenied,
    );

    let mut pending_approval = MembershipCommandBook::new();
    pending_approval
        .record_join_request(
            JoinRequestCommand::new(join),
            CandidateMembership::NotMember,
        )
        .expect("request records");
    pending_approval
        .approve_join(approval, CandidateMembership::NotMember)
        .expect("approval records a never-dispatched intent");
    let approval_receipt = pending_approval
        .reject_locally(
            approval.context().command_id(),
            MembershipRejection::PolicyDenied,
        )
        .expect("pending approval can be rejected locally before dispatch");
    assert_eq!(
        approval_receipt.phase(),
        MembershipCommandPhase::Rejected(MembershipRejection::PolicyDenied)
    );
    assert_eq!(
        pending_approval
            .next_sequencer_action(approval.context().command_id())
            .expect("rejected approval remains known"),
        None
    );
    assert_durable_rejection(
        &pending_approval,
        approval.context().command_id(),
        MembershipRejection::PolicyDenied,
    );
}

#[test]
fn local_rejection_never_overrides_a_reconciling_approval() {
    let candidate = identity(1);
    let owner = IdentityId::from_str(OWNER).expect("fixture owner ID is canonical");
    let join = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let approval =
        ApproveJoinCommand::new(context(5, 0x33, owner, 5, 2, candidate, 3, 4), digest(0x44));
    let mut book = MembershipCommandBook::new();
    book.record_join_request(
        JoinRequestCommand::new(join),
        CandidateMembership::NotMember,
    )
    .expect("request records");
    book.approve_join(approval, CandidateMembership::NotMember)
        .expect("approval records intent");
    book.observe_sequencer_resolution(
        approval.context().command_id(),
        SequencerResolution::Unknown,
    )
    .expect("uncertain submit enters reconciliation");

    assert_eq!(
        book.reject_locally(
            approval.context().command_id(),
            MembershipRejection::PolicyDenied,
        ),
        Err(MembershipCommandError::CommandNotReady)
    );
    assert_eq!(
        book.receipt(approval.context().command_id())
            .expect("reconciling approval retains a receipt")
            .phase(),
        MembershipCommandPhase::Reconciling
    );
    assert!(matches!(
        book.next_sequencer_action(approval.context().command_id())
            .expect("reconciling approval remains known"),
        Some(SequencerAction::Query(_))
    ));
}

#[test]
fn terminal_snapshot_rejects_missing_or_mismatched_approval_linkage() {
    let candidate = identity(1);
    let owner = IdentityId::from_str(OWNER).expect("fixture owner ID is canonical");
    let join = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let approve =
        ApproveJoinCommand::new(context(5, 0x33, owner, 5, 2, candidate, 3, 4), digest(0x44));

    let mut rejected_book = MembershipCommandBook::new();
    rejected_book
        .record_join_request(
            JoinRequestCommand::new(join),
            CandidateMembership::NotMember,
        )
        .expect("request records");
    rejected_book
        .approve_join(approve, CandidateMembership::NotMember)
        .expect("approval records intent");
    rejected_book
        .observe_sequencer_resolution(
            approve.context().command_id(),
            SequencerResolution::Rejected(MembershipRejection::PolicyDenied),
        )
        .expect("remote rejection is terminal");
    let mut missing_approval = rejected_book
        .snapshot()
        .expect("valid rejected workflow snapshots");
    missing_approval
        .commands
        .retain(|command| command.kind != MembershipCommandKind::ApproveJoin);
    assert_eq!(
        MembershipCommandBook::try_from_snapshot(missing_approval),
        Err(MembershipCommandError::InvariantViolation)
    );

    let mut applied_book = MembershipCommandBook::new();
    applied_book
        .record_join_request(
            JoinRequestCommand::new(join),
            CandidateMembership::NotMember,
        )
        .expect("request records");
    let pending = applied_book
        .approve_join(approve, CandidateMembership::NotMember)
        .expect("approval records intent");
    applied_book
        .observe_sequencer_resolution(
            approve.context().command_id(),
            SequencerResolution::Committed(commit_reference(
                approve.context().scope(),
                approve.context().command_id(),
                pending.request_digest(),
                0x77,
            )),
        )
        .expect("remote commit is terminal");
    let mut mismatched_commit = applied_book
        .snapshot()
        .expect("valid committed workflow snapshots");
    mismatched_commit.workflows[0].phase = MembershipWorkflowPersistencePhase::Committed(
        MembershipAdmission::Applied(commit_reference(
            approve.context().scope(),
            MembershipCommandId::new(request_id(6)),
            pending.request_digest(),
            0x88,
        )),
    );
    assert_eq!(
        MembershipCommandBook::try_from_snapshot(mismatched_commit),
        Err(MembershipCommandError::InvariantViolation)
    );
}

#[test]
fn terminal_snapshot_rejects_independent_terminal_shapes_the_reducer_cannot_emit() {
    let candidate = identity(1);
    let request = JoinRequestCommand::new(context(0, 0x22, candidate, 1, 2, candidate, 3, 4));
    let existing = commit_reference(
        request.context().scope(),
        MembershipCommandId::new(request_id(5)),
        digest(0x66),
        0x77,
    );

    let mut already_member = MembershipCommandBook::new();
    already_member
        .record_join_request(request, CandidateMembership::AlreadyMember(existing))
        .expect("already-member request records a standalone terminal receipt");
    let mut forged_applied = already_member
        .snapshot()
        .expect("valid already-member snapshot");
    forged_applied.commands[0].terminal_phase = Some(MembershipCommandPhase::Committed(
        MembershipAdmission::Applied(existing),
    ));
    assert_eq!(
        MembershipCommandBook::try_from_snapshot(forged_applied),
        Err(MembershipCommandError::InvariantViolation)
    );

    let mut rejected_request = MembershipCommandBook::new();
    rejected_request
        .record_join_request(request, CandidateMembership::NotMember)
        .expect("request records before local rejection");
    rejected_request
        .reject_locally(
            request.context().command_id(),
            MembershipRejection::PolicyDenied,
        )
        .expect("pending request is locally rejectable");
    let mut forged_approval_rejection = rejected_request
        .snapshot()
        .expect("valid locally rejected request snapshot");
    forged_approval_rejection.commands[0].kind = MembershipCommandKind::ApproveJoin;
    assert_eq!(
        MembershipCommandBook::try_from_snapshot(forged_approval_rejection),
        Err(MembershipCommandError::InvariantViolation)
    );
}

#[test]
fn persisted_reconciling_command_queries_before_a_linearizable_absence_rearms_same_submit() {
    let candidate = identity(1);
    let owner = IdentityId::from_str(OWNER).expect("fixture owner ID is canonical");
    let join = context(0, 0x22, candidate, 1, 2, candidate, 3, 4);
    let approve =
        ApproveJoinCommand::new(context(5, 0x33, owner, 5, 2, candidate, 3, 4), digest(0x44));
    let mut book = MembershipCommandBook::new();
    book.record_join_request(
        JoinRequestCommand::new(join),
        CandidateMembership::NotMember,
    )
    .expect("request records");
    book.approve_join(approve, CandidateMembership::NotMember)
        .expect("approval records intent");
    let original_submit = book
        .next_sequencer_action(approve.context().command_id())
        .expect("known approval")
        .expect("pending commit submits once");
    assert!(matches!(&original_submit, SequencerAction::Submit(_)));

    book.observe_sequencer_resolution(approve.context().command_id(), SequencerResolution::Unknown)
        .expect("uncertain submit enters reconciliation");
    let restored = MembershipCommandBook::try_from_snapshot(
        book.snapshot().expect("valid reducer state snapshots"),
    )
    .expect("durable command image rehydrates");
    assert_eq!(restored, book);
    assert!(matches!(
        restored
            .next_sequencer_action(approve.context().command_id())
            .expect("reconciled command exists"),
        Some(SequencerAction::Query(_))
    ));

    let mut restored = restored;
    restored
        .observe_sequencer_resolution(approve.context().command_id(), SequencerResolution::Absent)
        .expect("only a linearizable absence re-arms the command");
    assert_eq!(
        restored
            .next_sequencer_action(approve.context().command_id())
            .expect("re-armed command exists"),
        Some(original_submit)
    );
}
