#![forbid(unsafe_code)]

//! Pure, replay-safe membership-command coordination.
//!
//! This crate deliberately models neither MLS cryptography nor database I/O. It
//! retains the command, receipt, and Sequencer-query invariants that a durable
//! repository must preserve around those external boundaries.

use std::{collections::BTreeMap, error::Error, fmt};

use dtx_domain::{DeviceId, IdentityId, InviteCapabilityId, JoinRequestId, RequestId, Revision};
use dtx_group_policy::GroupScope;
use dtx_wire::{CanonicalValue, Sha256Digest, encode_deterministic_cbor};

/// Domain separator for an internal, canonical membership command request digest.
pub const MEMBERSHIP_COMMAND_REQUEST_HASH_DOMAIN: &[u8] =
    b"dirextalk.membership-command-request.v1\0";

/// Typed command identity for one membership action.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MembershipCommandId(RequestId);

impl MembershipCommandId {
    /// Creates a typed membership command identity from the stable request ID.
    #[must_use]
    pub const fn new(request_id: RequestId) -> Self {
        Self(request_id)
    }

    /// Returns the underlying stable request identifier.
    #[must_use]
    pub const fn request_id(self) -> RequestId {
        self.0
    }
}

/// Fences a membership action to one policy revision and opaque Sequencer head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipFence {
    policy_revision: Revision,
    sequencer_head: Sha256Digest,
}

impl MembershipFence {
    /// Creates a typed fence from already verified group-head facts.
    #[must_use]
    pub const fn new(policy_revision: Revision, sequencer_head: Sha256Digest) -> Self {
        Self {
            policy_revision,
            sequencer_head,
        }
    }

    /// Returns the policy revision that the actor authorized.
    #[must_use]
    pub const fn policy_revision(self) -> Revision {
        self.policy_revision
    }

    /// Returns the opaque expected Sequencer head digest.
    #[must_use]
    pub const fn sequencer_head(self) -> Sha256Digest {
        self.sequencer_head
    }
}

/// Common, authenticated fields of a join request or approval command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipCommandContext {
    command_id: MembershipCommandId,
    idempotency_key_hash: Sha256Digest,
    scope: GroupScope,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    join_request_id: JoinRequestId,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    invite_id: InviteCapabilityId,
    fence: MembershipFence,
}

impl MembershipCommandContext {
    /// Constructs one bounded, already authenticated command context.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        command_id: MembershipCommandId,
        idempotency_key_hash: Sha256Digest,
        scope: GroupScope,
        actor_identity_id: IdentityId,
        actor_device_id: DeviceId,
        join_request_id: JoinRequestId,
        candidate_identity_id: IdentityId,
        candidate_device_id: DeviceId,
        invite_id: InviteCapabilityId,
        fence: MembershipFence,
    ) -> Self {
        Self {
            command_id,
            idempotency_key_hash,
            scope,
            actor_identity_id,
            actor_device_id,
            join_request_id,
            candidate_identity_id,
            candidate_device_id,
            invite_id,
            fence,
        }
    }

    /// Computes the canonical digest for the candidate-authored join command.
    #[must_use]
    pub fn join_request_digest(self) -> Sha256Digest {
        command_digest(CommandKind::RequestJoin, self, None)
    }

    /// Returns the stable command identity.
    #[must_use]
    pub const fn command_id(self) -> MembershipCommandId {
        self.command_id
    }

    /// Returns only the retained hash of the caller-provided idempotency key.
    #[must_use]
    pub const fn idempotency_key_hash(self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    /// Returns the private-group or controlled-public-channel boundary.
    #[must_use]
    pub const fn scope(self) -> GroupScope {
        self.scope
    }

    /// Returns the authenticated action actor.
    #[must_use]
    pub const fn actor_identity_id(self) -> IdentityId {
        self.actor_identity_id
    }

    /// Returns the authenticated actor device.
    #[must_use]
    pub const fn actor_device_id(self) -> DeviceId {
        self.actor_device_id
    }

    /// Returns the join workflow identity.
    #[must_use]
    pub const fn join_request_id(self) -> JoinRequestId {
        self.join_request_id
    }

    /// Returns the candidate identity to admit.
    #[must_use]
    pub const fn candidate_identity_id(self) -> IdentityId {
        self.candidate_identity_id
    }

    /// Returns the candidate MLS device leaf identity.
    #[must_use]
    pub const fn candidate_device_id(self) -> DeviceId {
        self.candidate_device_id
    }

    /// Returns the invitation capability being consumed on a successful commit.
    #[must_use]
    pub const fn invite_id(self) -> InviteCapabilityId {
        self.invite_id
    }

    /// Returns the expected group policy and Sequencer fence.
    #[must_use]
    pub const fn fence(self) -> MembershipFence {
        self.fence
    }
}

/// Candidate-authored command that creates a pending approval workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinRequestCommand {
    context: MembershipCommandContext,
    request_digest: Sha256Digest,
}

impl JoinRequestCommand {
    /// Computes and retains the bounded canonical join-request digest.
    #[must_use]
    pub fn new(context: MembershipCommandContext) -> Self {
        Self {
            request_digest: context.join_request_digest(),
            context,
        }
    }

    /// Returns the authenticated command context.
    #[must_use]
    pub const fn context(self) -> MembershipCommandContext {
        self.context
    }

    /// Returns the request digest that participates in idempotency checks.
    #[must_use]
    pub const fn request_digest(self) -> Sha256Digest {
        self.request_digest
    }
}

/// Owner/Admin command that moves a pending request into a Sequencer intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApproveJoinCommand {
    context: MembershipCommandContext,
    authorization_digest: Sha256Digest,
    request_digest: Sha256Digest,
}

impl ApproveJoinCommand {
    /// Computes and retains the bounded canonical approval-command digest.
    #[must_use]
    pub fn new(context: MembershipCommandContext, authorization_digest: Sha256Digest) -> Self {
        Self {
            request_digest: command_digest(
                CommandKind::ApproveJoin,
                context,
                Some(authorization_digest),
            ),
            context,
            authorization_digest,
        }
    }

    /// Returns the authenticated command context.
    #[must_use]
    pub const fn context(self) -> MembershipCommandContext {
        self.context
    }

    /// Returns the digest of the already verified Owner/Admin authorization proof.
    #[must_use]
    pub const fn authorization_digest(self) -> Sha256Digest {
        self.authorization_digest
    }

    /// Returns the request digest that participates in idempotency checks.
    #[must_use]
    pub const fn request_digest(self) -> Sha256Digest {
        self.request_digest
    }
}

/// Opaque, verified reference to one remote membership commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipCommitReference {
    scope: GroupScope,
    command_id: MembershipCommandId,
    request_digest: Sha256Digest,
    committed_digest: Sha256Digest,
}

impl MembershipCommitReference {
    /// Creates the minimal opaque reference retained before MLS-specific fields exist.
    #[must_use]
    pub const fn new(
        scope: GroupScope,
        command_id: MembershipCommandId,
        request_digest: Sha256Digest,
        committed_digest: Sha256Digest,
    ) -> Self {
        Self {
            scope,
            command_id,
            request_digest,
            committed_digest,
        }
    }

    /// Returns the group scope to which the commit belongs.
    #[must_use]
    pub const fn scope(self) -> GroupScope {
        self.scope
    }

    /// Returns the command the remote Sequencer de-duplicated.
    #[must_use]
    pub const fn command_id(self) -> MembershipCommandId {
        self.command_id
    }

    /// Returns the command digest authenticated by the remote reference.
    #[must_use]
    pub const fn request_digest(self) -> Sha256Digest {
        self.request_digest
    }

    /// Returns the opaque digest of the committed remote evidence.
    #[must_use]
    pub const fn committed_digest(self) -> Sha256Digest {
        self.committed_digest
    }
}

/// Successful membership disposition retained in a terminal receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipAdmission {
    /// This command caused the candidate device to become a member leaf.
    Applied(MembershipCommitReference),
    /// The candidate was already a member; no invitation was consumed.
    AlreadyMember(MembershipCommitReference),
}

impl MembershipAdmission {
    /// Returns the associated, verified commit reference.
    #[must_use]
    pub const fn commit_reference(self) -> MembershipCommitReference {
        match self {
            Self::Applied(reference) | Self::AlreadyMember(reference) => reference,
        }
    }
}

/// Stable, non-secret remote rejection class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipRejection {
    /// The remote Sequencer rejected the submitted policy/action proof.
    PolicyDenied,
    /// The remote Sequencer rejected the predecessor fence.
    StaleFence,
    /// The remote Sequencer rejected the candidate or invitation binding.
    AdmissionDenied,
}

/// Current replayable phase for a membership command receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipCommandPhase {
    /// The candidate request is durable but has not received an Owner/Admin approval.
    PendingApproval,
    /// A durable intent/outbox exists and may be submitted under this command ID.
    PendingCommit,
    /// The remote effect may have happened; callers must query before any new submit.
    Reconciling,
    /// The workflow reached a successful, replayable admission result.
    Committed(MembershipAdmission),
    /// The Sequencer explicitly rejected the command; this is terminal.
    Rejected(MembershipRejection),
}

/// A non-secret current receipt returned for exact replay and reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipReceipt {
    command_id: MembershipCommandId,
    request_digest: Sha256Digest,
    phase: MembershipCommandPhase,
}

impl MembershipReceipt {
    /// Returns the stable membership command identity.
    #[must_use]
    pub const fn command_id(self) -> MembershipCommandId {
        self.command_id
    }

    /// Returns the immutable digest of the original command body.
    #[must_use]
    pub const fn request_digest(self) -> Sha256Digest {
        self.request_digest
    }

    /// Returns the latest durable workflow state for this command.
    #[must_use]
    pub const fn phase(self) -> MembershipCommandPhase {
        self.phase
    }
}

/// Caller-provided member-set fact established before a new approval intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateMembership {
    /// The exact identity/device pair is not yet a committed member leaf.
    NotMember,
    /// The exact identity/device pair already has a verified membership reference.
    AlreadyMember(MembershipCommitReference),
}

/// Result returned by a de-duplicating remote Membership Sequencer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequencerResolution {
    /// The remote Sequencer committed exactly one matching membership action.
    Committed(MembershipCommitReference),
    /// The remote Sequencer explicitly rejected the action.
    Rejected(MembershipRejection),
    /// The caller cannot tell whether submit happened and must query later.
    Unknown,
}

/// Opaque submit payload for a later MLS-aware Sequencer adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequencerSubmit {
    scope: GroupScope,
    command_id: MembershipCommandId,
    request_digest: Sha256Digest,
    join_request_id: JoinRequestId,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    invite_id: InviteCapabilityId,
    fence: MembershipFence,
    authorization_digest: Sha256Digest,
}

impl SequencerSubmit {
    /// Returns the exact idempotency pair the Sequencer must retain.
    #[must_use]
    pub const fn idempotency(self) -> (MembershipCommandId, Sha256Digest) {
        (self.command_id, self.request_digest)
    }

    /// Returns the group scope under which the commit must be ordered.
    #[must_use]
    pub const fn scope(self) -> GroupScope {
        self.scope
    }

    /// Returns the Owner/Admin identity that authorized this commit intent.
    #[must_use]
    pub const fn actor_identity_id(self) -> IdentityId {
        self.actor_identity_id
    }

    /// Returns the Owner/Admin device that authorized this commit intent.
    #[must_use]
    pub const fn actor_device_id(self) -> DeviceId {
        self.actor_device_id
    }

    /// Returns the pending join request being finalized.
    #[must_use]
    pub const fn join_request_id(self) -> JoinRequestId {
        self.join_request_id
    }

    /// Returns the identity whose MLS device leaf is being admitted.
    #[must_use]
    pub const fn candidate_identity_id(self) -> IdentityId {
        self.candidate_identity_id
    }

    /// Returns the MLS device leaf being admitted.
    #[must_use]
    pub const fn candidate_device_id(self) -> DeviceId {
        self.candidate_device_id
    }

    /// Returns the invitation capability reserved by this commit intent.
    #[must_use]
    pub const fn invite_id(self) -> InviteCapabilityId {
        self.invite_id
    }

    /// Returns the request-level group-policy and Sequencer fence.
    #[must_use]
    pub const fn fence(self) -> MembershipFence {
        self.fence
    }

    /// Returns the verified Owner/Admin authorization-proof digest.
    #[must_use]
    pub const fn authorization_digest(self) -> Sha256Digest {
        self.authorization_digest
    }
}

/// Lookup payload that never invents a new remote command identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequencerQuery {
    scope: GroupScope,
    command_id: MembershipCommandId,
    request_digest: Sha256Digest,
}

impl SequencerQuery {
    /// Returns the group scope under which the lookup is performed.
    #[must_use]
    pub const fn scope(self) -> GroupScope {
        self.scope
    }

    /// Returns the exact idempotency pair to query.
    #[must_use]
    pub const fn idempotency(self) -> (MembershipCommandId, Sha256Digest) {
        (self.command_id, self.request_digest)
    }
}

/// Next externally visible action permitted for one durable command state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SequencerAction {
    /// Submit a never-before-attempted durable intent.
    Submit(Box<SequencerSubmit>),
    /// Query an uncertain intent; do not issue another submit.
    Query(SequencerQuery),
}

/// Port that an MLS-aware Sequencer adapter will implement in a later stage.
pub trait CommitSequencer {
    /// Adapter-specific transport or availability failure.
    type Error;

    /// Idempotently submits one command identity/digest pair.
    ///
    /// # Errors
    ///
    /// Returns the adapter's transport, availability, or validation error.
    fn submit(&mut self, request: &SequencerSubmit) -> Result<SequencerResolution, Self::Error>;

    /// Queries the exact same command identity/digest pair after uncertainty.
    ///
    /// # Errors
    ///
    /// Returns the adapter's transport, availability, or validation error.
    fn query(&mut self, request: &SequencerQuery) -> Result<SequencerResolution, Self::Error>;
}

/// In-memory, replay-safe command/receipt model for one or more group scopes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MembershipCommandBook {
    commands: BTreeMap<MembershipCommandId, StoredCommand>,
    idempotency: BTreeMap<IdempotencyLookup, MembershipCommandId>,
    workflows: BTreeMap<JoinRequestId, JoinWorkflow>,
}

impl MembershipCommandBook {
    /// Creates an empty command book suitable for deterministic tests or rehydration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            commands: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            workflows: BTreeMap::new(),
        }
    }

    /// Records or exactly replays a candidate-authored pending join request.
    ///
    /// The caller must already authenticate the actor identity/device. This pure
    /// boundary additionally rejects using one identity to request another
    /// identity's admission.
    ///
    /// # Errors
    ///
    /// Returns a conflict for reused command/key/workflow identities or an
    /// actor/candidate mismatch for a non-self-authored request.
    pub fn record_join_request(
        &mut self,
        command: JoinRequestCommand,
        candidate_membership: CandidateMembership,
    ) -> Result<MembershipReceipt, MembershipCommandError> {
        let context = command.context;
        if let Some(receipt) = self.existing_or_conflict(
            context.command_id,
            command.request_digest,
            IdempotencyLookup::new(context),
        )? {
            return Ok(receipt);
        }
        if context.actor_identity_id != context.candidate_identity_id {
            return Err(MembershipCommandError::ActorCandidateMismatch);
        }
        if let CandidateMembership::AlreadyMember(reference) = candidate_membership {
            if reference.scope != context.scope {
                return Err(MembershipCommandError::CommitReferenceMismatch);
            }
            let phase =
                MembershipCommandPhase::Committed(MembershipAdmission::AlreadyMember(reference));
            self.commands.insert(
                context.command_id,
                StoredCommand::terminal(CommandKind::RequestJoin, command.request_digest, phase),
            );
            self.idempotency
                .insert(IdempotencyLookup::new(context), context.command_id);
            return self.receipt_for(context.command_id);
        }
        if self.workflows.contains_key(&context.join_request_id) {
            return Err(MembershipCommandError::JoinRequestConflict);
        }

        self.commands.insert(
            context.command_id,
            StoredCommand::workflow(
                CommandKind::RequestJoin,
                command.request_digest,
                context.join_request_id,
            ),
        );
        self.idempotency
            .insert(IdempotencyLookup::new(context), context.command_id);
        self.workflows
            .insert(context.join_request_id, JoinWorkflow::pending(context));
        self.receipt_for(context.command_id)
    }

    /// Records or exactly replays an Owner/Admin-approved commit intent.
    ///
    /// Group-policy authorization, signature verification, invite reservation,
    /// and database locking must happen before calling this reducer. The member
    /// fact is explicitly supplied so an already-present device resolves as a
    /// successful `AlreadyMember` receipt and finalizes any active workflow
    /// before another remote submit.
    ///
    /// # Errors
    ///
    /// Returns a replay conflict, an unknown or mismatched join request, or a
    /// conflict when another approval owns the active workflow.
    pub fn approve_join(
        &mut self,
        command: ApproveJoinCommand,
        candidate_membership: CandidateMembership,
    ) -> Result<MembershipReceipt, MembershipCommandError> {
        let context = command.context;
        if let Some(receipt) = self.existing_or_conflict(
            context.command_id,
            command.request_digest,
            IdempotencyLookup::new(context),
        )? {
            return Ok(receipt);
        }
        let workflow = self
            .workflows
            .get(&context.join_request_id)
            .copied()
            .ok_or(MembershipCommandError::JoinRequestNotFound)?;
        if !workflow.matches(context) {
            return Err(MembershipCommandError::JoinRequestMismatch);
        }

        if let CandidateMembership::AlreadyMember(reference) = candidate_membership {
            if reference.scope != context.scope {
                return Err(MembershipCommandError::CommitReferenceMismatch);
            }
            let phase =
                MembershipCommandPhase::Committed(MembershipAdmission::AlreadyMember(reference));
            self.commands.insert(
                context.command_id,
                StoredCommand::terminal(CommandKind::ApproveJoin, command.request_digest, phase),
            );
            self.idempotency
                .insert(IdempotencyLookup::new(context), context.command_id);
            if matches!(
                workflow.phase,
                WorkflowPhase::PendingApproval
                    | WorkflowPhase::PendingCommit { .. }
                    | WorkflowPhase::Reconciling { .. }
            ) {
                self.workflows.insert(
                    context.join_request_id,
                    JoinWorkflow {
                        phase: WorkflowPhase::Committed(MembershipAdmission::AlreadyMember(
                            reference,
                        )),
                        ..workflow
                    },
                );
            }
            return self.receipt_for(context.command_id);
        }

        match workflow.phase {
            WorkflowPhase::PendingApproval => {
                self.commands.insert(
                    context.command_id,
                    StoredCommand::workflow(
                        CommandKind::ApproveJoin,
                        command.request_digest,
                        context.join_request_id,
                    ),
                );
                self.idempotency
                    .insert(IdempotencyLookup::new(context), context.command_id);
                self.workflows.insert(
                    context.join_request_id,
                    JoinWorkflow {
                        phase: WorkflowPhase::PendingCommit {
                            approval_command_id: context.command_id,
                            approval_context: context,
                            authorization_digest: command.authorization_digest,
                        },
                        ..workflow
                    },
                );
                self.receipt_for(context.command_id)
            }
            WorkflowPhase::PendingCommit { .. } | WorkflowPhase::Reconciling { .. } => {
                Err(MembershipCommandError::JoinCommitInFlight)
            }
            WorkflowPhase::Committed(_) | WorkflowPhase::Rejected(_) => {
                Err(MembershipCommandError::JoinWorkflowTerminal)
            }
        }
    }

    /// Returns the next safe Sequencer action, if this command needs one.
    ///
    /// # Errors
    ///
    /// Returns an error when the command is unknown or rehydrated command and
    /// workflow records are inconsistent.
    pub fn next_sequencer_action(
        &self,
        command_id: MembershipCommandId,
    ) -> Result<Option<SequencerAction>, MembershipCommandError> {
        let command = self
            .commands
            .get(&command_id)
            .ok_or(MembershipCommandError::CommandNotFound)?;
        let Some(workflow_id) = command.workflow_id else {
            return Ok(None);
        };
        if command.kind != CommandKind::ApproveJoin {
            return Ok(None);
        }
        let workflow = self
            .workflows
            .get(&workflow_id)
            .ok_or(MembershipCommandError::InvariantViolation)?;
        let action = match workflow.phase {
            WorkflowPhase::PendingCommit {
                approval_command_id,
                approval_context,
                authorization_digest,
            } if approval_command_id == command_id => {
                Some(SequencerAction::Submit(Box::new(SequencerSubmit {
                    scope: approval_context.scope,
                    command_id,
                    request_digest: command.request_digest,
                    join_request_id: approval_context.join_request_id,
                    actor_identity_id: approval_context.actor_identity_id,
                    actor_device_id: approval_context.actor_device_id,
                    candidate_identity_id: approval_context.candidate_identity_id,
                    candidate_device_id: approval_context.candidate_device_id,
                    invite_id: approval_context.invite_id,
                    fence: approval_context.fence,
                    authorization_digest,
                })))
            }
            WorkflowPhase::Reconciling {
                approval_command_id,
            } if approval_command_id == command_id => {
                Some(SequencerAction::Query(SequencerQuery {
                    scope: workflow.context.scope,
                    command_id,
                    request_digest: command.request_digest,
                }))
            }
            _ => None,
        };
        Ok(action)
    }

    /// Applies a submit or lookup result to the one active approval workflow.
    ///
    /// An uncertain result advances to `Reconciling`; only an explicit remote
    /// rejection is terminal. A verified commit must bind the exact command ID,
    /// request digest, and scope before it can finalize the workflow.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown/non-approval command, invalid commit
    /// reference, impossible transition, or contradictory terminal result.
    pub fn observe_sequencer_resolution(
        &mut self,
        command_id: MembershipCommandId,
        resolution: SequencerResolution,
    ) -> Result<MembershipReceipt, MembershipCommandError> {
        let command = self
            .commands
            .get(&command_id)
            .copied()
            .ok_or(MembershipCommandError::CommandNotFound)?;
        if command.kind != CommandKind::ApproveJoin {
            return Err(MembershipCommandError::CommandNotReady);
        }
        let workflow_id = command
            .workflow_id
            .ok_or(MembershipCommandError::CommandNotReady)?;
        let workflow = self
            .workflows
            .get(&workflow_id)
            .copied()
            .ok_or(MembershipCommandError::InvariantViolation)?;

        let next_phase = match workflow.phase {
            WorkflowPhase::PendingCommit {
                approval_command_id,
                ..
            }
            | WorkflowPhase::Reconciling {
                approval_command_id,
            } if approval_command_id == command_id => match resolution {
                SequencerResolution::Unknown => WorkflowPhase::Reconciling {
                    approval_command_id: command_id,
                },
                SequencerResolution::Rejected(rejection) => WorkflowPhase::Rejected(rejection),
                SequencerResolution::Committed(reference) => {
                    validate_commit_reference(
                        reference,
                        workflow.context.scope,
                        command_id,
                        command.request_digest,
                    )?;
                    WorkflowPhase::Committed(MembershipAdmission::Applied(reference))
                }
            },
            WorkflowPhase::Committed(admission) => {
                if resolution == SequencerResolution::Committed(admission.commit_reference()) {
                    return self.receipt_for(command_id);
                }
                return Err(MembershipCommandError::TerminalResolutionConflict);
            }
            WorkflowPhase::Rejected(rejection) => {
                if resolution == SequencerResolution::Rejected(rejection) {
                    return self.receipt_for(command_id);
                }
                return Err(MembershipCommandError::TerminalResolutionConflict);
            }
            _ => return Err(MembershipCommandError::CommandNotReady),
        };
        self.workflows.insert(
            workflow_id,
            JoinWorkflow {
                phase: next_phase,
                ..workflow
            },
        );
        self.receipt_for(command_id)
    }

    /// Reads the current replayable receipt without mutating state.
    ///
    /// # Errors
    ///
    /// Returns an error when the command is unknown or rehydrated records are
    /// inconsistent.
    pub fn receipt(
        &self,
        command_id: MembershipCommandId,
    ) -> Result<MembershipReceipt, MembershipCommandError> {
        self.receipt_for(command_id)
    }

    fn existing_or_conflict(
        &self,
        command_id: MembershipCommandId,
        request_digest: Sha256Digest,
        idempotency: IdempotencyLookup,
    ) -> Result<Option<MembershipReceipt>, MembershipCommandError> {
        if let Some(existing) = self.commands.get(&command_id) {
            if existing.request_digest != request_digest {
                return Err(MembershipCommandError::CommandIdConflict);
            }
            return self.receipt_for(command_id).map(Some);
        }
        if let Some(existing_id) = self.idempotency.get(&idempotency) {
            let existing = self
                .commands
                .get(existing_id)
                .ok_or(MembershipCommandError::InvariantViolation)?;
            if existing.request_digest != request_digest {
                return Err(MembershipCommandError::IdempotencyConflict);
            }
            return self.receipt_for(*existing_id).map(Some);
        }
        Ok(None)
    }

    fn receipt_for(
        &self,
        command_id: MembershipCommandId,
    ) -> Result<MembershipReceipt, MembershipCommandError> {
        let command = self
            .commands
            .get(&command_id)
            .ok_or(MembershipCommandError::CommandNotFound)?;
        let phase = match (command.workflow_id, command.terminal_phase) {
            (Some(workflow_id), None) => self
                .workflows
                .get(&workflow_id)
                .map(|workflow| workflow.phase.as_public())
                .ok_or(MembershipCommandError::InvariantViolation)?,
            (None, Some(phase)) => phase,
            _ => return Err(MembershipCommandError::InvariantViolation),
        };
        Ok(MembershipReceipt {
            command_id,
            request_digest: command.request_digest,
            phase,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct IdempotencyLookup {
    scope: GroupScope,
    actor_identity_id: IdentityId,
    idempotency_key_hash: Sha256Digest,
}

impl IdempotencyLookup {
    const fn new(context: MembershipCommandContext) -> Self {
        Self {
            scope: context.scope,
            actor_identity_id: context.actor_identity_id,
            idempotency_key_hash: context.idempotency_key_hash,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoredCommand {
    kind: CommandKind,
    request_digest: Sha256Digest,
    workflow_id: Option<JoinRequestId>,
    terminal_phase: Option<MembershipCommandPhase>,
}

impl StoredCommand {
    const fn workflow(
        kind: CommandKind,
        request_digest: Sha256Digest,
        workflow_id: JoinRequestId,
    ) -> Self {
        Self {
            kind,
            request_digest,
            workflow_id: Some(workflow_id),
            terminal_phase: None,
        }
    }

    const fn terminal(
        kind: CommandKind,
        request_digest: Sha256Digest,
        terminal_phase: MembershipCommandPhase,
    ) -> Self {
        Self {
            kind,
            request_digest,
            workflow_id: None,
            terminal_phase: Some(terminal_phase),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JoinWorkflow {
    context: MembershipCommandContext,
    phase: WorkflowPhase,
}

impl JoinWorkflow {
    const fn pending(context: MembershipCommandContext) -> Self {
        Self {
            context,
            phase: WorkflowPhase::PendingApproval,
        }
    }

    fn matches(self, context: MembershipCommandContext) -> bool {
        self.context.scope == context.scope
            && self.context.join_request_id == context.join_request_id
            && self.context.candidate_identity_id == context.candidate_identity_id
            && self.context.candidate_device_id == context.candidate_device_id
            && self.context.invite_id == context.invite_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkflowPhase {
    PendingApproval,
    PendingCommit {
        approval_command_id: MembershipCommandId,
        approval_context: MembershipCommandContext,
        authorization_digest: Sha256Digest,
    },
    Reconciling {
        approval_command_id: MembershipCommandId,
    },
    Committed(MembershipAdmission),
    Rejected(MembershipRejection),
}

impl WorkflowPhase {
    const fn as_public(self) -> MembershipCommandPhase {
        match self {
            Self::PendingApproval => MembershipCommandPhase::PendingApproval,
            Self::PendingCommit { .. } => MembershipCommandPhase::PendingCommit,
            Self::Reconciling { .. } => MembershipCommandPhase::Reconciling,
            Self::Committed(admission) => MembershipCommandPhase::Committed(admission),
            Self::Rejected(rejection) => MembershipCommandPhase::Rejected(rejection),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandKind {
    RequestJoin,
    ApproveJoin,
}

impl CommandKind {
    const fn code(self) -> u64 {
        match self {
            Self::RequestJoin => 1,
            Self::ApproveJoin => 2,
        }
    }
}

/// Stable rejection from the pure membership command reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipCommandError {
    /// The idempotency key was reused for a different canonical command body.
    IdempotencyConflict,
    /// The stable command ID was reused for a different canonical command body.
    CommandIdConflict,
    /// A candidate-authored request named a different actor identity.
    ActorCandidateMismatch,
    /// A join workflow ID was reused for a different command.
    JoinRequestConflict,
    /// The approval references no known candidate join request.
    JoinRequestNotFound,
    /// The approval does not bind the same scope, candidate, and invite as its request.
    JoinRequestMismatch,
    /// Another Owner/Admin command already owns the active commit intent.
    JoinCommitInFlight,
    /// The join workflow reached a terminal state without an existing exact replay.
    JoinWorkflowTerminal,
    /// No command exists under the requested identity.
    CommandNotFound,
    /// The requested command is not an approval ready for a Sequencer result.
    CommandNotReady,
    /// A remote commit reference does not bind the exact command identity/digest/scope.
    CommitReferenceMismatch,
    /// A terminal workflow received a different remote result.
    TerminalResolutionConflict,
    /// Rehydrated internal command/workflow links are inconsistent.
    InvariantViolation,
}

impl fmt::Display for MembershipCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdempotencyConflict => {
                "membership idempotency key conflicts with another command"
            }
            Self::CommandIdConflict => "membership command ID conflicts with another command",
            Self::ActorCandidateMismatch => "membership request actor does not match candidate",
            Self::JoinRequestConflict => "membership join request conflicts with another workflow",
            Self::JoinRequestNotFound => "membership join request was not found",
            Self::JoinRequestMismatch => "membership approval does not match its join request",
            Self::JoinCommitInFlight => "membership join already has an active commit intent",
            Self::JoinWorkflowTerminal => "membership join workflow is terminal",
            Self::CommandNotFound => "membership command was not found",
            Self::CommandNotReady => "membership command is not ready for a Sequencer result",
            Self::CommitReferenceMismatch => "membership commit reference does not match command",
            Self::TerminalResolutionConflict => "membership terminal result conflicts with receipt",
            Self::InvariantViolation => "membership command state is inconsistent",
        })
    }
}

impl Error for MembershipCommandError {}

fn validate_commit_reference(
    reference: MembershipCommitReference,
    scope: GroupScope,
    command_id: MembershipCommandId,
    request_digest: Sha256Digest,
) -> Result<(), MembershipCommandError> {
    if reference.scope == scope
        && reference.command_id == command_id
        && reference.request_digest == request_digest
    {
        Ok(())
    } else {
        Err(MembershipCommandError::CommitReferenceMismatch)
    }
}

fn command_digest(
    kind: CommandKind,
    context: MembershipCommandContext,
    authorization_digest: Option<Sha256Digest>,
) -> Sha256Digest {
    let value = CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Unsigned(kind.code()),
        ),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(context.command_id.request_id().to_string()),
        ),
        (CanonicalValue::Unsigned(3), scope_value(context.scope)),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(context.actor_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(context.actor_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(context.join_request_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(context.candidate_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(context.candidate_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Text(context.invite_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Unsigned(context.fence.policy_revision.get()),
        ),
        (
            CanonicalValue::Unsigned(11),
            CanonicalValue::Bytes(context.fence.sequencer_head.as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(12),
            authorization_digest.map_or(CanonicalValue::Null, |digest| {
                CanonicalValue::Bytes(digest.as_bytes().to_vec())
            }),
        ),
    ]);
    // Every field above has a fixed bounded representation: UUIDv7 strings,
    // self-certifying IDs, 32-byte hashes, and a twelve-entry map. Encoding can
    // therefore never reach the profile limits for a valid typed context.
    let bytes = encode_deterministic_cbor(&value)
        .expect("bounded membership command transcript must be canonical CBOR");
    Sha256Digest::hash_domain(MEMBERSHIP_COMMAND_REQUEST_HASH_DOMAIN, &bytes)
}

fn scope_value(scope: GroupScope) -> CanonicalValue {
    let (kind, identifier) = match scope {
        GroupScope::PrivateConversation(identifier) => (1, identifier.to_string()),
        GroupScope::ControlledPublicChannel(identifier) => (2, identifier.to_string()),
    };
    CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(kind)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identifier),
        ),
    ])
}
