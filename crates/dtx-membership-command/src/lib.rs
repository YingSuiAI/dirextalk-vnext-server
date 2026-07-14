#![forbid(unsafe_code)]

//! Pure, replay-safe membership-command coordination.
//!
//! This crate deliberately models neither MLS cryptography nor database I/O. It
//! retains the command, receipt, and Sequencer-query invariants that a durable
//! repository must preserve around those external boundaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

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

impl MembershipCommandPhase {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Committed(_) | Self::Rejected(_))
    }
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
    /// A linearizable lookup verified that no durable command exists remotely.
    ///
    /// This disposition is valid only for an exact Sequencer query after a
    /// previously uncertain submit. It permits the same command identity and
    /// digest to be re-armed for a new idempotent submit; a transport timeout
    /// must never be mapped to this value.
    Absent,
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

/// Stable storage-neutral command kind for one membership command record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipCommandKind {
    /// Candidate-authored request that opens a workflow.
    RequestJoin,
    /// Owner/Admin command that may create a remote commit intent.
    ApproveJoin,
}

/// Stable idempotency coordinates retained for one membership command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipIdempotencyPersistence {
    /// Scope in which this key is unique.
    pub scope: GroupScope,
    /// Authenticated actor that owns the key namespace.
    pub actor_identity_id: IdentityId,
    /// Retained hash of the caller-provided idempotency key.
    pub idempotency_key_hash: Sha256Digest,
}

/// Storage-neutral durable representation of one membership command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipCommandPersistence {
    /// Stable command identity.
    pub command_id: MembershipCommandId,
    /// Request or approval command class.
    pub kind: MembershipCommandKind,
    /// Immutable canonical request digest.
    pub request_digest: Sha256Digest,
    /// Workflow this command observes, when it is not independently terminal.
    pub workflow_id: Option<JoinRequestId>,
    /// Independent terminal disposition, used for already-member commands.
    pub terminal_phase: Option<MembershipCommandPhase>,
    /// Scope/actor/key lookup used for exact replay.
    pub idempotency: MembershipIdempotencyPersistence,
}

/// Storage-neutral state of one join workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipWorkflowPersistencePhase {
    /// Candidate request is durable but still awaits approval.
    PendingApproval,
    /// Approval intent is durable and has not yet entered an uncertain state.
    PendingCommit {
        /// Command identity assigned to the approving actor.
        approval_command_id: MembershipCommandId,
        /// Actor/fence context that must be sent to the Sequencer.
        approval_context: MembershipCommandContext,
        /// Verified Owner/Admin authorization proof digest.
        authorization_digest: Sha256Digest,
    },
    /// The remote effect may have happened and must be queried before submit.
    Reconciling {
        /// Command identity whose remote result is being reconciled.
        approval_command_id: MembershipCommandId,
        /// Retained so a linearizable remote absence can re-arm the same submit.
        approval_context: MembershipCommandContext,
        /// Retained so a re-armed submit is byte-for-byte the same intent.
        authorization_digest: Sha256Digest,
    },
    /// A verified remote result admitted or already contained the candidate.
    Committed(MembershipAdmission),
    /// A verified remote result explicitly rejected the action.
    Rejected(MembershipRejection),
}

/// Storage-neutral durable representation of one join workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipWorkflowPersistence {
    /// Stable workflow identity, equal to `context.join_request_id()`.
    pub join_request_id: JoinRequestId,
    /// Immutable candidate-authored request coordinates.
    pub context: MembershipCommandContext,
    /// Current state of the workflow.
    pub phase: MembershipWorkflowPersistencePhase,
}

/// Complete durable image of [`MembershipCommandBook`].
///
/// A persistence adapter maps normalized command/workflow rows to this image,
/// then calls [`MembershipCommandBook::try_from_snapshot`] instead of
/// reimplementing replay and state-machine rules in SQL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipCommandBookSnapshot {
    /// Every command record with its exact replay coordinates.
    pub commands: Vec<MembershipCommandPersistence>,
    /// Every active or terminal join workflow.
    pub workflows: Vec<MembershipWorkflowPersistence>,
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

    /// Captures one complete storage-neutral image of replay and workflow state.
    ///
    /// # Errors
    ///
    /// Returns an error if an internal command no longer has exactly one
    /// idempotency mapping. Valid reducer state always has a complete image;
    /// surfacing a mismatch prevents a persistence adapter from silently
    /// discarding replay protection.
    pub fn snapshot(&self) -> Result<MembershipCommandBookSnapshot, MembershipCommandError> {
        let mut idempotency_by_command = BTreeMap::new();
        for (lookup, command_id) in &self.idempotency {
            if idempotency_by_command
                .insert(*command_id, *lookup)
                .is_some()
            {
                return Err(MembershipCommandError::InvariantViolation);
            }
        }

        let mut commands = Vec::with_capacity(self.commands.len());
        for (command_id, command) in &self.commands {
            let lookup = idempotency_by_command
                .remove(command_id)
                .ok_or(MembershipCommandError::InvariantViolation)?;
            commands.push(MembershipCommandPersistence {
                command_id: *command_id,
                kind: command.kind.persistence_kind(),
                request_digest: command.request_digest,
                workflow_id: command.workflow_id,
                terminal_phase: command.terminal_phase,
                idempotency: lookup.persistence(),
            });
        }
        if !idempotency_by_command.is_empty() {
            return Err(MembershipCommandError::InvariantViolation);
        }

        let workflows = self
            .workflows
            .iter()
            .map(
                |(join_request_id, workflow)| MembershipWorkflowPersistence {
                    join_request_id: *join_request_id,
                    context: workflow.context,
                    phase: workflow.phase.persistence_phase(),
                },
            )
            .collect();
        Ok(MembershipCommandBookSnapshot {
            commands,
            workflows,
        })
    }

    /// Rehydrates command replay state and join workflows from durable rows.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate IDs, malformed terminal shapes, missing
    /// idempotency mappings, or a command/workflow graph that cannot be
    /// produced by this reducer. Invalid durable data never becomes a source
    /// of authorization or reconciliation decisions.
    pub fn try_from_snapshot(
        snapshot: MembershipCommandBookSnapshot,
    ) -> Result<Self, MembershipCommandError> {
        let mut workflows = BTreeMap::new();
        for persisted in snapshot.workflows {
            if persisted.join_request_id != persisted.context.join_request_id()
                || persisted.context.actor_identity_id()
                    != persisted.context.candidate_identity_id()
                || workflows
                    .insert(
                        persisted.join_request_id,
                        JoinWorkflow {
                            context: persisted.context,
                            phase: WorkflowPhase::from_persistence(&persisted.phase),
                        },
                    )
                    .is_some()
            {
                return Err(MembershipCommandError::InvariantViolation);
            }
        }

        let mut commands = BTreeMap::new();
        let mut idempotency = BTreeMap::new();
        for persisted in snapshot.commands {
            if persisted.idempotency.scope != scope_for_command(&persisted, &workflows)? {
                return Err(MembershipCommandError::InvariantViolation);
            }
            let lookup = IdempotencyLookup::from_persistence(persisted.idempotency);
            if idempotency.insert(lookup, persisted.command_id).is_some()
                || commands
                    .insert(
                        persisted.command_id,
                        StoredCommand {
                            kind: CommandKind::from_persistence(persisted.kind),
                            request_digest: persisted.request_digest,
                            workflow_id: persisted.workflow_id,
                            terminal_phase: persisted.terminal_phase,
                        },
                    )
                    .is_some()
            {
                return Err(MembershipCommandError::InvariantViolation);
            }
        }

        let book = Self {
            commands,
            idempotency,
            workflows,
        };
        book.validate_snapshot_graph()?;
        Ok(book)
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
                ..
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
                approval_context,
                authorization_digest,
            }
            | WorkflowPhase::Reconciling {
                approval_command_id,
                approval_context,
                authorization_digest,
            } if approval_command_id == command_id => match resolution {
                SequencerResolution::Unknown => WorkflowPhase::Reconciling {
                    approval_command_id: command_id,
                    approval_context,
                    authorization_digest,
                },
                SequencerResolution::Absent
                    if matches!(workflow.phase, WorkflowPhase::Reconciling { .. }) =>
                {
                    WorkflowPhase::PendingCommit {
                        approval_command_id: command_id,
                        approval_context,
                        authorization_digest,
                    }
                }
                SequencerResolution::Absent => return Err(MembershipCommandError::CommandNotReady),
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

    /// Persists a definitive local policy rejection before any Sequencer effect.
    ///
    /// This is valid only while a request awaits approval or while the exact
    /// approval command has a locally durable, never-dispatched submit intent.
    /// Once an intent is reconciling, callers must use the remote query result
    /// instead of converting uncertainty into a local rejection.
    ///
    /// # Errors
    ///
    /// Returns an error if the command/workflow is unknown or no longer in a
    /// state that can be rejected without contradicting an external effect.
    pub fn reject_locally(
        &mut self,
        command_id: MembershipCommandId,
        rejection: MembershipRejection,
    ) -> Result<MembershipReceipt, MembershipCommandError> {
        let command = self
            .commands
            .get(&command_id)
            .copied()
            .ok_or(MembershipCommandError::CommandNotFound)?;
        let workflow_id = command
            .workflow_id
            .ok_or(MembershipCommandError::CommandNotReady)?;
        let workflow = self
            .workflows
            .get(&workflow_id)
            .copied()
            .ok_or(MembershipCommandError::InvariantViolation)?;
        let locally_rejectable = match (command.kind, workflow.phase) {
            (CommandKind::RequestJoin, WorkflowPhase::PendingApproval) => {
                self.workflows.remove(&workflow_id);
                self.commands.insert(
                    command_id,
                    StoredCommand::terminal(
                        CommandKind::RequestJoin,
                        command.request_digest,
                        MembershipCommandPhase::Rejected(rejection),
                    ),
                );
                return self.receipt_for(command_id);
            }
            (
                CommandKind::ApproveJoin,
                WorkflowPhase::PendingCommit {
                    approval_command_id,
                    ..
                },
            ) => approval_command_id == command_id,
            _ => false,
        };
        if !locally_rejectable {
            return Err(MembershipCommandError::CommandNotReady);
        }
        self.workflows.insert(
            workflow_id,
            JoinWorkflow {
                phase: WorkflowPhase::Rejected(rejection),
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

    fn validate_snapshot_graph(&self) -> Result<(), MembershipCommandError> {
        let mut mapped_commands = BTreeSet::new();
        for (lookup, command_id) in &self.idempotency {
            let command = self
                .commands
                .get(command_id)
                .ok_or(MembershipCommandError::InvariantViolation)?;
            if !mapped_commands.insert(*command_id) {
                return Err(MembershipCommandError::InvariantViolation);
            }
            if let Some(scope) = scope_for_stored_command(command, &self.workflows)?
                && lookup.scope != scope
            {
                return Err(MembershipCommandError::InvariantViolation);
            }
        }
        if mapped_commands.len() != self.commands.len() {
            return Err(MembershipCommandError::InvariantViolation);
        }

        for (command_id, command) in &self.commands {
            match (command.workflow_id, command.terminal_phase) {
                (Some(workflow_id), None) => {
                    let workflow = self
                        .workflows
                        .get(&workflow_id)
                        .ok_or(MembershipCommandError::InvariantViolation)?;
                    validate_workflow_command(*command_id, command, workflow)?;
                }
                (None, Some(phase)) if phase.is_terminal() => {
                    validate_terminal_command(command, phase)?;
                }
                _ => return Err(MembershipCommandError::InvariantViolation),
            }
        }

        for (workflow_id, workflow) in &self.workflows {
            if workflow.context.join_request_id != *workflow_id
                || workflow.context.actor_identity_id != workflow.context.candidate_identity_id
            {
                return Err(MembershipCommandError::InvariantViolation);
            }
            let has_request = self.commands.iter().any(|(command_id, command)| {
                command.kind == CommandKind::RequestJoin
                    && command.workflow_id == Some(*workflow_id)
                    && command.request_digest == workflow.context.join_request_digest()
                    && self.idempotency.iter().any(|(lookup, mapped)| {
                        *mapped == *command_id
                            && *lookup == IdempotencyLookup::new(workflow.context)
                    })
            });
            if !has_request {
                return Err(MembershipCommandError::InvariantViolation);
            }
            workflow
                .phase
                .validate(*workflow_id, workflow.context, self)?;
        }
        Ok(())
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

    const fn persistence(self) -> MembershipIdempotencyPersistence {
        MembershipIdempotencyPersistence {
            scope: self.scope,
            actor_identity_id: self.actor_identity_id,
            idempotency_key_hash: self.idempotency_key_hash,
        }
    }

    const fn from_persistence(value: MembershipIdempotencyPersistence) -> Self {
        Self {
            scope: value.scope,
            actor_identity_id: value.actor_identity_id,
            idempotency_key_hash: value.idempotency_key_hash,
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
        workflow_context_matches(self.context, context)
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
        approval_context: MembershipCommandContext,
        authorization_digest: Sha256Digest,
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

    const fn persistence_phase(self) -> MembershipWorkflowPersistencePhase {
        match self {
            Self::PendingApproval => MembershipWorkflowPersistencePhase::PendingApproval,
            Self::PendingCommit {
                approval_command_id,
                approval_context,
                authorization_digest,
            } => MembershipWorkflowPersistencePhase::PendingCommit {
                approval_command_id,
                approval_context,
                authorization_digest,
            },
            Self::Reconciling {
                approval_command_id,
                approval_context,
                authorization_digest,
            } => MembershipWorkflowPersistencePhase::Reconciling {
                approval_command_id,
                approval_context,
                authorization_digest,
            },
            Self::Committed(admission) => MembershipWorkflowPersistencePhase::Committed(admission),
            Self::Rejected(rejection) => MembershipWorkflowPersistencePhase::Rejected(rejection),
        }
    }

    const fn from_persistence(phase: &MembershipWorkflowPersistencePhase) -> Self {
        match *phase {
            MembershipWorkflowPersistencePhase::PendingApproval => Self::PendingApproval,
            MembershipWorkflowPersistencePhase::PendingCommit {
                approval_command_id,
                approval_context,
                authorization_digest,
            } => Self::PendingCommit {
                approval_command_id,
                approval_context,
                authorization_digest,
            },
            MembershipWorkflowPersistencePhase::Reconciling {
                approval_command_id,
                approval_context,
                authorization_digest,
            } => Self::Reconciling {
                approval_command_id,
                approval_context,
                authorization_digest,
            },
            MembershipWorkflowPersistencePhase::Committed(admission) => Self::Committed(admission),
            MembershipWorkflowPersistencePhase::Rejected(rejection) => Self::Rejected(rejection),
        }
    }

    fn validate(
        self,
        workflow_id: JoinRequestId,
        context: MembershipCommandContext,
        book: &MembershipCommandBook,
    ) -> Result<(), MembershipCommandError> {
        match self {
            Self::PendingApproval => Ok(()),
            Self::PendingCommit {
                approval_command_id,
                approval_context,
                authorization_digest,
            }
            | Self::Reconciling {
                approval_command_id,
                approval_context,
                authorization_digest,
            } => {
                if !workflow_context_matches(context, approval_context) {
                    return Err(MembershipCommandError::InvariantViolation);
                }
                let command = book
                    .commands
                    .get(&approval_command_id)
                    .ok_or(MembershipCommandError::InvariantViolation)?;
                if command.kind != CommandKind::ApproveJoin
                    || command.workflow_id != Some(workflow_id)
                    || command.request_digest
                        != ApproveJoinCommand::new(approval_context, authorization_digest)
                            .request_digest()
                {
                    return Err(MembershipCommandError::InvariantViolation);
                }
                Ok(())
            }
            Self::Committed(MembershipAdmission::Applied(reference)) => {
                let Some((approval_command_id, approval)) =
                    single_workflow_approval(book, workflow_id)?
                else {
                    return Err(MembershipCommandError::InvariantViolation);
                };
                if reference.scope() != context.scope
                    || approval_command_id != reference.command_id()
                    || approval.request_digest != reference.request_digest()
                {
                    return Err(MembershipCommandError::InvariantViolation);
                }
                Ok(())
            }
            Self::Committed(MembershipAdmission::AlreadyMember(reference)) => {
                if reference.scope() != context.scope {
                    return Err(MembershipCommandError::InvariantViolation);
                }
                single_workflow_approval(book, workflow_id)?;
                let has_terminal_origin = book.commands.values().any(|command| {
                    command.kind == CommandKind::ApproveJoin
                        && command.workflow_id.is_none()
                        && command.terminal_phase
                            == Some(MembershipCommandPhase::Committed(
                                MembershipAdmission::AlreadyMember(reference),
                            ))
                });
                if has_terminal_origin {
                    Ok(())
                } else {
                    Err(MembershipCommandError::InvariantViolation)
                }
            }
            Self::Rejected(_) => {
                if single_workflow_approval(book, workflow_id)?.is_some() {
                    Ok(())
                } else {
                    Err(MembershipCommandError::InvariantViolation)
                }
            }
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

    const fn persistence_kind(self) -> MembershipCommandKind {
        match self {
            Self::RequestJoin => MembershipCommandKind::RequestJoin,
            Self::ApproveJoin => MembershipCommandKind::ApproveJoin,
        }
    }

    const fn from_persistence(kind: MembershipCommandKind) -> Self {
        match kind {
            MembershipCommandKind::RequestJoin => Self::RequestJoin,
            MembershipCommandKind::ApproveJoin => Self::ApproveJoin,
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

fn scope_for_command(
    command: &MembershipCommandPersistence,
    workflows: &BTreeMap<JoinRequestId, JoinWorkflow>,
) -> Result<GroupScope, MembershipCommandError> {
    command
        .workflow_id
        .map_or(Ok(command.idempotency.scope), |workflow_id| {
            workflows
                .get(&workflow_id)
                .map(|workflow| workflow.context.scope)
                .ok_or(MembershipCommandError::InvariantViolation)
        })
}

fn scope_for_stored_command(
    command: &StoredCommand,
    workflows: &BTreeMap<JoinRequestId, JoinWorkflow>,
) -> Result<Option<GroupScope>, MembershipCommandError> {
    match (command.workflow_id, command.terminal_phase) {
        (Some(workflow_id), None) => workflows
            .get(&workflow_id)
            .map(|workflow| Some(workflow.context.scope))
            .ok_or(MembershipCommandError::InvariantViolation),
        (None, Some(MembershipCommandPhase::Committed(admission))) => {
            Ok(Some(admission.commit_reference().scope()))
        }
        (None, Some(MembershipCommandPhase::Rejected(_)) | None) => Ok(None),
        _ => Err(MembershipCommandError::InvariantViolation),
    }
}

fn validate_terminal_command(
    command: &StoredCommand,
    phase: MembershipCommandPhase,
) -> Result<(), MembershipCommandError> {
    match (command.kind, phase) {
        (
            CommandKind::RequestJoin,
            MembershipCommandPhase::Rejected(_)
            | MembershipCommandPhase::Committed(MembershipAdmission::AlreadyMember(_)),
        )
        | (
            CommandKind::ApproveJoin,
            MembershipCommandPhase::Committed(MembershipAdmission::AlreadyMember(_)),
        ) => Ok(()),
        _ => Err(MembershipCommandError::InvariantViolation),
    }
}

fn validate_workflow_command(
    command_id: MembershipCommandId,
    command: &StoredCommand,
    workflow: &JoinWorkflow,
) -> Result<(), MembershipCommandError> {
    match command.kind {
        CommandKind::RequestJoin => {
            if command.request_digest == workflow.context.join_request_digest() {
                Ok(())
            } else {
                Err(MembershipCommandError::InvariantViolation)
            }
        }
        CommandKind::ApproveJoin => match workflow.phase {
            WorkflowPhase::PendingCommit {
                approval_command_id,
                approval_context,
                authorization_digest,
            }
            | WorkflowPhase::Reconciling {
                approval_command_id,
                approval_context,
                authorization_digest,
            } if approval_command_id == command_id
                && workflow_context_matches(workflow.context, approval_context)
                && command.request_digest
                    == ApproveJoinCommand::new(approval_context, authorization_digest)
                        .request_digest() =>
            {
                Ok(())
            }
            WorkflowPhase::Committed(_) | WorkflowPhase::Rejected(_) => Ok(()),
            _ => Err(MembershipCommandError::InvariantViolation),
        },
    }
}

fn single_workflow_approval(
    book: &MembershipCommandBook,
    workflow_id: JoinRequestId,
) -> Result<Option<(MembershipCommandId, &StoredCommand)>, MembershipCommandError> {
    let mut approvals = book.commands.iter().filter_map(|(command_id, command)| {
        (command.kind == CommandKind::ApproveJoin && command.workflow_id == Some(workflow_id))
            .then_some((*command_id, command))
    });
    let approval = approvals.next();
    if approvals.next().is_some() {
        Err(MembershipCommandError::InvariantViolation)
    } else {
        Ok(approval)
    }
}

fn workflow_context_matches(
    request: MembershipCommandContext,
    candidate: MembershipCommandContext,
) -> bool {
    request.scope == candidate.scope
        && request.join_request_id == candidate.join_request_id
        && request.candidate_identity_id == candidate.candidate_identity_id
        && request.candidate_device_id == candidate.candidate_device_id
        && request.invite_id == candidate.invite_id
}

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
