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
/// Domain separator for the V2 transcript that binds the candidate `KeyPackage`.
pub const MEMBERSHIP_COMMAND_REQUEST_V2_HASH_DOMAIN: &[u8] =
    b"dirextalk.membership-command-request.v2\0";

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
    candidate_key_package_digest: Option<Sha256Digest>,
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
            candidate_key_package_digest: None,
        }
    }

    /// Constructs the V2 membership context and binds one exact candidate
    /// `KeyPackage` digest through join, approval, and Sequencer admission.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new_v2(
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
        candidate_key_package_digest: Sha256Digest,
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
            candidate_key_package_digest: Some(candidate_key_package_digest),
        }
    }

    /// Computes the canonical digest for the candidate-authored join command.
    #[must_use]
    pub fn join_request_digest(&self) -> Sha256Digest {
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

    /// Returns the V2 candidate `KeyPackage` binding. `None` identifies a
    /// frozen V17/V18 workflow that cannot authorize the V30 production path.
    #[must_use]
    pub const fn candidate_key_package_digest(self) -> Option<Sha256Digest> {
        self.candidate_key_package_digest
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
                &context,
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
