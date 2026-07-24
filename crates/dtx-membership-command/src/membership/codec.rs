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
                && workflow_context_matches(&workflow.context, &approval_context)
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
    request: &MembershipCommandContext,
    candidate: &MembershipCommandContext,
) -> bool {
    request.scope == candidate.scope
        && request.join_request_id == candidate.join_request_id
        && request.candidate_identity_id == candidate.candidate_identity_id
        && request.candidate_device_id == candidate.candidate_device_id
        && request.invite_id == candidate.invite_id
        && request.candidate_key_package_digest == candidate.candidate_key_package_digest
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
    context: &MembershipCommandContext,
    authorization_digest: Option<Sha256Digest>,
) -> Sha256Digest {
    let mut fields = vec![
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
    ];
    let domain = if let Some(candidate_key_package_digest) = context.candidate_key_package_digest {
        fields.push((
            CanonicalValue::Unsigned(13),
            CanonicalValue::Bytes(candidate_key_package_digest.as_bytes().to_vec()),
        ));
        MEMBERSHIP_COMMAND_REQUEST_V2_HASH_DOMAIN
    } else {
        MEMBERSHIP_COMMAND_REQUEST_HASH_DOMAIN
    };
    let value = CanonicalValue::Map(fields);
    // Every field above has a fixed bounded representation: UUIDv7 strings,
    // self-certifying IDs, 32-byte hashes, and a bounded versioned map. Encoding can
    // therefore never reach the profile limits for a valid typed context.
    let bytes = encode_deterministic_cbor(&value)
        .expect("bounded membership command transcript must be canonical CBOR");
    Sha256Digest::hash_domain(domain, &bytes)
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
