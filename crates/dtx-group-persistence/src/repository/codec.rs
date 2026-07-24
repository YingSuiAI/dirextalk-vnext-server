struct TerminalColumns {
    phase: Option<&'static str>,
    admission: Option<&'static str>,
    commit_scope_kind: Option<&'static str>,
    commit_scope_id: Option<String>,
    commit_command_id: Option<Uuid>,
    commit_request_digest: Option<Vec<u8>>,
    committed_digest: Option<Vec<u8>>,
    rejection: Option<&'static str>,
}

fn terminal_columns(
    phase: Option<MembershipCommandPhase>,
) -> Result<TerminalColumns, GroupPersistenceError> {
    match phase {
        None => Ok(TerminalColumns {
            phase: None,
            admission: None,
            commit_scope_kind: None,
            commit_scope_id: None,
            commit_command_id: None,
            commit_request_digest: None,
            committed_digest: None,
            rejection: None,
        }),
        Some(MembershipCommandPhase::Committed(admission)) => {
            let reference = admission.commit_reference();
            let (commit_scope_kind, commit_scope_id) = scope_columns(reference.scope());
            Ok(TerminalColumns {
                phase: Some(COMMITTED_STATE),
                admission: Some(admission_code(admission)),
                commit_scope_kind: Some(commit_scope_kind),
                commit_scope_id: Some(commit_scope_id),
                commit_command_id: Some(uuid_from(reference.command_id().request_id())),
                commit_request_digest: Some(reference.request_digest().as_bytes().to_vec()),
                committed_digest: Some(reference.committed_digest().as_bytes().to_vec()),
                rejection: None,
            })
        }
        Some(MembershipCommandPhase::Rejected(rejection)) => Ok(TerminalColumns {
            phase: Some(REJECTED_STATE),
            admission: None,
            commit_scope_kind: None,
            commit_scope_id: None,
            commit_command_id: None,
            commit_request_digest: None,
            committed_digest: None,
            rejection: Some(rejection_code(rejection)),
        }),
        Some(
            MembershipCommandPhase::PendingApproval
            | MembershipCommandPhase::PendingCommit
            | MembershipCommandPhase::Reconciling,
        ) => Err(GroupPersistenceError::CorruptData(
            "non-terminal command phase",
        )),
    }
}

struct WorkflowColumns {
    state: &'static str,
    approval_command_id: Option<Uuid>,
    approval_actor_identity_id: Option<String>,
    approval_actor_device_id: Option<Uuid>,
    approval_idempotency_key_hash: Option<Vec<u8>>,
    approval_policy_revision: Option<i64>,
    approval_sequencer_head: Option<Vec<u8>>,
    authorization_digest: Option<Vec<u8>>,
    admission: Option<&'static str>,
    commit_scope_kind: Option<&'static str>,
    commit_scope_id: Option<String>,
    commit_command_id: Option<Uuid>,
    commit_request_digest: Option<Vec<u8>>,
    committed_digest: Option<Vec<u8>>,
    rejection: Option<&'static str>,
}

fn workflow_columns(
    phase: &MembershipWorkflowPersistencePhase,
) -> Result<WorkflowColumns, GroupPersistenceError> {
    let empty = || WorkflowColumns {
        state: PENDING_APPROVAL_STATE,
        approval_command_id: None,
        approval_actor_identity_id: None,
        approval_actor_device_id: None,
        approval_idempotency_key_hash: None,
        approval_policy_revision: None,
        approval_sequencer_head: None,
        authorization_digest: None,
        admission: None,
        commit_scope_kind: None,
        commit_scope_id: None,
        commit_command_id: None,
        commit_request_digest: None,
        committed_digest: None,
        rejection: None,
    };
    match *phase {
        MembershipWorkflowPersistencePhase::PendingApproval => Ok(empty()),
        MembershipWorkflowPersistencePhase::PendingCommit {
            approval_command_id,
            approval_context,
            authorization_digest,
        }
        | MembershipWorkflowPersistencePhase::Reconciling {
            approval_command_id,
            approval_context,
            authorization_digest,
        } => {
            let state = match *phase {
                MembershipWorkflowPersistencePhase::PendingCommit { .. } => PENDING_COMMIT_STATE,
                MembershipWorkflowPersistencePhase::Reconciling { .. } => RECONCILING_STATE,
                MembershipWorkflowPersistencePhase::PendingApproval
                | MembershipWorkflowPersistencePhase::Committed(_)
                | MembershipWorkflowPersistencePhase::Rejected(_) => {
                    return Err(GroupPersistenceError::CorruptData(
                        "workflow state encoding",
                    ));
                }
            };
            Ok(WorkflowColumns {
                state,
                approval_command_id: Some(uuid_from(approval_command_id.request_id())),
                approval_actor_identity_id: Some(approval_context.actor_identity_id().to_string()),
                approval_actor_device_id: Some(uuid_from(approval_context.actor_device_id())),
                approval_idempotency_key_hash: Some(
                    approval_context.idempotency_key_hash().as_bytes().to_vec(),
                ),
                approval_policy_revision: Some(revision_i64(
                    approval_context.fence().policy_revision(),
                )?),
                approval_sequencer_head: Some(
                    approval_context
                        .fence()
                        .sequencer_head()
                        .as_bytes()
                        .to_vec(),
                ),
                authorization_digest: Some(authorization_digest.as_bytes().to_vec()),
                ..empty()
            })
        }
        MembershipWorkflowPersistencePhase::Committed(admission) => {
            let reference = admission.commit_reference();
            let (commit_scope_kind, commit_scope_id) = scope_columns(reference.scope());
            Ok(WorkflowColumns {
                state: COMMITTED_STATE,
                admission: Some(admission_code(admission)),
                commit_scope_kind: Some(commit_scope_kind),
                commit_scope_id: Some(commit_scope_id),
                commit_command_id: Some(uuid_from(reference.command_id().request_id())),
                commit_request_digest: Some(reference.request_digest().as_bytes().to_vec()),
                committed_digest: Some(reference.committed_digest().as_bytes().to_vec()),
                ..empty()
            })
        }
        MembershipWorkflowPersistencePhase::Rejected(rejection) => Ok(WorkflowColumns {
            state: REJECTED_STATE,
            rejection: Some(rejection_code(rejection)),
            ..empty()
        }),
    }
}

#[allow(clippy::needless_pass_by_value)] // SQLx yields each row by value from the result iterator.
fn outbox_from_row(row: sqlx::postgres::PgRow) -> Result<OutboxRow, GroupPersistenceError> {
    Ok(OutboxRow {
        scope_kind: row.try_get("scope_kind")?,
        scope_id: row.try_get("scope_id")?,
        command_id: row.try_get("command_id")?,
        request_id: join_request_id(row.try_get("request_id")?)?,
        action: row.try_get("action")?,
        leased_action: row.try_get("leased_action")?,
        lease_expires_at_ms: required_i64(
            row.try_get("lease_expires_at_ms")?,
            "outbox lease expiry",
        )?,
    })
}

fn action_code(action: &SequencerAction) -> &'static str {
    match action {
        SequencerAction::Submit(_) => SUBMIT_ACTION,
        SequencerAction::Query(_) => QUERY_ACTION,
    }
}

fn local_policy_rejection(error: GroupPolicyError) -> Option<MembershipRejection> {
    match error {
        GroupPolicyError::RevisionConflict { .. } => Some(MembershipRejection::StaleFence),
        GroupPolicyError::Unauthorized
        | GroupPolicyError::InviteRevoked
        | GroupPolicyError::InviteExpired
        | GroupPolicyError::InviteIssuerNoLongerAuthorized => {
            Some(MembershipRejection::PolicyDenied)
        }
        GroupPolicyError::CounterExhausted | GroupPolicyError::ReservationInvariantViolation => {
            None
        }
        GroupPolicyError::OwnerCannotBeAdmin
        | GroupPolicyError::OwnerCannotBeRemoved
        | GroupPolicyError::AlreadyAdmin
        | GroupPolicyError::NotAdmin
        | GroupPolicyError::AdminLimitReached
        | GroupPolicyError::InviteAlreadyExists
        | GroupPolicyError::InvalidInviteUseLimit
        | GroupPolicyError::InvalidInviteExpiry
        | GroupPolicyError::InviteNotFound
        | GroupPolicyError::InviteAlreadyRevoked
        | GroupPolicyError::AlreadyMember
        | GroupPolicyError::MemberNotFound
        | GroupPolicyError::JoinRequestAlreadyPending
        | GroupPolicyError::CandidateJoinInFlight
        | GroupPolicyError::PendingJoinNotFound
        | GroupPolicyError::AlreadyApproved
        | GroupPolicyError::JoinAlreadyReserved
        | GroupPolicyError::ReservedJoinNotFound
        | GroupPolicyError::InviteTargetMismatch
        | GroupPolicyError::InviteUseLimitReached => Some(MembershipRejection::AdmissionDenied),
    }
}

fn command_kind_code(kind: MembershipCommandKind) -> &'static str {
    match kind {
        MembershipCommandKind::RequestJoin => REQUEST_JOIN_KIND,
        MembershipCommandKind::ApproveJoin => APPROVE_JOIN_KIND,
    }
}

fn command_kind(value: &str) -> Result<MembershipCommandKind, GroupPersistenceError> {
    match value {
        REQUEST_JOIN_KIND => Ok(MembershipCommandKind::RequestJoin),
        APPROVE_JOIN_KIND => Ok(MembershipCommandKind::ApproveJoin),
        _ => Err(GroupPersistenceError::CorruptData(
            "membership command kind",
        )),
    }
}

fn admission_code(admission: MembershipAdmission) -> &'static str {
    match admission {
        MembershipAdmission::Applied(_) => APPLIED_ADMISSION,
        MembershipAdmission::AlreadyMember(_) => ALREADY_MEMBER_ADMISSION,
    }
}

fn rejection_code(rejection: MembershipRejection) -> &'static str {
    match rejection {
        MembershipRejection::PolicyDenied => POLICY_DENIED_REJECTION,
        MembershipRejection::StaleFence => STALE_FENCE_REJECTION,
        MembershipRejection::AdmissionDenied => ADMISSION_DENIED_REJECTION,
    }
}

fn rejection(value: &str) -> Result<MembershipRejection, GroupPersistenceError> {
    match value {
        POLICY_DENIED_REJECTION => Ok(MembershipRejection::PolicyDenied),
        STALE_FENCE_REJECTION => Ok(MembershipRejection::StaleFence),
        ADMISSION_DENIED_REJECTION => Ok(MembershipRejection::AdmissionDenied),
        _ => Err(GroupPersistenceError::CorruptData("membership rejection")),
    }
}

fn authority_to_columns(
    authority: GroupAuthorityPersistence,
) -> Result<(&'static str, Option<i64>), GroupPersistenceError> {
    match authority {
        GroupAuthorityPersistence::Owner => Ok((OWNER_AUTHORITY, None)),
        GroupAuthorityPersistence::Admin {
            authorization_generation,
        } => Ok((
            ADMIN_AUTHORITY,
            Some(revision_i64(authorization_generation)?),
        )),
    }
}

#[allow(clippy::needless_pass_by_value)] // The row decoder owns the string and validates it immediately.
fn authority(
    authority: String,
    generation: Option<i64>,
) -> Result<GroupAuthorityPersistence, GroupPersistenceError> {
    match (authority.as_str(), generation) {
        (OWNER_AUTHORITY, None) => Ok(GroupAuthorityPersistence::Owner),
        (ADMIN_AUTHORITY, Some(generation)) => Ok(GroupAuthorityPersistence::Admin {
            authorization_generation: revision(generation)?,
        }),
        _ => Err(GroupPersistenceError::CorruptData("group authority term")),
    }
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn terminal_phase_from_fields(
    phase: Option<String>,
    admission: Option<String>,
    commit_scope_kind: Option<String>,
    commit_scope_id: Option<String>,
    commit_command_id: Option<Uuid>,
    commit_request_digest: Option<Vec<u8>>,
    committed_digest: Option<Vec<u8>>,
    rejection_value: Option<String>,
) -> Result<Option<MembershipCommandPhase>, GroupPersistenceError> {
    match phase.as_deref() {
        None => {
            if admission.is_some()
                || commit_scope_kind.is_some()
                || commit_scope_id.is_some()
                || commit_command_id.is_some()
                || commit_request_digest.is_some()
                || committed_digest.is_some()
                || rejection_value.is_some()
            {
                return Err(GroupPersistenceError::CorruptData(
                    "command terminal columns",
                ));
            }
            Ok(None)
        }
        Some(COMMITTED_STATE) => Ok(Some(MembershipCommandPhase::Committed(
            admission_from_fields(
                required_string(admission, "command terminal admission")?,
                required_string(commit_scope_kind, "command terminal scope kind")?,
                required_string(commit_scope_id, "command terminal scope id")?,
                required_uuid(commit_command_id, "command terminal commit ID")?,
                required_bytes(commit_request_digest, "command terminal request digest")?,
                required_bytes(committed_digest, "command terminal committed digest")?,
            )?,
        ))),
        Some(REJECTED_STATE) => {
            let rejection_value = required_string(rejection_value, "command terminal rejection")?;
            Ok(Some(MembershipCommandPhase::Rejected(rejection(
                &rejection_value,
            )?)))
        }
        _ => Err(GroupPersistenceError::CorruptData("command terminal phase")),
    }
}

#[allow(clippy::needless_pass_by_value)] // The row decoder owns each terminal column and validates it immediately.
fn admission_from_fields(
    admission: String,
    scope_kind: String,
    scope_id: String,
    command_id: Uuid,
    request_digest: Vec<u8>,
    committed_digest: Vec<u8>,
) -> Result<MembershipAdmission, GroupPersistenceError> {
    let reference = MembershipCommitReference::new(
        scope_from_storage(&scope_kind, &scope_id)?,
        membership_command_id(command_id)?,
        digest(request_digest, "membership commit request digest")?,
        digest(committed_digest, "membership committed digest")?,
    );
    match admission.as_str() {
        APPLIED_ADMISSION => Ok(MembershipAdmission::Applied(reference)),
        ALREADY_MEMBER_ADMISSION => Ok(MembershipAdmission::AlreadyMember(reference)),
        _ => Err(GroupPersistenceError::CorruptData("membership admission")),
    }
}

fn scope_from_storage(kind: &str, id: &str) -> Result<GroupScope, GroupPersistenceError> {
    match kind {
        PRIVATE_CONVERSATION_SCOPE => ConversationId::from_str(id)
            .map(GroupScope::PrivateConversation)
            .map_err(|_| GroupPersistenceError::CorruptData("private group scope")),
        CONTROLLED_PUBLIC_CHANNEL_SCOPE => ChannelId::from_str(id)
            .map(GroupScope::ControlledPublicChannel)
            .map_err(|_| GroupPersistenceError::CorruptData("public group scope")),
        _ => Err(GroupPersistenceError::CorruptData("group scope kind")),
    }
}

#[allow(clippy::needless_pass_by_value)] // The row decoder owns the string and validates it immediately.
fn identity_id(value: String) -> Result<IdentityId, GroupPersistenceError> {
    IdentityId::from_str(&value).map_err(|_| GroupPersistenceError::CorruptData("identity ID"))
}

fn device_id(value: Uuid) -> Result<DeviceId, GroupPersistenceError> {
    DeviceId::try_from(value).map_err(|_| GroupPersistenceError::CorruptData("device ID"))
}

fn invite_capability_id(value: Uuid) -> Result<InviteCapabilityId, GroupPersistenceError> {
    InviteCapabilityId::try_from(value)
        .map_err(|_| GroupPersistenceError::CorruptData("invite capability ID"))
}

fn join_request_id(value: Uuid) -> Result<JoinRequestId, GroupPersistenceError> {
    JoinRequestId::try_from(value)
        .map_err(|_| GroupPersistenceError::CorruptData("join request ID"))
}

fn membership_command_id(value: Uuid) -> Result<MembershipCommandId, GroupPersistenceError> {
    RequestId::try_from(value)
        .map(MembershipCommandId::new)
        .map_err(|_| GroupPersistenceError::CorruptData("membership command ID"))
}

fn uuid_from<T>(value: T) -> Uuid
where
    Uuid: From<T>,
{
    Uuid::from(value)
}

fn revision(value: i64) -> Result<Revision, GroupPersistenceError> {
    let value =
        u64::try_from(value).map_err(|_| GroupPersistenceError::CorruptData("policy revision"))?;
    Revision::new(value).map_err(|_| GroupPersistenceError::CorruptData("policy revision"))
}

fn revision_i64(value: Revision) -> Result<i64, GroupPersistenceError> {
    i64::try_from(value.get()).map_err(|_| GroupPersistenceError::CorruptData("policy revision"))
}

fn digest(value: Vec<u8>, label: &'static str) -> Result<Sha256Digest, GroupPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| GroupPersistenceError::CorruptData(label))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn required_string(
    value: Option<String>,
    label: &'static str,
) -> Result<String, GroupPersistenceError> {
    value.ok_or(GroupPersistenceError::CorruptData(label))
}

fn required_uuid(value: Option<Uuid>, label: &'static str) -> Result<Uuid, GroupPersistenceError> {
    value.ok_or(GroupPersistenceError::CorruptData(label))
}

fn required_i64(value: Option<i64>, label: &'static str) -> Result<i64, GroupPersistenceError> {
    value.ok_or(GroupPersistenceError::CorruptData(label))
}

fn required_bytes(
    value: Option<Vec<u8>>,
    label: &'static str,
) -> Result<Vec<u8>, GroupPersistenceError> {
    value.ok_or(GroupPersistenceError::CorruptData(label))
}
