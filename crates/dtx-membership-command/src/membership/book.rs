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
            IdempotencyLookup::new(&context),
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
                .insert(IdempotencyLookup::new(&context), context.command_id);
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
            .insert(IdempotencyLookup::new(&context), context.command_id);
        self.workflows
            .insert(context.join_request_id, JoinWorkflow::pending(&context));
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
            IdempotencyLookup::new(&context),
        )? {
            return Ok(receipt);
        }
        let workflow = self
            .workflows
            .get(&context.join_request_id)
            .copied()
            .ok_or(MembershipCommandError::JoinRequestNotFound)?;
        if !workflow.matches(&context) {
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
                .insert(IdempotencyLookup::new(&context), context.command_id);
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
                    .insert(IdempotencyLookup::new(&context), context.command_id);
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
                            && *lookup == IdempotencyLookup::new(&workflow.context)
                    })
            });
            if !has_request {
                return Err(MembershipCommandError::InvariantViolation);
            }
            workflow
                .phase
                .validate(*workflow_id, &workflow.context, self)?;
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
    const fn new(context: &MembershipCommandContext) -> Self {
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
    const fn pending(context: &MembershipCommandContext) -> Self {
        Self {
            context: *context,
            phase: WorkflowPhase::PendingApproval,
        }
    }

    fn matches(self, context: &MembershipCommandContext) -> bool {
        workflow_context_matches(&self.context, context)
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
        context: &MembershipCommandContext,
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
                if !workflow_context_matches(context, &approval_context) {
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
