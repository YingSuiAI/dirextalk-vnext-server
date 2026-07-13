use std::{collections::BTreeMap, error::Error, fmt};

use dtx_agent_host::{AgentHost, HostLifecycle};
use dtx_domain::{ConnectorId, HostId, Revision, TenantId};

use crate::{
    CatalogRelease, CommandApplication, CommandDisposition, CommandOutcome, CommandResult,
    ConnectorTarget, CredentialArtifactProvider, DurableHostCommand, HostCommand,
    HostCommandEnvelope, HostRevisionFence, Journal, JournalRecord, ManagedConnectorDesiredState,
    ManagedConnectorSnapshot, OperationIntent, OperationReceipt, PortError, ProcessController,
    ProcessMutationId, ProcessObservation, ReleaseCatalog, RemovalPolicy, SupervisorSnapshot,
    types::validate_snapshot_ids,
};

/// Pure host-local desired/observed state coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostSupervisor {
    tenant_id: TenantId,
    host_id: HostId,
    revisions: HostRevisionFence,
    instances: BTreeMap<ConnectorId, ManagedConnectorSnapshot>,
}

#[derive(Clone, Copy)]
enum ReleaseValidation {
    Known,
    Runnable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableCommandPreconditionError {
    ConnectorNotFound,
    ConnectorRemoved,
    ConnectorMustBeStopped,
    AdapterMismatch,
    CredentialUnchanged,
}

pub(crate) fn validate_durable_command_precondition(
    existing: Option<&ManagedConnectorSnapshot>,
    command: DurableHostCommand,
) -> Result<(), DurableCommandPreconditionError> {
    let target = command.target();
    if let DurableHostCommand::Ensure { .. } = command {
        let Some(existing) = existing else {
            return Ok(());
        };
        if existing.desired_state == ManagedConnectorDesiredState::RemovedRetainingData {
            return Err(DurableCommandPreconditionError::ConnectorRemoved);
        }
        if existing.adapter_kind != target.adapter_kind() {
            return Err(DurableCommandPreconditionError::AdapterMismatch);
        }
        if existing.desired_state == ManagedConnectorDesiredState::Running {
            return Err(DurableCommandPreconditionError::ConnectorMustBeStopped);
        }
        return Ok(());
    }

    let existing = existing.ok_or(DurableCommandPreconditionError::ConnectorNotFound)?;
    if existing.desired_state == ManagedConnectorDesiredState::RemovedRetainingData {
        return Err(DurableCommandPreconditionError::ConnectorRemoved);
    }
    if existing.adapter_kind != target.adapter_kind() {
        return Err(DurableCommandPreconditionError::AdapterMismatch);
    }
    if let DurableHostCommand::RotateCredential { credential_ref, .. } = command
        && existing.credential_ref == Some(credential_ref)
    {
        return Err(DurableCommandPreconditionError::CredentialUnchanged);
    }
    Ok(())
}

impl From<DurableCommandPreconditionError> for SupervisorError {
    fn from(error: DurableCommandPreconditionError) -> Self {
        match error {
            DurableCommandPreconditionError::ConnectorNotFound => Self::ConnectorNotFound,
            DurableCommandPreconditionError::ConnectorRemoved => Self::ConnectorRemoved,
            DurableCommandPreconditionError::ConnectorMustBeStopped => Self::ConnectorMustBeStopped,
            DurableCommandPreconditionError::AdapterMismatch => Self::AdapterMismatch,
            DurableCommandPreconditionError::CredentialUnchanged => Self::CredentialUnchanged,
        }
    }
}

impl HostSupervisor {
    /// Creates a supervisor bound to one enrolled active Host.
    ///
    /// The local desired/observed fence starts at the exact durable Host fence;
    /// it is never reset when this core is constructed.
    ///
    /// # Errors
    ///
    /// Rejects a Host that is not active or whose revision facts are invalid.
    pub fn new(host: &AgentHost) -> Result<Self, SupervisorSnapshotError> {
        if host.lifecycle() != HostLifecycle::Active {
            return Err(SupervisorSnapshotError::HostNotActive);
        }
        let revisions =
            HostRevisionFence::from_revisions(host.desired_revision(), host.observed_revision())
                .map_err(|_| SupervisorSnapshotError::InvalidRevisionFence)?;
        Ok(Self {
            tenant_id: host.tenant_id(),
            host_id: host.host_id(),
            revisions,
            instances: BTreeMap::new(),
        })
    }

    /// Rehydrates only after validating Host binding, revision ordering,
    /// sibling uniqueness, state postconditions, counters, and every persisted
    /// release against the current catalog.
    ///
    /// # Errors
    ///
    /// Fails closed on any malformed or no-longer-approved snapshot fact.
    pub fn try_from_snapshot<R: ReleaseCatalog>(
        host: &AgentHost,
        snapshot: SupervisorSnapshot,
        catalog: &mut R,
    ) -> Result<Self, SupervisorSnapshotError> {
        if host.lifecycle() != HostLifecycle::Active {
            return Err(SupervisorSnapshotError::HostNotActive);
        }
        if snapshot.tenant_id != host.tenant_id() || snapshot.host_id != host.host_id() {
            return Err(SupervisorSnapshotError::HostBoundaryMismatch);
        }
        let revisions = HostRevisionFence::from_revisions(
            snapshot.desired_revision,
            snapshot.observed_revision,
        )
        .map_err(|_| SupervisorSnapshotError::InvalidRevisionFence)?;
        validate_snapshot_ids(&snapshot.instances)
            .map_err(|()| SupervisorSnapshotError::DuplicateConnector)?;
        if !snapshot.instances.is_empty()
            && (revisions.desired() == Revision::INITIAL
                || revisions.observed() != Some(revisions.desired()))
        {
            return Err(SupervisorSnapshotError::InvalidInstanceState);
        }

        let mut instances = BTreeMap::new();
        for instance in snapshot.instances {
            if instance.release.adapter_kind() != instance.adapter_kind {
                return Err(SupervisorSnapshotError::AdapterMismatch);
            }
            if instance.credential_generation > Revision::MAX
                || (instance.credential_generation == 0) != instance.credential_ref.is_none()
                || instance.credential_ref.is_none() != instance.credential_operation_id.is_none()
                || !snapshot_observation_is_valid(instance)
            {
                return Err(SupervisorSnapshotError::InvalidInstanceState);
            }
            let approved = catalog
                .resolve_known(instance.adapter_kind, instance.release.digest())
                .map_err(|_| SupervisorSnapshotError::ReleaseNotApproved)?;
            if approved != instance.release {
                return Err(SupervisorSnapshotError::ReleaseNotApproved);
            }
            instances.insert(instance.connector_id, instance);
        }
        Ok(Self {
            tenant_id: snapshot.tenant_id,
            host_id: snapshot.host_id,
            revisions,
            instances,
        })
    }

    /// Returns the complete non-secret persistence image.
    #[must_use]
    pub fn snapshot(&self) -> SupervisorSnapshot {
        SupervisorSnapshot {
            tenant_id: self.tenant_id,
            host_id: self.host_id,
            desired_revision: self.revisions.desired(),
            observed_revision: self.revisions.observed(),
            instances: self.instances.values().copied().collect(),
        }
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub const fn revision_fence(&self) -> HostRevisionFence {
        self.revisions
    }

    #[must_use]
    pub fn instance(&self, connector_id: ConnectorId) -> Option<&ManagedConnectorSnapshot> {
        self.instances.get(&connector_id)
    }

    /// Reads one known Connector's current process state without creating an
    /// operation, writing the journal, or changing desired/observed revisions.
    ///
    /// # Errors
    ///
    /// Rejects an unknown Connector or a sanitized observation-port failure.
    pub fn observe<A, P>(
        &self,
        connector_id: ConnectorId,
        process: &mut P,
    ) -> Result<ProcessObservation, SupervisorError>
    where
        P: ProcessController<A>,
    {
        let instance = self
            .instances
            .get(&connector_id)
            .ok_or(SupervisorError::ConnectorNotFound)?;
        process
            .observe(self.target(connector_id, instance.adapter_kind))
            .map_err(SupervisorError::Process)
    }

    /// Executes one closed mutation after durably journaling its resolved
    /// intent. A different operation cannot pass an unresolved Host intent.
    ///
    /// # Errors
    ///
    /// Rejects wrong-host, stale, conflicting, pending, unapproved, or invalid
    /// lifecycle input and maps sanitized port failures without diagnostics.
    pub fn execute<J, R, C, P>(
        &mut self,
        envelope: &HostCommandEnvelope,
        journal: &mut J,
        catalog: &mut R,
        credentials: &mut C,
        process: &mut P,
    ) -> Result<CommandResult, SupervisorError>
    where
        J: Journal,
        R: ReleaseCatalog,
        C: CredentialArtifactProvider,
        P: ProcessController<C::Artifact>,
    {
        self.ensure_envelope_boundary(*envelope)?;
        if let Some(record) = journal
            .lookup(self.host_id, envelope.operation_id())
            .map_err(SupervisorError::Journal)?
        {
            return match record {
                JournalRecord::Completed { intent, receipt } => {
                    Self::validate_intent_for_envelope(&intent, *envelope)?;
                    self.restore_completed(&intent, receipt, catalog)
                }
                JournalRecord::Pending(intent) => {
                    Self::validate_intent_for_envelope(&intent, *envelope)?;
                    if Self::pending_start_is_policy_blocked(&intent, catalog)? {
                        self.reconcile_policy_blocked_start(&intent, journal, catalog, process)
                    } else {
                        self.apply_intent(
                            &intent,
                            CommandApplication::Reconciled,
                            journal,
                            catalog,
                            credentials,
                            process,
                        )
                    }
                }
            };
        }

        let pending = journal
            .pending(self.host_id)
            .map_err(SupervisorError::Journal)?;
        if !pending.is_empty() {
            return Err(SupervisorError::PendingOperation);
        }
        if envelope.expected() != self.revisions {
            return Err(SupervisorError::StaleRevision {
                current: self.revisions,
            });
        }

        let command = self.resolve_command(envelope.command(), catalog)?;
        let resulting = self
            .revisions
            .advance_and_acknowledge()
            .ok_or(SupervisorError::RevisionExhausted)?;
        let intent = OperationIntent::new(*envelope, resulting, command);
        let predecessor = self.snapshot();
        journal
            .persist_intent(intent.clone(), &predecessor)
            .map_err(SupervisorError::Journal)?;
        self.apply_intent(
            &intent,
            CommandApplication::Applied,
            journal,
            catalog,
            credentials,
            process,
        )
    }

    /// Reconciles the Host's sole durable pending operation after a crash.
    ///
    /// # Errors
    ///
    /// Fails closed for multiple pending intents, malformed durable state,
    /// revision divergence, catalog revocation, or a port failure.
    pub fn reconcile<J, R, C, P>(
        &mut self,
        journal: &mut J,
        catalog: &mut R,
        credentials: &mut C,
        process: &mut P,
    ) -> Result<Vec<CommandResult>, SupervisorError>
    where
        J: Journal,
        R: ReleaseCatalog,
        C: CredentialArtifactProvider,
        P: ProcessController<C::Artifact>,
    {
        let pending = journal
            .pending(self.host_id)
            .map_err(SupervisorError::Journal)?;
        if pending.len() > 1 {
            return Err(SupervisorError::SnapshotDiverged);
        }
        let Some(intent) = pending.first() else {
            return Ok(Vec::new());
        };
        if Self::pending_start_is_policy_blocked(intent, catalog)? {
            let result = self.reconcile_policy_blocked_start(intent, journal, catalog, process)?;
            return Ok(vec![result]);
        }
        let result = self.apply_intent(
            intent,
            CommandApplication::Reconciled,
            journal,
            catalog,
            credentials,
            process,
        )?;
        Ok(vec![result])
    }

    fn pending_start_is_policy_blocked<R: ReleaseCatalog>(
        intent: &OperationIntent,
        catalog: &mut R,
    ) -> Result<bool, SupervisorError> {
        let release = match intent.command() {
            DurableHostCommand::Start { release, .. }
            | DurableHostCommand::Restart { release, .. } => release,
            DurableHostCommand::Ensure { .. }
            | DurableHostCommand::Stop { .. }
            | DurableHostCommand::RotateCredential { .. }
            | DurableHostCommand::RemoveRetainingData { .. } => return Ok(false),
        };
        match catalog.resolve_runnable(release.adapter_kind(), release.digest()) {
            Ok(current) if current == release => Ok(false),
            Ok(_) => Err(SupervisorError::ReleaseCapabilityMismatch),
            Err(error) if error.kind() == crate::PortErrorKind::NotApproved => Ok(true),
            Err(error) => Err(SupervisorError::ReleaseCatalog(error)),
        }
    }

    fn reconcile_policy_blocked_start<J, R, P, A>(
        &mut self,
        intent: &OperationIntent,
        journal: &mut J,
        catalog: &mut R,
        process: &mut P,
    ) -> Result<CommandResult, SupervisorError>
    where
        J: Journal,
        R: ReleaseCatalog,
        P: ProcessController<A>,
    {
        self.validate_intent(intent, catalog, ReleaseValidation::Known)?;
        if self.revisions != intent.expected() {
            return Err(SupervisorError::SnapshotDiverged);
        }
        let target = intent.command().target();
        let observation = process
            .stop(
                ProcessMutationId::policy_compensation(intent.operation_id()),
                target,
            )
            .map_err(SupervisorError::Process)?;
        if observation != ProcessObservation::Stopped {
            return Err(SupervisorError::InvalidProcessObservation);
        }
        let mut staged = self.clone();
        staged.apply_policy_blocked_state(intent.command())?;
        staged.revisions = intent.resulting();
        let outcome = staged.current_outcome_with_disposition(
            target.connector_id(),
            CommandDisposition::PolicyBlocked,
        )?;
        journal
            .complete(
                OperationReceipt::new(intent.operation_id(), intent.command_digest(), outcome),
                &staged.snapshot(),
            )
            .map_err(SupervisorError::Journal)?;
        *self = staged;
        Ok(CommandResult::new(CommandApplication::Reconciled, outcome))
    }

    fn ensure_envelope_boundary(
        &self,
        envelope: HostCommandEnvelope,
    ) -> Result<(), SupervisorError> {
        if envelope.tenant_id() == self.tenant_id && envelope.host_id() == self.host_id {
            Ok(())
        } else {
            Err(SupervisorError::HostBoundaryMismatch)
        }
    }

    fn resolve_command<R: ReleaseCatalog>(
        &self,
        command: HostCommand,
        catalog: &mut R,
    ) -> Result<DurableHostCommand, SupervisorError> {
        match command {
            HostCommand::Ensure {
                connector_id,
                adapter_kind,
                release_digest,
            } => {
                if let Some(existing) = self.instances.get(&connector_id) {
                    if existing.desired_state == ManagedConnectorDesiredState::RemovedRetainingData
                    {
                        return Err(SupervisorError::ConnectorRemoved);
                    }
                    if existing.adapter_kind != adapter_kind {
                        return Err(SupervisorError::AdapterMismatch);
                    }
                    if existing.desired_state == ManagedConnectorDesiredState::Running {
                        return Err(SupervisorError::ConnectorMustBeStopped);
                    }
                }
                let release = catalog
                    .resolve_runnable(adapter_kind, release_digest)
                    .map_err(SupervisorError::ReleaseCatalog)?;
                if release.adapter_kind() != adapter_kind || release.digest() != release_digest {
                    return Err(SupervisorError::ReleaseCapabilityMismatch);
                }
                Ok(DurableHostCommand::Ensure {
                    target: self.target(connector_id, adapter_kind),
                    release,
                })
            }
            HostCommand::Start { connector_id } => {
                let instance = self.usable_instance(connector_id)?;
                Self::ensure_release_runnable(instance.release, catalog)?;
                let credential_ref = instance
                    .credential_ref
                    .ok_or(SupervisorError::CredentialRequired)?;
                let credential_operation_id = instance
                    .credential_operation_id
                    .ok_or(SupervisorError::CredentialRequired)?;
                Ok(DurableHostCommand::Start {
                    target: self.target(connector_id, instance.adapter_kind),
                    release: instance.release,
                    credential_ref,
                    credential_operation_id,
                })
            }
            HostCommand::Stop { connector_id } => {
                let instance = self.usable_instance(connector_id)?;
                Ok(DurableHostCommand::Stop {
                    target: self.target(connector_id, instance.adapter_kind),
                })
            }
            HostCommand::Restart { connector_id } => {
                let instance = self.usable_instance(connector_id)?;
                Self::ensure_release_runnable(instance.release, catalog)?;
                let credential_ref = instance
                    .credential_ref
                    .ok_or(SupervisorError::CredentialRequired)?;
                let credential_operation_id = instance
                    .credential_operation_id
                    .ok_or(SupervisorError::CredentialRequired)?;
                Ok(DurableHostCommand::Restart {
                    target: self.target(connector_id, instance.adapter_kind),
                    release: instance.release,
                    credential_ref,
                    credential_operation_id,
                })
            }
            HostCommand::RotateCredential {
                connector_id,
                credential_ref,
            } => {
                let instance = self.usable_instance(connector_id)?;
                Self::ensure_release_runnable(instance.release, catalog)?;
                if instance.credential_ref == Some(credential_ref) {
                    return Err(SupervisorError::CredentialUnchanged);
                }
                let resulting_generation = instance
                    .credential_generation
                    .checked_add(1)
                    .filter(|value| *value <= Revision::MAX)
                    .ok_or(SupervisorError::CredentialGenerationExhausted)?;
                Ok(DurableHostCommand::RotateCredential {
                    target: self.target(connector_id, instance.adapter_kind),
                    release: instance.release,
                    credential_ref,
                    resulting_generation,
                })
            }
            HostCommand::Remove {
                connector_id,
                policy: RemovalPolicy::RetainData,
            } => {
                let instance = self.usable_instance(connector_id)?;
                Ok(DurableHostCommand::RemoveRetainingData {
                    target: self.target(connector_id, instance.adapter_kind),
                })
            }
        }
    }

    fn ensure_release_runnable<R: ReleaseCatalog>(
        release: CatalogRelease,
        catalog: &mut R,
    ) -> Result<(), SupervisorError> {
        let approved = catalog
            .resolve_runnable(release.adapter_kind(), release.digest())
            .map_err(SupervisorError::ReleaseCatalog)?;
        if approved == release {
            Ok(())
        } else {
            Err(SupervisorError::ReleaseCapabilityMismatch)
        }
    }

    fn ensure_release_known<R: ReleaseCatalog>(
        release: CatalogRelease,
        catalog: &mut R,
    ) -> Result<(), SupervisorError> {
        let known = catalog
            .resolve_known(release.adapter_kind(), release.digest())
            .map_err(SupervisorError::ReleaseCatalog)?;
        if known == release {
            Ok(())
        } else {
            Err(SupervisorError::ReleaseCapabilityMismatch)
        }
    }

    fn validate_release<R: ReleaseCatalog>(
        release: CatalogRelease,
        catalog: &mut R,
        validation: ReleaseValidation,
    ) -> Result<(), SupervisorError> {
        match validation {
            ReleaseValidation::Known => Self::ensure_release_known(release, catalog),
            ReleaseValidation::Runnable => Self::ensure_release_runnable(release, catalog),
        }
    }

    fn usable_instance(
        &self,
        connector_id: ConnectorId,
    ) -> Result<&ManagedConnectorSnapshot, SupervisorError> {
        let instance = self
            .instances
            .get(&connector_id)
            .ok_or(SupervisorError::ConnectorNotFound)?;
        if instance.desired_state == ManagedConnectorDesiredState::RemovedRetainingData {
            Err(SupervisorError::ConnectorRemoved)
        } else {
            Ok(instance)
        }
    }

    const fn target(
        &self,
        connector_id: ConnectorId,
        adapter_kind: dtx_connect_registry::AdapterKind,
    ) -> ConnectorTarget {
        ConnectorTarget::new(self.tenant_id, self.host_id, connector_id, adapter_kind)
    }

    fn validate_intent_for_envelope(
        intent: &OperationIntent,
        envelope: HostCommandEnvelope,
    ) -> Result<(), SupervisorError> {
        if intent.operation_id() != envelope.operation_id()
            || intent.command_digest() != envelope.command_digest()
            || intent.expected() != envelope.expected()
            || !durable_command_matches(intent.command(), envelope.command())
        {
            return Err(SupervisorError::OperationConflict);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn validate_intent<R: ReleaseCatalog>(
        &self,
        intent: &OperationIntent,
        catalog: &mut R,
        release_validation: ReleaseValidation,
    ) -> Result<(), SupervisorError> {
        if intent.tenant_id() != self.tenant_id || intent.host_id() != self.host_id {
            return Err(SupervisorError::HostBoundaryMismatch);
        }
        if intent.expected().advance_and_acknowledge() != Some(intent.resulting()) {
            return Err(SupervisorError::SnapshotDiverged);
        }
        let at_expected = self.revisions == intent.expected();
        let at_resulting = self.revisions == intent.resulting();
        let historical = self.revisions.desired() > intent.resulting().desired();
        if !at_expected && !at_resulting && !historical {
            return Err(SupervisorError::SnapshotDiverged);
        }

        let command = intent.command();
        let target = command.target();
        if target.tenant_id() != self.tenant_id || target.host_id() != self.host_id {
            return Err(SupervisorError::HostBoundaryMismatch);
        }
        if matches!(
            command,
            DurableHostCommand::Ensure { release, .. }
                | DurableHostCommand::Start { release, .. }
                | DurableHostCommand::Restart { release, .. }
                | DurableHostCommand::RotateCredential { release, .. }
                if release.adapter_kind() != target.adapter_kind()
        ) {
            return Err(SupervisorError::ReleaseCapabilityMismatch);
        }
        if let DurableHostCommand::RotateCredential {
            resulting_generation,
            ..
        } = command
            && (resulting_generation == 0 || resulting_generation > Revision::MAX)
        {
            return Err(SupervisorError::SnapshotDiverged);
        }
        if historical {
            return match command {
                DurableHostCommand::Ensure { release, .. }
                | DurableHostCommand::Start { release, .. }
                | DurableHostCommand::Restart { release, .. }
                | DurableHostCommand::RotateCredential { release, .. } => {
                    Self::validate_release(release, catalog, release_validation)
                }
                DurableHostCommand::Stop { .. }
                | DurableHostCommand::RemoveRetainingData { .. } => Ok(()),
            };
        }
        let instance = self.instances.get(&target.connector_id());
        if at_expected {
            validate_durable_command_precondition(instance, command)?;
        }
        match command {
            DurableHostCommand::Ensure { release, .. } => {
                Self::validate_release(release, catalog, release_validation)?;
                if release.adapter_kind() != target.adapter_kind() {
                    return Err(SupervisorError::ReleaseCapabilityMismatch);
                }
                if let Some(existing) = instance {
                    if existing.adapter_kind != target.adapter_kind() {
                        return Err(SupervisorError::AdapterMismatch);
                    }
                    if at_expected
                        && existing.desired_state
                            == ManagedConnectorDesiredState::RemovedRetainingData
                    {
                        return Err(SupervisorError::ConnectorRemoved);
                    }
                    if at_resulting && existing.release != release {
                        return Err(SupervisorError::SnapshotDiverged);
                    }
                } else if at_resulting {
                    return Err(SupervisorError::SnapshotDiverged);
                }
            }
            DurableHostCommand::Start { release, .. }
            | DurableHostCommand::Restart { release, .. }
            | DurableHostCommand::RotateCredential { release, .. } => {
                Self::validate_release(release, catalog, release_validation)?;
                let existing = instance.ok_or(SupervisorError::SnapshotDiverged)?;
                if existing.adapter_kind != target.adapter_kind() || existing.release != release {
                    return Err(SupervisorError::SnapshotDiverged);
                }
                if at_expected
                    && existing.desired_state == ManagedConnectorDesiredState::RemovedRetainingData
                {
                    return Err(SupervisorError::ConnectorRemoved);
                }
                if let DurableHostCommand::RotateCredential {
                    resulting_generation,
                    ..
                } = command
                {
                    let expected_generation = if at_expected {
                        existing.credential_generation.checked_add(1)
                    } else {
                        Some(existing.credential_generation)
                    };
                    if expected_generation != Some(resulting_generation)
                        || resulting_generation > Revision::MAX
                    {
                        return Err(SupervisorError::SnapshotDiverged);
                    }
                }
                if let DurableHostCommand::Start {
                    credential_ref,
                    credential_operation_id,
                    ..
                }
                | DurableHostCommand::Restart {
                    credential_ref,
                    credential_operation_id,
                    ..
                } = command
                    && (existing.credential_ref != Some(credential_ref)
                        || existing.credential_operation_id != Some(credential_operation_id))
                {
                    return Err(SupervisorError::SnapshotDiverged);
                }
            }
            DurableHostCommand::Stop { .. } | DurableHostCommand::RemoveRetainingData { .. } => {
                let existing = instance.ok_or(SupervisorError::SnapshotDiverged)?;
                if existing.adapter_kind != target.adapter_kind() {
                    return Err(SupervisorError::AdapterMismatch);
                }
                if at_expected
                    && existing.desired_state == ManagedConnectorDesiredState::RemovedRetainingData
                {
                    return Err(SupervisorError::ConnectorRemoved);
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_intent<J, R, C, P>(
        &mut self,
        intent: &OperationIntent,
        application: CommandApplication,
        journal: &mut J,
        catalog: &mut R,
        credentials: &mut C,
        process: &mut P,
    ) -> Result<CommandResult, SupervisorError>
    where
        J: Journal,
        R: ReleaseCatalog,
        C: CredentialArtifactProvider,
        P: ProcessController<C::Artifact>,
    {
        let release_validation = if application == CommandApplication::Reconciled
            && matches!(
                intent.command(),
                DurableHostCommand::Ensure { .. } | DurableHostCommand::RotateCredential { .. }
            ) {
            ReleaseValidation::Known
        } else {
            ReleaseValidation::Runnable
        };
        self.validate_intent(intent, catalog, release_validation)?;
        if self.revisions != intent.expected() && self.revisions != intent.resulting() {
            return Err(SupervisorError::SnapshotDiverged);
        }
        if self.revisions == intent.resulting() {
            let outcome = self.current_outcome(intent.command().target().connector_id())?;
            if !command_outcome_is_valid(intent.command(), outcome) {
                return Err(SupervisorError::SnapshotDiverged);
            }
            journal
                .complete(
                    OperationReceipt::new(intent.operation_id(), intent.command_digest(), outcome),
                    &self.snapshot(),
                )
                .map_err(SupervisorError::Journal)?;
            return Ok(CommandResult::new(application, outcome));
        }

        let observation = self.apply_process(intent, credentials, process)?;
        let mut staged = self.clone();
        staged.apply_state(intent.operation_id(), intent.command(), observation)?;
        staged.revisions = intent.resulting();
        let outcome = staged.current_outcome(intent.command().target().connector_id())?;
        journal
            .complete(
                OperationReceipt::new(intent.operation_id(), intent.command_digest(), outcome),
                &staged.snapshot(),
            )
            .map_err(SupervisorError::Journal)?;
        *self = staged;
        Ok(CommandResult::new(application, outcome))
    }

    fn restore_completed<R: ReleaseCatalog>(
        &mut self,
        intent: &OperationIntent,
        receipt: OperationReceipt,
        catalog: &mut R,
    ) -> Result<CommandResult, SupervisorError> {
        if receipt.operation_id() != intent.operation_id()
            || receipt.command_digest() != intent.command_digest()
            || receipt.outcome().revisions != intent.resulting()
            || receipt.outcome().connector_id != intent.command().target().connector_id()
            || !command_outcome_is_valid(intent.command(), receipt.outcome())
        {
            return Err(SupervisorError::SnapshotDiverged);
        }
        self.validate_intent(intent, catalog, ReleaseValidation::Known)?;
        if self.revisions.desired() > intent.resulting().desired() {
            return Ok(CommandResult::new(
                CommandApplication::Replayed,
                receipt.outcome(),
            ));
        }
        if self.revisions == intent.expected() {
            let mut staged = self.clone();
            if receipt.outcome().disposition == CommandDisposition::PolicyBlocked {
                staged.apply_policy_blocked_state(intent.command())?;
            } else {
                staged.apply_state(
                    intent.operation_id(),
                    intent.command(),
                    receipt.outcome().observation,
                )?;
            }
            staged.revisions = intent.resulting();
            if staged.current_outcome_with_disposition(
                receipt.outcome().connector_id,
                receipt.outcome().disposition,
            )? != receipt.outcome()
            {
                return Err(SupervisorError::SnapshotDiverged);
            }
            *self = staged;
        } else if self.current_outcome_with_disposition(
            receipt.outcome().connector_id,
            receipt.outcome().disposition,
        )? != receipt.outcome()
        {
            return Err(SupervisorError::SnapshotDiverged);
        }
        Ok(CommandResult::new(
            CommandApplication::Replayed,
            receipt.outcome(),
        ))
    }

    fn apply_process<C, P>(
        &self,
        intent: &OperationIntent,
        credentials: &mut C,
        process: &mut P,
    ) -> Result<ProcessObservation, SupervisorError>
    where
        C: CredentialArtifactProvider,
        P: ProcessController<C::Artifact>,
    {
        let operation_id = intent.operation_id();
        let mutation_id = ProcessMutationId::requested(operation_id);
        let command = intent.command();
        let observation = match command {
            DurableHostCommand::Ensure { target, release } => process
                .ensure(mutation_id, target, release)
                .map_err(SupervisorError::Process)?,
            DurableHostCommand::Start {
                target,
                release,
                credential_ref,
                ..
            } => process
                .start(mutation_id, target, release, credential_ref)
                .map_err(SupervisorError::Process)?,
            DurableHostCommand::Stop { target } => process
                .stop(mutation_id, target)
                .map_err(SupervisorError::Process)?,
            DurableHostCommand::Restart {
                target,
                release,
                credential_ref,
                ..
            } => process
                .restart(mutation_id, target, release, credential_ref)
                .map_err(SupervisorError::Process)?,
            DurableHostCommand::RotateCredential {
                target,
                credential_ref,
                ..
            } => {
                let artifact = credentials
                    .materialize(operation_id, target, credential_ref)
                    .map_err(SupervisorError::CredentialArtifact)?;
                process
                    .rotate_credential(mutation_id, target, credential_ref, &artifact)
                    .map_err(SupervisorError::Process)?
            }
            DurableHostCommand::RemoveRetainingData { target } => process
                .remove_retaining_data(mutation_id, target)
                .map_err(SupervisorError::Process)?,
        };
        if self.observation_is_valid(command, observation) {
            Ok(observation)
        } else {
            Err(SupervisorError::InvalidProcessObservation)
        }
    }

    fn observation_is_valid(
        &self,
        command: DurableHostCommand,
        observation: ProcessObservation,
    ) -> bool {
        match command {
            DurableHostCommand::Ensure { .. } | DurableHostCommand::Stop { .. } => {
                observation == ProcessObservation::Stopped
            }
            DurableHostCommand::Start { .. } | DurableHostCommand::Restart { .. } => {
                matches!(
                    observation,
                    ProcessObservation::Running | ProcessObservation::Failed
                )
            }
            DurableHostCommand::RotateCredential { target, .. } => self
                .instances
                .get(&target.connector_id())
                .is_some_and(|instance| match instance.desired_state {
                    ManagedConnectorDesiredState::Running => {
                        matches!(
                            observation,
                            ProcessObservation::Running | ProcessObservation::Failed
                        )
                    }
                    ManagedConnectorDesiredState::EnsuredStopped
                    | ManagedConnectorDesiredState::Stopped => {
                        observation == ProcessObservation::Stopped
                    }
                    ManagedConnectorDesiredState::RemovedRetainingData => false,
                }),
            DurableHostCommand::RemoveRetainingData { .. } => {
                observation == ProcessObservation::Absent
            }
        }
    }

    fn apply_state(
        &mut self,
        operation_id: crate::HostOperationId,
        command: DurableHostCommand,
        observation: ProcessObservation,
    ) -> Result<(), SupervisorError> {
        if !self.observation_is_valid(command, observation) {
            return Err(SupervisorError::InvalidProcessObservation);
        }
        match command {
            DurableHostCommand::Ensure { target, release } => {
                let (credential_generation, credential_ref, credential_operation_id) = self
                    .instances
                    .get(&target.connector_id())
                    .map_or((0, None, None), |instance| {
                        (
                            instance.credential_generation,
                            instance.credential_ref,
                            instance.credential_operation_id,
                        )
                    });
                self.instances.insert(
                    target.connector_id(),
                    ManagedConnectorSnapshot {
                        connector_id: target.connector_id(),
                        adapter_kind: target.adapter_kind(),
                        release,
                        desired_state: ManagedConnectorDesiredState::EnsuredStopped,
                        observation,
                        credential_generation,
                        credential_ref,
                        credential_operation_id,
                    },
                );
            }
            DurableHostCommand::Start { target, .. }
            | DurableHostCommand::Restart { target, .. } => {
                let instance = self.instance_mut(target.connector_id())?;
                instance.desired_state = ManagedConnectorDesiredState::Running;
                instance.observation = observation;
            }
            DurableHostCommand::Stop { target } => {
                let instance = self.instance_mut(target.connector_id())?;
                instance.desired_state = ManagedConnectorDesiredState::Stopped;
                instance.observation = observation;
            }
            DurableHostCommand::RotateCredential {
                target,
                credential_ref,
                resulting_generation,
                ..
            } => {
                let instance = self.instance_mut(target.connector_id())?;
                instance.credential_generation = resulting_generation;
                instance.credential_ref = Some(credential_ref);
                instance.credential_operation_id = Some(operation_id);
                instance.observation = observation;
            }
            DurableHostCommand::RemoveRetainingData { target } => {
                let instance = self.instance_mut(target.connector_id())?;
                instance.desired_state = ManagedConnectorDesiredState::RemovedRetainingData;
                instance.observation = observation;
            }
        }
        Ok(())
    }

    fn apply_policy_blocked_state(
        &mut self,
        command: DurableHostCommand,
    ) -> Result<(), SupervisorError> {
        if !matches!(
            command,
            DurableHostCommand::Start { .. } | DurableHostCommand::Restart { .. }
        ) {
            return Err(SupervisorError::SnapshotDiverged);
        }
        let instance = self.instance_mut(command.target().connector_id())?;
        instance.desired_state = ManagedConnectorDesiredState::Stopped;
        instance.observation = ProcessObservation::Stopped;
        Ok(())
    }

    fn current_outcome(
        &self,
        connector_id: ConnectorId,
    ) -> Result<CommandOutcome, SupervisorError> {
        self.current_outcome_with_disposition(connector_id, CommandDisposition::Applied)
    }

    fn current_outcome_with_disposition(
        &self,
        connector_id: ConnectorId,
        disposition: CommandDisposition,
    ) -> Result<CommandOutcome, SupervisorError> {
        let instance = self
            .instances
            .get(&connector_id)
            .ok_or(SupervisorError::SnapshotDiverged)?;
        Ok(CommandOutcome {
            connector_id,
            revisions: self.revisions,
            disposition,
            desired_state: instance.desired_state,
            observation: instance.observation,
            credential_generation: instance.credential_generation,
        })
    }

    fn instance_mut(
        &mut self,
        connector_id: ConnectorId,
    ) -> Result<&mut ManagedConnectorSnapshot, SupervisorError> {
        self.instances
            .get_mut(&connector_id)
            .ok_or(SupervisorError::SnapshotDiverged)
    }
}

const fn snapshot_observation_is_valid(instance: ManagedConnectorSnapshot) -> bool {
    matches!(
        (instance.desired_state, instance.observation),
        (
            ManagedConnectorDesiredState::EnsuredStopped | ManagedConnectorDesiredState::Stopped,
            ProcessObservation::Stopped
        ) | (
            ManagedConnectorDesiredState::Running,
            ProcessObservation::Running | ProcessObservation::Failed
        ) | (
            ManagedConnectorDesiredState::RemovedRetainingData,
            ProcessObservation::Absent
        )
    )
}

fn durable_command_matches(command: DurableHostCommand, requested: HostCommand) -> bool {
    match (command, requested) {
        (
            DurableHostCommand::Ensure { target, release },
            HostCommand::Ensure {
                connector_id,
                adapter_kind,
                release_digest,
            },
        ) => {
            target.connector_id() == connector_id
                && target.adapter_kind() == adapter_kind
                && release.adapter_kind() == adapter_kind
                && release.digest().as_bytes() == release_digest.as_bytes()
        }
        (DurableHostCommand::Start { target, .. }, HostCommand::Start { connector_id })
        | (DurableHostCommand::Stop { target }, HostCommand::Stop { connector_id })
        | (DurableHostCommand::Restart { target, .. }, HostCommand::Restart { connector_id }) => {
            target.connector_id() == connector_id
        }
        (
            DurableHostCommand::RotateCredential {
                target,
                credential_ref: durable_reference,
                ..
            },
            HostCommand::RotateCredential {
                connector_id,
                credential_ref: requested_reference,
            },
        ) => {
            target.connector_id() == connector_id
                && durable_reference.as_bytes() == requested_reference.as_bytes()
        }
        (
            DurableHostCommand::RemoveRetainingData { target },
            HostCommand::Remove {
                connector_id,
                policy: RemovalPolicy::RetainData,
            },
        ) => target.connector_id() == connector_id,
        _ => false,
    }
}

const fn command_outcome_is_valid(command: DurableHostCommand, outcome: CommandOutcome) -> bool {
    if matches!(outcome.disposition, CommandDisposition::PolicyBlocked) {
        return matches!(
            command,
            DurableHostCommand::Start { .. } | DurableHostCommand::Restart { .. }
        ) && matches!(
            (outcome.desired_state, outcome.observation),
            (
                ManagedConnectorDesiredState::Stopped,
                ProcessObservation::Stopped
            )
        );
    }
    match command {
        DurableHostCommand::Ensure { .. } => {
            matches!(
                (outcome.desired_state, outcome.observation),
                (
                    ManagedConnectorDesiredState::EnsuredStopped,
                    ProcessObservation::Stopped
                )
            )
        }
        DurableHostCommand::Start { .. } | DurableHostCommand::Restart { .. } => {
            matches!(
                (outcome.desired_state, outcome.observation),
                (
                    ManagedConnectorDesiredState::Running,
                    ProcessObservation::Running | ProcessObservation::Failed
                )
            )
        }
        DurableHostCommand::Stop { .. } => {
            matches!(
                (outcome.desired_state, outcome.observation),
                (
                    ManagedConnectorDesiredState::Stopped,
                    ProcessObservation::Stopped
                )
            )
        }
        DurableHostCommand::RotateCredential {
            resulting_generation,
            ..
        } => {
            outcome.credential_generation == resulting_generation
                && matches!(
                    (outcome.desired_state, outcome.observation),
                    (
                        ManagedConnectorDesiredState::Running,
                        ProcessObservation::Running | ProcessObservation::Failed
                    ) | (
                        ManagedConnectorDesiredState::EnsuredStopped
                            | ManagedConnectorDesiredState::Stopped,
                        ProcessObservation::Stopped
                    )
                )
        }
        DurableHostCommand::RemoveRetainingData { .. } => {
            matches!(
                (outcome.desired_state, outcome.observation),
                (
                    ManagedConnectorDesiredState::RemovedRetainingData,
                    ProcessObservation::Absent
                )
            )
        }
    }
}

/// Fail-closed snapshot validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorSnapshotError {
    HostNotActive,
    HostBoundaryMismatch,
    InvalidRevisionFence,
    DuplicateConnector,
    AdapterMismatch,
    InvalidInstanceState,
    ReleaseNotApproved,
}

impl fmt::Display for SupervisorSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("host supervisor snapshot was rejected")
    }
}

impl Error for SupervisorSnapshotError {}

/// Stable execution error without arbitrary controller diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorError {
    HostBoundaryMismatch,
    StaleRevision { current: HostRevisionFence },
    OperationConflict,
    PendingOperation,
    ConnectorNotFound,
    ConnectorRemoved,
    ConnectorMustBeStopped,
    AdapterMismatch,
    ReleaseCapabilityMismatch,
    RevisionExhausted,
    CredentialGenerationExhausted,
    CredentialRequired,
    CredentialUnchanged,
    SnapshotDiverged,
    InvalidProcessObservation,
    Journal(PortError),
    ReleaseCatalog(PortError),
    CredentialArtifact(PortError),
    Process(PortError),
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("host supervisor command failed")
    }
}

impl Error for SupervisorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(error)
            | Self::ReleaseCatalog(error)
            | Self::CredentialArtifact(error)
            | Self::Process(error) => Some(error),
            Self::HostBoundaryMismatch
            | Self::StaleRevision { .. }
            | Self::OperationConflict
            | Self::PendingOperation
            | Self::ConnectorNotFound
            | Self::ConnectorRemoved
            | Self::ConnectorMustBeStopped
            | Self::AdapterMismatch
            | Self::ReleaseCapabilityMismatch
            | Self::RevisionExhausted
            | Self::CredentialGenerationExhausted
            | Self::CredentialRequired
            | Self::CredentialUnchanged
            | Self::SnapshotDiverged
            | Self::InvalidProcessObservation => None,
        }
    }
}
