use std::{cell::RefCell, collections::BTreeMap, rc::Rc, str::FromStr};

use dtx_agent_host::{AgentHost, ReportedHealth};
use dtx_agent_host_supervisor::{
    BootstrapCredentialFacts, BootstrapMaterialProvider, CatalogRelease, CommandApplication,
    CommandDisposition, CommandResult, ConnectorLifecycleFacts, ConnectorProcessState,
    CredentialArtifactProvider, CredentialArtifactRef, FinalizedMaterialProof, HostCommand,
    HostCommandEnvelope, HostOperationId, HostRevisionFence, HostSupervisor, InstallState,
    InstallStateJournal, Journal, JournalRecord, ManagedConnectorDesiredState, OperationIntent,
    OperationReceipt, PortError, PortErrorKind, PrepareMaterialResult, PreparedMaterialProof,
    ProcessController, ProcessMutationId, ProcessMutationPhase, ProcessObservation, ReleaseCatalog,
    ReleaseDigest, RemovalPolicy, ResourceProfile, SupervisorError, SupervisorSnapshot,
    SupervisorSnapshotError,
};
use dtx_connect_registry::AdapterKind;
use dtx_domain::{ConnectorId, HostCredentialId, HostId, IdentityId, Revision, TenantId};

const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

#[derive(Clone, Default)]
struct SharedJournal(Rc<RefCell<BTreeMap<HostOperationId, JournalRecord>>>);

#[derive(Clone, Default)]
struct SharedSnapshot(Rc<RefCell<Option<SupervisorSnapshot>>>);

#[derive(Clone, Default)]
struct FakeJournal {
    records: SharedJournal,
    snapshot: SharedSnapshot,
    install_state: Option<InstallState>,
}

#[derive(Default)]
struct FakeMaterial {
    calls: usize,
    expired: bool,
    fail: bool,
    wrong: bool,
    credential_revision: Option<Revision>,
}
impl BootstrapMaterialProvider for FakeMaterial {
    fn prepare(
        &mut self,
        _operation_id: HostOperationId,
        facts: ConnectorLifecycleFacts,
        _release: CatalogRelease,
    ) -> Result<PrepareMaterialResult, PortError> {
        self.calls += 1;
        if self.fail {
            return Err(PortError::new(PortErrorKind::Unavailable));
        }
        if self.expired {
            return Ok(PrepareMaterialResult::ExpiredUnclaimed);
        }
        Ok(PrepareMaterialResult::Prepared(PreparedMaterialProof {
            facts,
            prepared_receipt: dtx_agent_host_supervisor::PreparedReceiptDigest::from_bytes([9; 32]),
            credentials: BootstrapCredentialFacts {
                generation: 1,
                revision: self
                    .credential_revision
                    .unwrap_or(Revision::new(2).unwrap()),
                credential_ref: CredentialArtifactRef::from_bytes([7; 32]),
                mcp_bearer_ref: dtx_agent_host_supervisor::McpBearerRef::from_bytes([8; 32]),
            },
            observation: ProcessObservation::Stopped,
        }))
    }
    fn finalize(
        &mut self,
        _operation_id: HostOperationId,
        facts: ConnectorLifecycleFacts,
        prepared_receipt: dtx_agent_host_supervisor::PreparedReceiptDigest,
        _release: CatalogRelease,
    ) -> Result<FinalizedMaterialProof, PortError> {
        self.calls += 1;
        Ok(FinalizedMaterialProof {
            facts,
            prepared_receipt,
            finalized_receipt: dtx_agent_host_supervisor::FinalizedReceiptDigest::from_bytes(
                [10; 32],
            ),
            credentials: BootstrapCredentialFacts {
                generation: 1,
                revision: Revision::new(2).unwrap(),
                credential_ref: CredentialArtifactRef::from_bytes(if self.wrong {
                    [6; 32]
                } else {
                    [7; 32]
                }),
                mcp_bearer_ref: dtx_agent_host_supervisor::McpBearerRef::from_bytes([8; 32]),
            },
            observation: ProcessObservation::Running,
        })
    }
}

impl Journal for FakeJournal {
    fn lookup(
        &mut self,
        _host_id: HostId,
        operation_id: HostOperationId,
    ) -> Result<Option<JournalRecord>, PortError> {
        Ok(self.records.0.borrow().get(&operation_id).cloned())
    }

    fn load_snapshot(&mut self, _host_id: HostId) -> Result<Option<SupervisorSnapshot>, PortError> {
        Ok(self.snapshot.0.borrow().clone())
    }

    fn persist_intent(
        &mut self,
        intent: OperationIntent,
        predecessor: &SupervisorSnapshot,
    ) -> Result<(), PortError> {
        let mut snapshot = self.snapshot.0.borrow_mut();
        if snapshot
            .as_ref()
            .is_some_and(|current| current != predecessor)
        {
            return Err(PortError::new(PortErrorKind::Conflict));
        }
        let mut records = self.records.0.borrow_mut();
        match records.get(&intent.operation_id()) {
            None => {
                records.insert(intent.operation_id(), JournalRecord::Pending(intent));
                *snapshot = Some(predecessor.clone());
                Ok(())
            }
            Some(JournalRecord::Pending(existing)) if existing == &intent => Ok(()),
            Some(JournalRecord::Completed {
                intent: completed_intent,
                receipt,
            }) if completed_intent == &intent
                && receipt.operation_id() == intent.operation_id()
                && receipt.command_digest() == intent.command_digest() =>
            {
                Ok(())
            }
            Some(_) => Err(PortError::new(PortErrorKind::Conflict)),
        }
    }

    fn complete(
        &mut self,
        receipt: OperationReceipt,
        resulting: &SupervisorSnapshot,
    ) -> Result<(), PortError> {
        let mut records = self.records.0.borrow_mut();
        let Some(JournalRecord::Pending(intent)) = records.get(&receipt.operation_id()) else {
            return Err(PortError::new(PortErrorKind::Conflict));
        };
        if intent.command_digest() != receipt.command_digest() {
            return Err(PortError::new(PortErrorKind::Conflict));
        }
        let intent = intent.clone();
        records.insert(
            receipt.operation_id(),
            JournalRecord::Completed { intent, receipt },
        );
        *self.snapshot.0.borrow_mut() = Some(resulting.clone());
        Ok(())
    }

    fn pending(&mut self, host_id: HostId) -> Result<Vec<OperationIntent>, PortError> {
        Ok(self
            .records
            .0
            .borrow()
            .values()
            .filter_map(|record| match record {
                JournalRecord::Pending(intent) if intent.host_id() == host_id => {
                    Some(intent.clone())
                }
                JournalRecord::Pending(_) | JournalRecord::Completed { .. } => None,
            })
            .collect())
    }
}

impl InstallStateJournal for FakeJournal {
    fn load_install_state(
        &mut self,
        _host_id: HostId,
        _connector_id: ConnectorId,
    ) -> Result<Option<InstallState>, PortError> {
        Ok(self.install_state)
    }
}

#[derive(Default)]
struct FakeCatalog {
    known: Vec<CatalogRelease>,
    runnable: Vec<CatalogRelease>,
}

impl FakeCatalog {
    fn approve(&mut self, release: CatalogRelease) {
        if !self.known.contains(&release) {
            self.known.push(release);
        }
        if !self.runnable.contains(&release) {
            self.runnable.push(release);
        }
    }

    fn revoke(&mut self, release: CatalogRelease) {
        self.runnable.retain(|candidate| *candidate != release);
    }
}

impl ReleaseCatalog for FakeCatalog {
    fn resolve_known(
        &mut self,
        adapter_kind: AdapterKind,
        digest: ReleaseDigest,
    ) -> Result<CatalogRelease, PortError> {
        self.known
            .iter()
            .copied()
            .find(|release| release.adapter_kind() == adapter_kind && release.digest() == digest)
            .ok_or_else(|| PortError::new(PortErrorKind::NotApproved))
    }

    fn resolve_runnable(
        &mut self,
        adapter_kind: AdapterKind,
        digest: ReleaseDigest,
    ) -> Result<CatalogRelease, PortError> {
        self.runnable
            .iter()
            .copied()
            .find(|release| release.adapter_kind() == adapter_kind && release.digest() == digest)
            .ok_or_else(|| PortError::new(PortErrorKind::NotApproved))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FakeCredentialArtifact(CredentialArtifactRef);

#[derive(Default)]
struct FakeCredentials {
    journal: SharedJournal,
    requested: Vec<(HostOperationId, ConnectorId, CredentialArtifactRef)>,
}

impl FakeCredentials {
    fn with_journal(journal: SharedJournal) -> Self {
        Self {
            journal,
            ..Self::default()
        }
    }
}

impl CredentialArtifactProvider for FakeCredentials {
    type Artifact = FakeCredentialArtifact;

    fn materialize(
        &mut self,
        operation_id: HostOperationId,
        target: dtx_agent_host_supervisor::ConnectorTarget,
        reference: CredentialArtifactRef,
    ) -> Result<Self::Artifact, PortError> {
        assert!(matches!(
            self.journal.0.borrow().get(&operation_id),
            Some(JournalRecord::Pending(_))
        ));
        self.requested
            .push((operation_id, target.connector_id(), reference));
        Ok(FakeCredentialArtifact(reference))
    }
}

#[derive(Default)]
struct FakeProcessController {
    journal: SharedJournal,
    calls: Vec<(ProcessMutationId, ConnectorId, ConnectorProcessState)>,
    logical_effects: BTreeMap<ProcessMutationId, ConnectorProcessState>,
    observations: BTreeMap<ConnectorId, ProcessObservation>,
    ensured_releases: BTreeMap<ConnectorId, CatalogRelease>,
    fail_once: Option<ProcessMutationId>,
    observe_calls: Vec<ConnectorId>,
    restore_calls: Vec<(ProcessMutationId, ConnectorId)>,
}

impl FakeProcessController {
    fn with_journal(journal: SharedJournal) -> Self {
        Self {
            journal,
            ..Self::default()
        }
    }

    fn fail_once_after_effect(&mut self, mutation_id: ProcessMutationId) {
        self.fail_once = Some(mutation_id);
    }

    fn apply(
        &mut self,
        mutation_id: ProcessMutationId,
        connector_id: ConnectorId,
        state: ConnectorProcessState,
        observation: ProcessObservation,
    ) -> Result<ProcessObservation, PortError> {
        assert!(matches!(
            self.journal.0.borrow().get(&mutation_id.operation_id()),
            Some(JournalRecord::Pending(_))
        ));
        if self
            .logical_effects
            .get(&mutation_id)
            .is_some_and(|existing| *existing != state)
        {
            return Err(PortError::new(PortErrorKind::Conflict));
        }
        self.calls.push((mutation_id, connector_id, state));
        self.logical_effects.entry(mutation_id).or_insert(state);
        self.observations.insert(connector_id, observation);
        if self.fail_once == Some(mutation_id) {
            self.fail_once = None;
            return Err(PortError::new(PortErrorKind::Unavailable));
        }
        Ok(observation)
    }
}

impl ProcessController<FakeCredentialArtifact> for FakeProcessController {
    fn ensure(
        &mut self,
        mutation_id: ProcessMutationId,
        target: dtx_agent_host_supervisor::ConnectorTarget,
        release: CatalogRelease,
    ) -> Result<ProcessObservation, PortError> {
        self.ensured_releases.insert(target.connector_id(), release);
        self.apply(
            mutation_id,
            target.connector_id(),
            ConnectorProcessState::Ensured,
            ProcessObservation::Stopped,
        )
    }

    fn start(
        &mut self,
        mutation_id: ProcessMutationId,
        target: dtx_agent_host_supervisor::ConnectorTarget,
        _release: CatalogRelease,
        _credential_ref: CredentialArtifactRef,
    ) -> Result<ProcessObservation, PortError> {
        self.apply(
            mutation_id,
            target.connector_id(),
            ConnectorProcessState::Running,
            ProcessObservation::Running,
        )
    }

    fn stop(
        &mut self,
        mutation_id: ProcessMutationId,
        target: dtx_agent_host_supervisor::ConnectorTarget,
    ) -> Result<ProcessObservation, PortError> {
        self.apply(
            mutation_id,
            target.connector_id(),
            ConnectorProcessState::Stopped,
            ProcessObservation::Stopped,
        )
    }

    fn restart(
        &mut self,
        mutation_id: ProcessMutationId,
        target: dtx_agent_host_supervisor::ConnectorTarget,
        _release: CatalogRelease,
        _credential_ref: CredentialArtifactRef,
    ) -> Result<ProcessObservation, PortError> {
        self.apply(
            mutation_id,
            target.connector_id(),
            ConnectorProcessState::Running,
            ProcessObservation::Running,
        )
    }

    fn restore_installed_runtime(
        &mut self,
        mutation_id: ProcessMutationId,
        target: dtx_agent_host_supervisor::ConnectorTarget,
        _credential_ref: CredentialArtifactRef,
        _bearer_ref: dtx_agent_host_supervisor::McpBearerRef,
    ) -> Result<(), PortError> {
        assert!(matches!(
            self.journal.0.borrow().get(&mutation_id.operation_id()),
            Some(JournalRecord::Pending(_))
        ));
        self.restore_calls
            .push((mutation_id, target.connector_id()));
        Ok(())
    }

    fn rotate_credential(
        &mut self,
        mutation_id: ProcessMutationId,
        target: dtx_agent_host_supervisor::ConnectorTarget,
        _credential_ref: CredentialArtifactRef,
        _artifact: &FakeCredentialArtifact,
    ) -> Result<ProcessObservation, PortError> {
        let observation = self
            .observations
            .get(&target.connector_id())
            .copied()
            .unwrap_or(ProcessObservation::Stopped);
        self.apply(
            mutation_id,
            target.connector_id(),
            ConnectorProcessState::CredentialRotated,
            observation,
        )
    }

    fn remove_retaining_data(
        &mut self,
        mutation_id: ProcessMutationId,
        target: dtx_agent_host_supervisor::ConnectorTarget,
    ) -> Result<ProcessObservation, PortError> {
        self.apply(
            mutation_id,
            target.connector_id(),
            ConnectorProcessState::RemovedRetainingData,
            ProcessObservation::Absent,
        )
    }

    fn observe(
        &mut self,
        target: dtx_agent_host_supervisor::ConnectorTarget,
    ) -> Result<ProcessObservation, PortError> {
        self.observe_calls.push(target.connector_id());
        let observation = self
            .observations
            .get(&target.connector_id())
            .copied()
            .unwrap_or(ProcessObservation::Absent);
        Ok(observation)
    }
}

fn active_host() -> AgentHost {
    let mut host = AgentHost::register(
        TenantId::new(),
        HostId::new(),
        IdentityId::from_str(OWNER_ID).unwrap(),
    );
    host.enroll(Revision::INITIAL, HostCredentialId::new())
        .unwrap();
    host
}

fn active_host_with_revision_lag() -> AgentHost {
    let mut host = active_host();
    let credential_id = host.credential_id().unwrap();
    host.advance_desired_revision(host.revision()).unwrap();
    host.record_heartbeat(
        host.revision(),
        credential_id,
        Revision::INITIAL,
        ReportedHealth::Healthy,
        1_000,
        1_000,
    )
    .unwrap();
    host
}

fn release(adapter_kind: AdapterKind, byte: u8, profile: ResourceProfile) -> CatalogRelease {
    CatalogRelease::approved(
        adapter_kind,
        ReleaseDigest::from_bytes([byte; 32]),
        profile,
        Revision::INITIAL,
    )
}

#[allow(clippy::large_types_passed_by_value)]
fn envelope(
    supervisor: &HostSupervisor,
    operation_id: HostOperationId,
    command: HostCommand,
) -> HostCommandEnvelope {
    HostCommandEnvelope::new(
        supervisor.tenant_id(),
        supervisor.host_id(),
        operation_id,
        supervisor.revision_fence(),
        command,
    )
}

fn install_facts(
    supervisor: &HostSupervisor,
    connector_id: ConnectorId,
    release: CatalogRelease,
) -> ConnectorLifecycleFacts {
    ConnectorLifecycleFacts::new(
        dtx_agent_host_supervisor::ConnectorLifecycleOperationId::new(),
        dtx_agent_host_supervisor::PlatformTarget::LinuxAmd64,
        release.adapter_kind(),
        release.digest(),
        supervisor.tenant_id(),
        supervisor.host_id(),
        connector_id,
        100,
        dtx_agent_host_supervisor::PlanDigest::from_bytes([1; 32]),
        dtx_agent_host_supervisor::HandoffDigest::from_bytes([2; 32]),
        dtx_agent_host_supervisor::ConfigDigest::from_bytes([3; 32]),
        dtx_agent_host_supervisor::TrustDigest::from_bytes([4; 32]),
        dtx_agent_host_supervisor::MaterialDigest::from_bytes([5; 32]),
    )
}

#[test]
fn expired_new_prepare_routes_to_the_provider_and_records_expired_unclaimed() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 77, ResourceProfile::Standard);
    let facts = install_facts(&supervisor, ConnectorId::new(), approved);
    let envelope = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::PrepareConnectorMaterial { facts },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut material = FakeMaterial {
        expired: true,
        ..Default::default()
    };
    let predecessor = supervisor.snapshot();
    let result = supervisor
        .prepare_connector_material(&envelope, &mut journal, &mut catalog, &mut material, 101)
        .unwrap();
    assert_eq!(
        result.outcome().disposition,
        CommandDisposition::ExpiredUnclaimed
    );
    assert_eq!(supervisor.snapshot(), predecessor);
    assert_eq!(material.calls, 1);
    assert!(matches!(
        journal
            .lookup(supervisor.host_id(), envelope.operation_id())
            .unwrap(),
        Some(JournalRecord::Completed { .. })
    ));
}

#[test]
fn pending_prepare_expiry_completes_unchanged_and_replays_without_provider() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 78, ResourceProfile::Standard);
    let facts = install_facts(&supervisor, ConnectorId::new(), approved);
    let command = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::PrepareConnectorMaterial { facts },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut material = FakeMaterial {
        fail: true,
        ..Default::default()
    };
    assert!(
        supervisor
            .prepare_connector_material(&command, &mut journal, &mut catalog, &mut material, 10)
            .is_err()
    );
    let predecessor = supervisor.snapshot();
    material.fail = false;
    material.expired = true;
    let terminal = supervisor
        .prepare_connector_material(&command, &mut journal, &mut catalog, &mut material, 101)
        .unwrap();
    assert_eq!(
        terminal.outcome().disposition,
        CommandDisposition::ExpiredUnclaimed
    );
    assert_eq!(supervisor.snapshot(), predecessor);
    let calls = material.calls;
    let replay = supervisor
        .prepare_connector_material(&command, &mut journal, &mut catalog, &mut material, 101)
        .unwrap();
    assert_eq!(replay.application(), CommandApplication::Replayed);
    assert_eq!(material.calls, calls);
}

#[test]
fn successful_prepare_replay_is_exact_and_adopts_opaque_refs() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 79, ResourceProfile::Standard);
    let facts = install_facts(&supervisor, ConnectorId::new(), approved);
    let command = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::PrepareConnectorMaterial { facts },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut material = FakeMaterial::default();
    let applied = supervisor
        .prepare_connector_material(&command, &mut journal, &mut catalog, &mut material, 10)
        .unwrap();
    assert_eq!(applied.application(), CommandApplication::Applied);
    assert!(
        supervisor
            .install_state(facts.connector_id())
            .unwrap()
            .is_prepared()
    );
    let calls = material.calls;
    let replay = supervisor
        .prepare_connector_material(&command, &mut journal, &mut catalog, &mut material, 10)
        .unwrap();
    assert_eq!(replay.application(), CommandApplication::Replayed);
    assert_eq!(material.calls, calls);
    assert_eq!(
        supervisor
            .adopted_mcp_bearer_ref(facts.connector_id())
            .unwrap()
            .as_bytes(),
        [8; 32]
    );
}

#[test]
fn installed_connector_rejects_v1_credential_rotation_without_poisoning_start_or_restart() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 83, ResourceProfile::Standard);
    let facts = install_facts(&supervisor, ConnectorId::new(), approved);
    let prepare = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::PrepareConnectorMaterial { facts },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut material = FakeMaterial::default();
    supervisor
        .prepare_connector_material(&prepare, &mut journal, &mut catalog, &mut material, 10)
        .unwrap();
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    let rejected = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::RotateCredential {
            connector_id: facts.connector_id(),
            credential_ref: CredentialArtifactRef::from_bytes([42; 32]),
        },
    );
    let snapshot_before = supervisor.snapshot();
    let credential_before = supervisor
        .instance(facts.connector_id())
        .unwrap()
        .credential_ref;
    let records_before = journal.records.0.borrow().len();
    assert_eq!(
        supervisor.execute(
            &rejected,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        ),
        Err(SupervisorError::InstallLifecycleConflict)
    );
    assert_eq!(journal.records.0.borrow().len(), records_before);
    assert_eq!(supervisor.snapshot(), snapshot_before);
    assert_eq!(
        supervisor
            .instance(facts.connector_id())
            .unwrap()
            .credential_ref,
        credential_before
    );
    assert!(credentials.requested.is_empty());
    assert!(controller.calls.is_empty());

    journal.install_state = supervisor.install_state(facts.connector_id());
    let mut reloaded =
        HostSupervisor::try_from_snapshot(&host, supervisor.snapshot(), &mut catalog).unwrap();
    reloaded
        .rehydrate_install_state(&mut journal, facts.connector_id())
        .unwrap();
    execute(
        &mut reloaded,
        HostCommand::Start {
            connector_id: facts.connector_id(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    execute(
        &mut reloaded,
        HostCommand::Restart {
            connector_id: facts.connector_id(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    assert_eq!(controller.restore_calls.len(), 2);
}

#[test]
fn uninstalled_connector_retains_v1_credential_rotation_behavior() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 84, ResourceProfile::Standard);
    let connector_id = ConnectorId::new();
    let credential_ref = CredentialArtifactRef::from_bytes([84; 32]);
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    execute(
        &mut supervisor,
        HostCommand::Ensure {
            connector_id,
            adapter_kind: AdapterKind::Codex,
            release_digest: approved.digest(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );

    let result = execute(
        &mut supervisor,
        HostCommand::RotateCredential {
            connector_id,
            credential_ref,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );

    assert_eq!(result.application(), CommandApplication::Applied);
    assert_eq!(
        supervisor.instance(connector_id).unwrap().credential_ref,
        Some(credential_ref)
    );
    assert_eq!(credentials.requested.len(), 1);
}

#[test]
fn historical_v1_rotation_replays_after_later_install_without_effects() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 85, ResourceProfile::Standard);
    let connector_id = ConnectorId::new();
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    execute(
        &mut supervisor,
        HostCommand::Ensure {
            connector_id,
            adapter_kind: AdapterKind::Codex,
            release_digest: approved.digest(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    let rotation = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::RotateCredential {
            connector_id,
            credential_ref: CredentialArtifactRef::from_bytes([85; 32]),
        },
    );
    let rotated = supervisor
        .execute(
            &rotation,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        )
        .unwrap();

    let facts = install_facts(&supervisor, connector_id, approved);
    let prepare = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::PrepareConnectorMaterial { facts },
    );
    let mut material = FakeMaterial::default();
    supervisor
        .prepare_connector_material(&prepare, &mut journal, &mut catalog, &mut material, 10)
        .unwrap();
    let snapshot_before_replay = supervisor.snapshot();
    let credential_calls_before_replay = credentials.requested.len();
    let process_calls_before_replay = controller.calls.len();

    let replay = supervisor
        .execute(
            &rotation,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        )
        .unwrap();

    assert_eq!(replay.application(), CommandApplication::Replayed);
    assert_eq!(replay.outcome(), rotated.outcome());
    assert_eq!(supervisor.snapshot(), snapshot_before_replay);
    assert_eq!(credentials.requested.len(), credential_calls_before_replay);
    assert_eq!(controller.calls.len(), process_calls_before_replay);
}

#[test]
fn installed_connector_fences_ensure_release_drift_but_accepts_the_exact_release() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 84, ResourceProfile::Standard);
    let replacement = release(AdapterKind::Codex, 85, ResourceProfile::Compute);
    let facts = install_facts(&supervisor, ConnectorId::new(), approved);
    let prepare = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::PrepareConnectorMaterial { facts },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    catalog.approve(replacement);
    let mut journal = FakeJournal::default();
    let mut material = FakeMaterial::default();
    supervisor
        .prepare_connector_material(&prepare, &mut journal, &mut catalog, &mut material, 10)
        .unwrap();
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    let drift = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::Ensure {
            connector_id: facts.connector_id(),
            adapter_kind: AdapterKind::Codex,
            release_digest: replacement.digest(),
        },
    );
    let records_before = journal.records.0.borrow().len();
    assert_eq!(
        supervisor.execute(
            &drift,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        ),
        Err(SupervisorError::InstallLifecycleConflict)
    );
    assert_eq!(journal.records.0.borrow().len(), records_before);
    assert!(controller.calls.is_empty());
    execute(
        &mut supervisor,
        HostCommand::Ensure {
            connector_id: facts.connector_id(),
            adapter_kind: AdapterKind::Codex,
            release_digest: approved.digest(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
}

#[test]
fn new_prepare_operation_after_prepared_conflicts_without_provider_call() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 81, ResourceProfile::Standard);
    let facts = install_facts(&supervisor, ConnectorId::new(), approved);
    let first = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::PrepareConnectorMaterial { facts },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut material = FakeMaterial::default();
    supervisor
        .prepare_connector_material(&first, &mut journal, &mut catalog, &mut material, 10)
        .unwrap();
    let calls = material.calls;
    let second = HostCommandEnvelope::new(
        supervisor.tenant_id(),
        supervisor.host_id(),
        HostOperationId::new(),
        supervisor.revision_fence(),
        HostCommand::PrepareConnectorMaterial { facts },
    );
    assert_eq!(
        supervisor
            .prepare_connector_material(&second, &mut journal, &mut catalog, &mut material, 10)
            .unwrap_err(),
        SupervisorError::InstallLifecycleConflict
    );
    assert_eq!(material.calls, calls);
}

#[test]
fn revoked_pending_prepare_uses_known_release_and_accepts_independent_credential_revision() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 82, ResourceProfile::Standard);
    let facts = install_facts(&supervisor, ConnectorId::new(), approved);
    let command = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::PrepareConnectorMaterial { facts },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut material = FakeMaterial {
        fail: true,
        credential_revision: Some(Revision::new(99).unwrap()),
        ..Default::default()
    };
    assert!(
        supervisor
            .prepare_connector_material(&command, &mut journal, &mut catalog, &mut material, 10)
            .is_err()
    );
    catalog.revoke(approved);
    material.fail = false;
    let result = supervisor
        .prepare_connector_material(&command, &mut journal, &mut catalog, &mut material, 10)
        .unwrap();
    assert_eq!(result.application(), CommandApplication::Applied);
    assert_eq!(
        supervisor
            .install_state(facts.connector_id())
            .unwrap()
            .facts(),
        facts
    );
}

#[test]
fn finalize_requires_running_and_replays_without_provider() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 80, ResourceProfile::Standard);
    let facts = install_facts(&supervisor, ConnectorId::new(), approved);
    let prepare = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::PrepareConnectorMaterial { facts },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut material = FakeMaterial::default();
    supervisor
        .prepare_connector_material(&prepare, &mut journal, &mut catalog, &mut material, 10)
        .unwrap();
    let finalize = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::FinalizeConnectorMaterial {
            facts,
            prepared_receipt: dtx_agent_host_supervisor::PreparedReceiptDigest::from_bytes([9; 32]),
        },
    );
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    assert_eq!(
        supervisor
            .finalize_connector_material(
                &finalize,
                &mut journal,
                &mut catalog,
                &mut material,
                &mut controller
            )
            .unwrap_err(),
        SupervisorError::InstallNotRunning
    );
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    execute(
        &mut supervisor,
        HostCommand::Start {
            connector_id: facts.connector_id(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    assert_eq!(controller.restore_calls.len(), 1);
    assert_eq!(controller.restore_calls[0].1, facts.connector_id());
    material.wrong = true;
    assert_eq!(
        supervisor
            .finalize_connector_material(
                &finalize,
                &mut journal,
                &mut catalog,
                &mut material,
                &mut controller,
            )
            .unwrap_err(),
        SupervisorError::InstallProofInvalid
    );
    material.wrong = false;
    let completed = supervisor
        .finalize_connector_material(
            &finalize,
            &mut journal,
            &mut catalog,
            &mut material,
            &mut controller,
        )
        .unwrap();
    assert_eq!(completed.application(), CommandApplication::Applied);
    let calls = material.calls;
    let replay = supervisor
        .finalize_connector_material(
            &finalize,
            &mut journal,
            &mut catalog,
            &mut material,
            &mut controller,
        )
        .unwrap();
    assert_eq!(replay.application(), CommandApplication::Replayed);
    assert_eq!(material.calls, calls);
}

#[test]
fn supervisor_inherits_host_revision_lag_and_mutation_advances_and_acks_once() {
    let host = active_host_with_revision_lag();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    assert_eq!(
        supervisor.revision_fence(),
        HostRevisionFence::new(2, Some(1)).unwrap()
    );

    let approved = release(AdapterKind::Codex, 11, ResourceProfile::Standard);
    let connector_id = ConnectorId::new();
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    execute(
        &mut supervisor,
        HostCommand::Ensure {
            connector_id,
            adapter_kind: AdapterKind::Codex,
            release_digest: approved.digest(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );

    assert_eq!(
        supervisor.revision_fence(),
        HostRevisionFence::new(3, Some(3)).unwrap()
    );
}

#[test]
fn command_is_durable_before_effect_and_replay_is_exact() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 1, ResourceProfile::Standard);
    let connector_id = ConnectorId::new();
    let operation_id = HostOperationId::new();
    let command = HostCommand::Ensure {
        connector_id,
        adapter_kind: AdapterKind::Codex,
        release_digest: approved.digest(),
    };
    let command = envelope(&supervisor, operation_id, command);
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());

    let applied = supervisor
        .execute(
            &command,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        )
        .unwrap();
    assert_eq!(applied.application(), CommandApplication::Applied);
    assert_eq!(controller.calls.len(), 1);
    assert_eq!(
        supervisor.revision_fence(),
        HostRevisionFence::new(2, Some(2)).unwrap()
    );
    assert_eq!(
        controller.ensured_releases.get(&connector_id),
        Some(&approved)
    );

    let replayed = supervisor
        .execute(
            &command,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        )
        .unwrap();
    assert_eq!(replayed.application(), CommandApplication::Replayed);
    assert_eq!(controller.calls.len(), 1);
    assert_eq!(replayed.outcome(), applied.outcome());

    let conflicting = HostCommandEnvelope::new(
        host.tenant_id(),
        host.host_id(),
        operation_id,
        supervisor.revision_fence(),
        HostCommand::Start { connector_id },
    );
    assert!(matches!(
        supervisor.execute(
            &conflicting,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        ),
        Err(SupervisorError::OperationConflict)
    ));

    let unapproved_operation = HostOperationId::new();
    let unapproved = envelope(
        &supervisor,
        unapproved_operation,
        HostCommand::Ensure {
            connector_id: ConnectorId::new(),
            adapter_kind: AdapterKind::Rig,
            release_digest: ReleaseDigest::from_bytes([9; 32]),
        },
    );
    assert!(matches!(
        supervisor.execute(
            &unapproved,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        ),
        Err(SupervisorError::ReleaseCatalog(_))
    ));
    assert!(
        journal
            .lookup(host.host_id(), unapproved_operation)
            .unwrap()
            .is_none()
    );
}

#[test]
fn completed_replay_from_old_snapshot_restores_state_without_process_effect() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let old_snapshot = supervisor.snapshot();
    let approved = release(AdapterKind::Codex, 12, ResourceProfile::Standard);
    let connector_id = ConnectorId::new();
    let operation_id = HostOperationId::new();
    let command = envelope(
        &supervisor,
        operation_id,
        HostCommand::Ensure {
            connector_id,
            adapter_kind: AdapterKind::Codex,
            release_digest: approved.digest(),
        },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let mut controller = FakeProcessController::with_journal(journal.records.clone());

    let first = supervisor
        .execute(
            &command,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        )
        .unwrap();
    let completed_snapshot = supervisor.snapshot();
    assert_eq!(
        journal.load_snapshot(host.host_id()).unwrap(),
        Some(completed_snapshot.clone())
    );
    assert_eq!(controller.calls.len(), 1);

    let mut restarted =
        HostSupervisor::try_from_snapshot(&host, old_snapshot, &mut catalog).unwrap();
    let replay = restarted
        .execute(
            &command,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        )
        .unwrap();

    assert_eq!(replay.application(), CommandApplication::Replayed);
    assert_eq!(replay.outcome(), first.outcome());
    assert_eq!(restarted.snapshot(), completed_snapshot);
    assert_eq!(controller.calls.len(), 1);
    assert!(matches!(
        journal.lookup(host.host_id(), operation_id).unwrap(),
        Some(JournalRecord::Completed { intent, receipt })
            if intent.operation_id() == receipt.operation_id()
    ));
}

#[test]
fn historical_exact_replay_returns_receipt_without_rolling_state_back() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 14, ResourceProfile::Standard);
    let connector_id = ConnectorId::new();
    let ensure_operation = HostOperationId::new();
    let ensure = envelope(
        &supervisor,
        ensure_operation,
        HostCommand::Ensure {
            connector_id,
            adapter_kind: AdapterKind::Codex,
            release_digest: approved.digest(),
        },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    let ensure_result = supervisor
        .execute(
            &ensure,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        )
        .unwrap();
    let missing_credential_operation = HostOperationId::new();
    let missing_credential = envelope(
        &supervisor,
        missing_credential_operation,
        HostCommand::Start { connector_id },
    );
    assert_eq!(
        supervisor.execute(
            &missing_credential,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        ),
        Err(SupervisorError::CredentialRequired)
    );
    assert!(
        journal
            .lookup(host.host_id(), missing_credential_operation)
            .unwrap()
            .is_none()
    );
    execute(
        &mut supervisor,
        HostCommand::RotateCredential {
            connector_id,
            credential_ref: CredentialArtifactRef::from_bytes([14; 32]),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    execute(
        &mut supervisor,
        HostCommand::Start { connector_id },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    let current = supervisor.snapshot();
    let process_calls = controller.calls.len();

    let replay = supervisor
        .execute(
            &ensure,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        )
        .unwrap();

    assert_eq!(replay.application(), CommandApplication::Replayed);
    assert_eq!(replay.outcome(), ensure_result.outcome());
    assert_eq!(supervisor.snapshot(), current);
    assert_eq!(controller.calls.len(), process_calls);
}

#[test]
fn completed_replay_uses_known_history_after_current_release_revocation() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 15, ResourceProfile::Standard);
    let connector_id = ConnectorId::new();
    let command = envelope(
        &supervisor,
        HostOperationId::new(),
        HostCommand::Ensure {
            connector_id,
            adapter_kind: AdapterKind::Codex,
            release_digest: approved.digest(),
        },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    supervisor
        .execute(
            &command,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        )
        .unwrap();
    catalog.revoke(approved);

    let replay = supervisor
        .execute(
            &command,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        )
        .expect("durable completed receipt survives current policy revocation");
    assert_eq!(replay.application(), CommandApplication::Replayed);
    assert_eq!(controller.calls.len(), 1);
}

#[derive(Clone, Copy, Debug)]
enum PolicyBlockedCase {
    Start,
    Restart,
}

impl PolicyBlockedCase {
    const fn command(self, connector_id: ConnectorId) -> HostCommand {
        match self {
            Self::Start => HostCommand::Start { connector_id },
            Self::Restart => HostCommand::Restart { connector_id },
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One table-driven crash/retry contract keeps Start and Restart identical.
fn revoked_pending_start_and_restart_use_an_idempotent_distinct_compensation_phase() {
    for case in [PolicyBlockedCase::Start, PolicyBlockedCase::Restart] {
        let host = active_host();
        let mut supervisor = HostSupervisor::new(&host).unwrap();
        let approved = release(AdapterKind::Codex, 24, ResourceProfile::Standard);
        let connector_id = ConnectorId::new();
        let sibling_id = ConnectorId::new();
        let mut catalog = FakeCatalog::default();
        catalog.approve(approved);
        let mut journal = FakeJournal::default();
        let mut credentials = FakeCredentials::with_journal(journal.records.clone());
        let mut controller = FakeProcessController::with_journal(journal.records.clone());
        for current in [connector_id, sibling_id] {
            execute(
                &mut supervisor,
                HostCommand::Ensure {
                    connector_id: current,
                    adapter_kind: AdapterKind::Codex,
                    release_digest: approved.digest(),
                },
                &mut journal,
                &mut catalog,
                &mut credentials,
                &mut controller,
            );
        }
        execute(
            &mut supervisor,
            HostCommand::RotateCredential {
                connector_id,
                credential_ref: CredentialArtifactRef::from_bytes([0x44; 32]),
            },
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        );
        if matches!(case, PolicyBlockedCase::Restart) {
            execute(
                &mut supervisor,
                HostCommand::Start { connector_id },
                &mut journal,
                &mut catalog,
                &mut credentials,
                &mut controller,
            );
        }
        let sibling_before = *supervisor.instance(sibling_id).unwrap();
        let operation_id = HostOperationId::new();
        let requested = ProcessMutationId::requested(operation_id);
        let compensation = ProcessMutationId::policy_compensation(operation_id);
        let command = envelope(&supervisor, operation_id, case.command(connector_id));
        assert_ne!(requested, compensation, "{case:?}");
        assert_eq!(requested.operation_id(), compensation.operation_id());
        assert_eq!(requested.phase(), ProcessMutationPhase::RequestedEffect);
        assert_eq!(
            compensation.phase(),
            ProcessMutationPhase::PolicyCompensation
        );

        controller.fail_once_after_effect(requested);
        assert!(
            matches!(
                supervisor.execute(
                    &command,
                    &mut journal,
                    &mut catalog,
                    &mut credentials,
                    &mut controller,
                ),
                Err(SupervisorError::Process(_))
            ),
            "{case:?}"
        );
        assert_eq!(*supervisor.instance(sibling_id).unwrap(), sibling_before);
        catalog.revoke(approved);

        controller.fail_once_after_effect(compensation);
        assert!(
            matches!(
                supervisor.reconcile(
                    &mut journal,
                    &mut catalog,
                    &mut credentials,
                    &mut controller,
                ),
                Err(SupervisorError::Process(_))
            ),
            "{case:?}"
        );
        assert_eq!(journal.pending(supervisor.host_id()).unwrap().len(), 1);
        assert_eq!(*supervisor.instance(sibling_id).unwrap(), sibling_before);

        let [blocked] = supervisor
            .reconcile(
                &mut journal,
                &mut catalog,
                &mut credentials,
                &mut controller,
            )
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            blocked.outcome().disposition,
            CommandDisposition::PolicyBlocked,
            "{case:?}"
        );
        assert_eq!(
            blocked.outcome().desired_state,
            ManagedConnectorDesiredState::Stopped,
            "{case:?}"
        );
        assert_eq!(blocked.outcome().observation, ProcessObservation::Stopped);
        assert!(journal.pending(supervisor.host_id()).unwrap().is_empty());
        assert_eq!(*supervisor.instance(sibling_id).unwrap(), sibling_before);
        assert_eq!(
            controller.logical_effects.get(&requested),
            Some(&ConnectorProcessState::Running)
        );
        assert_eq!(
            controller.logical_effects.get(&compensation),
            Some(&ConnectorProcessState::Stopped)
        );
        assert_eq!(
            controller
                .calls
                .iter()
                .filter(|(mutation_id, _, _)| mutation_id.operation_id() == operation_id)
                .map(|(mutation_id, _, state)| (mutation_id.phase(), *state))
                .collect::<Vec<_>>(),
            vec![
                (
                    ProcessMutationPhase::RequestedEffect,
                    ConnectorProcessState::Running,
                ),
                (
                    ProcessMutationPhase::PolicyCompensation,
                    ConnectorProcessState::Stopped,
                ),
                (
                    ProcessMutationPhase::PolicyCompensation,
                    ConnectorProcessState::Stopped,
                ),
            ],
            "{case:?}"
        );

        let completed_snapshot = journal.load_snapshot(host.host_id()).unwrap().unwrap();
        let calls_before_replay = controller.calls.len();
        let mut restarted =
            HostSupervisor::try_from_snapshot(&host, completed_snapshot.clone(), &mut catalog)
                .unwrap();
        let replay = restarted
            .execute(
                &command,
                &mut journal,
                &mut catalog,
                &mut credentials,
                &mut controller,
            )
            .unwrap();
        assert_eq!(replay.application(), CommandApplication::Replayed);
        assert_eq!(replay.outcome(), blocked.outcome());
        assert_eq!(controller.calls.len(), calls_before_replay);
        assert_eq!(restarted.snapshot(), completed_snapshot);
        assert_eq!(*restarted.instance(sibling_id).unwrap(), sibling_before);
    }
}

#[test]
fn ensure_rejects_a_running_connector_before_persisting_an_intent() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let initial = release(AdapterKind::Codex, 16, ResourceProfile::Standard);
    let replacement = release(AdapterKind::Codex, 17, ResourceProfile::Compute);
    let connector_id = ConnectorId::new();
    let mut catalog = FakeCatalog::default();
    catalog.approve(initial);
    catalog.approve(replacement);
    let mut journal = FakeJournal::default();
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    execute(
        &mut supervisor,
        HostCommand::Ensure {
            connector_id,
            adapter_kind: AdapterKind::Codex,
            release_digest: initial.digest(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    execute(
        &mut supervisor,
        HostCommand::RotateCredential {
            connector_id,
            credential_ref: CredentialArtifactRef::from_bytes([16; 32]),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    execute(
        &mut supervisor,
        HostCommand::Start { connector_id },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    let operation_id = HostOperationId::new();
    let command = envelope(
        &supervisor,
        operation_id,
        HostCommand::Ensure {
            connector_id,
            adapter_kind: AdapterKind::Codex,
            release_digest: replacement.digest(),
        },
    );

    assert_eq!(
        supervisor.execute(
            &command,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        ),
        Err(SupervisorError::ConnectorMustBeStopped)
    );
    assert!(
        journal
            .lookup(host.host_id(), operation_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(supervisor.instance(connector_id).unwrap().release, initial);
}

#[test]
fn pending_running_ensure_is_rejected_before_another_process_effect() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let initial = release(AdapterKind::Codex, 43, ResourceProfile::Standard);
    let replacement = release(AdapterKind::Codex, 44, ResourceProfile::Compute);
    let connector_id = ConnectorId::new();
    let mut catalog = FakeCatalog::default();
    catalog.approve(initial);
    catalog.approve(replacement);
    let mut journal = FakeJournal::default();
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    execute(
        &mut supervisor,
        HostCommand::Ensure {
            connector_id,
            adapter_kind: AdapterKind::Codex,
            release_digest: initial.digest(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    execute(
        &mut supervisor,
        HostCommand::RotateCredential {
            connector_id,
            credential_ref: CredentialArtifactRef::from_bytes([43; 32]),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    let predecessor = supervisor.snapshot();
    let operation_id = HostOperationId::new();
    let command = envelope(
        &supervisor,
        operation_id,
        HostCommand::Ensure {
            connector_id,
            adapter_kind: AdapterKind::Codex,
            release_digest: replacement.digest(),
        },
    );
    controller.fail_once_after_effect(ProcessMutationId::requested(operation_id));
    assert!(matches!(
        supervisor.execute(
            &command,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        ),
        Err(SupervisorError::Process(_))
    ));

    let mut forged_running = predecessor;
    let instance = forged_running
        .instances
        .iter_mut()
        .find(|instance| instance.connector_id == connector_id)
        .unwrap();
    instance.desired_state = ManagedConnectorDesiredState::Running;
    instance.observation = ProcessObservation::Running;
    let mut restarted =
        HostSupervisor::try_from_snapshot(&host, forged_running, &mut catalog).unwrap();
    let calls_before_reconcile = controller.calls.len();
    assert_eq!(
        restarted.reconcile(
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        ),
        Err(SupervisorError::ConnectorMustBeStopped)
    );
    assert_eq!(controller.calls.len(), calls_before_reconcile);
}

#[test]
fn a_pending_host_intent_blocks_every_different_operation() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 13, ResourceProfile::Standard);
    let pending_operation = HostOperationId::new();
    let pending_connector = ConnectorId::new();
    let command = envelope(
        &supervisor,
        pending_operation,
        HostCommand::Ensure {
            connector_id: pending_connector,
            adapter_kind: AdapterKind::Codex,
            release_digest: approved.digest(),
        },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    controller.fail_once_after_effect(ProcessMutationId::requested(pending_operation));

    assert!(matches!(
        supervisor.execute(
            &command,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        ),
        Err(SupervisorError::Process(_))
    ));

    let other_operation = HostOperationId::new();
    let other = envelope(
        &supervisor,
        other_operation,
        HostCommand::Ensure {
            connector_id: ConnectorId::new(),
            adapter_kind: AdapterKind::Codex,
            release_digest: approved.digest(),
        },
    );
    assert_eq!(
        supervisor.execute(
            &other,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        ),
        Err(SupervisorError::PendingOperation)
    );
    assert_eq!(controller.calls.len(), 1);
    assert!(
        journal
            .lookup(host.host_id(), other_operation)
            .unwrap()
            .is_none()
    );
}

#[test]
fn pending_intent_reconciles_after_crash_without_duplicate_logical_effect() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let initial_snapshot = supervisor.snapshot();
    let approved = release(AdapterKind::OpenClawAcp, 2, ResourceProfile::Compute);
    let operation_id = HostOperationId::new();
    let connector_id = ConnectorId::new();
    let command = envelope(
        &supervisor,
        operation_id,
        HostCommand::Ensure {
            connector_id,
            adapter_kind: AdapterKind::OpenClawAcp,
            release_digest: approved.digest(),
        },
    );
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    controller.fail_once_after_effect(ProcessMutationId::requested(operation_id));
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());

    assert!(matches!(
        supervisor.execute(
            &command,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        ),
        Err(SupervisorError::Process(_))
    ));
    assert!(matches!(
        journal.lookup(host.host_id(), operation_id).unwrap(),
        Some(JournalRecord::Pending(_))
    ));
    assert!(supervisor.instance(connector_id).is_none());

    let mut restarted =
        HostSupervisor::try_from_snapshot(&host, initial_snapshot, &mut catalog).unwrap();
    let reconciled = restarted
        .reconcile(
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        )
        .unwrap();
    assert_eq!(reconciled.len(), 1);
    assert_eq!(reconciled[0].application(), CommandApplication::Reconciled);
    assert_eq!(controller.calls.len(), 2);
    assert_eq!(controller.logical_effects.len(), 1);
    assert_eq!(
        restarted.instance(connector_id).unwrap().desired_state,
        ManagedConnectorDesiredState::EnsuredStopped
    );
    assert!(matches!(
        journal.lookup(host.host_id(), operation_id).unwrap(),
        Some(JournalRecord::Completed { .. })
    ));
}

#[test]
fn closed_commands_cover_lifecycle_and_never_mutate_a_sibling() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let codex = release(AdapterKind::Codex, 3, ResourceProfile::Standard);
    let eino = release(AdapterKind::Eino, 4, ResourceProfile::Compute);
    let mut catalog = FakeCatalog::default();
    catalog.approve(codex);
    catalog.approve(eino);
    let mut journal = FakeJournal::default();
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    let first = ConnectorId::new();
    let sibling = ConnectorId::new();

    execute(
        &mut supervisor,
        HostCommand::Ensure {
            connector_id: first,
            adapter_kind: AdapterKind::Codex,
            release_digest: codex.digest(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    execute(
        &mut supervisor,
        HostCommand::Ensure {
            connector_id: sibling,
            adapter_kind: AdapterKind::Eino,
            release_digest: eino.digest(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );
    let sibling_before = *supervisor.instance(sibling).unwrap();
    execute(
        &mut supervisor,
        HostCommand::RotateCredential {
            connector_id: first,
            credential_ref: CredentialArtifactRef::from_bytes([6; 32]),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );

    for command in lifecycle_commands(first) {
        execute(
            &mut supervisor,
            command,
            &mut journal,
            &mut catalog,
            &mut credentials,
            &mut controller,
        );
        assert_eq!(*supervisor.instance(sibling).unwrap(), sibling_before);
    }
    let before_observe = supervisor.snapshot();
    assert_eq!(
        supervisor.observe(sibling, &mut controller).unwrap(),
        ProcessObservation::Stopped
    );
    assert_eq!(supervisor.snapshot(), before_observe);
    assert_eq!(controller.observe_calls, vec![sibling]);
    assert_eq!(credentials.requested.len(), 2);
    assert_eq!(
        supervisor.instance(first).unwrap().desired_state,
        ManagedConnectorDesiredState::RemovedRetainingData
    );
    assert_eq!(
        supervisor.instance(first).unwrap().observation,
        ProcessObservation::Absent
    );
    assert_eq!(
        supervisor
            .instance(sibling)
            .unwrap()
            .release
            .resource_profile(),
        ResourceProfile::Compute
    );
}

fn lifecycle_commands(connector_id: ConnectorId) -> [HostCommand; 5] {
    [
        HostCommand::Start { connector_id },
        HostCommand::Stop { connector_id },
        HostCommand::Restart { connector_id },
        HostCommand::RotateCredential {
            connector_id,
            credential_ref: CredentialArtifactRef::from_bytes([7; 32]),
        },
        HostCommand::Remove {
            connector_id,
            policy: RemovalPolicy::RetainData,
        },
    ]
}

#[test]
fn snapshot_rehydration_rejects_wrong_host_duplicates_and_unapproved_release() {
    let host = active_host();
    let mut supervisor = HostSupervisor::new(&host).unwrap();
    let approved = release(AdapterKind::Codex, 5, ResourceProfile::Standard);
    let mut catalog = FakeCatalog::default();
    catalog.approve(approved);
    let mut journal = FakeJournal::default();
    let mut controller = FakeProcessController::with_journal(journal.records.clone());
    let mut credentials = FakeCredentials::with_journal(journal.records.clone());
    execute(
        &mut supervisor,
        HostCommand::Ensure {
            connector_id: ConnectorId::new(),
            adapter_kind: AdapterKind::Codex,
            release_digest: approved.digest(),
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut controller,
    );

    let mut wrong_host = supervisor.snapshot();
    wrong_host.host_id = HostId::new();
    assert_eq!(
        HostSupervisor::try_from_snapshot(&host, wrong_host, &mut catalog),
        Err(SupervisorSnapshotError::HostBoundaryMismatch)
    );

    let mut duplicate = supervisor.snapshot();
    duplicate.instances.push(duplicate.instances[0]);
    assert_eq!(
        HostSupervisor::try_from_snapshot(&host, duplicate, &mut catalog),
        Err(SupervisorSnapshotError::DuplicateConnector)
    );

    let mut observed_ahead = supervisor.snapshot();
    observed_ahead.desired_revision = Revision::INITIAL;
    observed_ahead.observed_revision = Some(Revision::new(2).unwrap());
    assert_eq!(
        HostSupervisor::try_from_snapshot(&host, observed_ahead, &mut catalog),
        Err(SupervisorSnapshotError::InvalidRevisionFence)
    );

    let mut impossible_state = supervisor.snapshot();
    impossible_state.instances[0].observation = ProcessObservation::Failed;
    assert_eq!(
        HostSupervisor::try_from_snapshot(&host, impossible_state, &mut catalog),
        Err(SupervisorSnapshotError::InvalidInstanceState)
    );

    let mut unreachable_initial = supervisor.snapshot();
    unreachable_initial.desired_revision = Revision::INITIAL;
    unreachable_initial.observed_revision = Some(Revision::INITIAL);
    assert_eq!(
        HostSupervisor::try_from_snapshot(&host, unreachable_initial, &mut catalog),
        Err(SupervisorSnapshotError::InvalidInstanceState)
    );

    catalog.revoke(approved);
    assert!(
        HostSupervisor::try_from_snapshot(&host, supervisor.snapshot(), &mut catalog).is_ok(),
        "known historical release metadata remains recoverable after revocation"
    );

    let mut unapproved = supervisor.snapshot();
    unapproved.instances[0].release = release(
        AdapterKind::Codex,
        99,
        unapproved.instances[0].release.resource_profile(),
    );
    assert!(matches!(
        HostSupervisor::try_from_snapshot(&host, unapproved, &mut catalog),
        Err(SupervisorSnapshotError::ReleaseNotApproved)
    ));
}

#[allow(clippy::large_types_passed_by_value)]
fn execute(
    supervisor: &mut HostSupervisor,
    command: HostCommand,
    journal: &mut FakeJournal,
    catalog: &mut FakeCatalog,
    credentials: &mut FakeCredentials,
    controller: &mut FakeProcessController,
) -> CommandResult {
    let envelope = envelope(supervisor, HostOperationId::new(), command);
    supervisor
        .execute(&envelope, journal, catalog, credentials, controller)
        .unwrap()
}
