#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{
        fs::{OpenOptionsExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use dtx_agent_host::AgentHost;
use dtx_agent_host_supervisor::{
    CatalogRelease, CredentialArtifactProvider, CredentialArtifactRef, FileJournal, HostCommand,
    HostCommandEnvelope, HostOperationId, HostSupervisor, Journal, JournalRecord,
    LinuxCredentialArtifact, LinuxProcessController, LinuxReconcileStatus, OperationIntent,
    OperationReceipt, PortError, PortErrorKind, ProcessObservation, ReleaseCatalog, ReleaseDigest,
    RemovalPolicy, ResourceProfile, SupervisorSnapshot,
};
use dtx_connect_registry::AdapterKind;
use dtx_domain::{ConnectorId, HostCredentialId, HostId, IdentityId, Revision, TenantId};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";
const TENANT_ID: &str = "01980f00-0000-7000-8000-000000000101";
const HOST_ID: &str = "01980f00-0000-7000-8000-000000000102";
const CODEX_ID: &str = "01980f00-0000-7000-8000-000000000103";
const OPENCLAW_ID: &str = "01980f00-0000-7000-8000-000000000104";
const DISPOSABLE_VM_ENV: &str = "DTX_DISPOSABLE_VM_ACCEPTANCE";
const FIXTURE_BINARY_ENV: &str = "DTX_CONNECT_FIXTURE_BINARY";
const HOST_BOUNDARY_FIXTURE_BINARY_ENV: &str = "DTX_HOST_BOUNDARY_FIXTURE_BINARY";
const CONTROL_SOCKET: &str = "/run/dirextalk/host-supervisor/control.sock";
const HOST_BOUNDARY_PROBE_TRIGGER: &str = "/run/dirextalk/host-supervisor/probe-nft-alone.trigger";
const IMDS_V4: &str = "169.254.169.254/32";
const IMDS_V6: &str = "fd00:ec2::254/128";
const WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const CRASH_LOOP_TIMEOUT: Duration = Duration::from_secs(40);
const WAIT_STEP: Duration = Duration::from_millis(100);

#[test]
#[ignore = "requires an isolated root Linux VM with systemd and cgroup v2"]
#[allow(clippy::too_many_lines)]
fn two_connectors_are_isolated_and_recover_an_intent_after_supervisor_crash() {
    assert!(
        matches!(std::env::var(DISPOSABLE_VM_ENV).as_deref(), Ok("1")),
        "refusing destructive acceptance without {DISPOSABLE_VM_ENV}=1"
    );
    assert_eq!(
        effective_uid(),
        0,
        "the VM acceptance gate must run as root"
    );
    let fixture_source = PathBuf::from(
        std::env::var_os(FIXTURE_BINARY_ENV)
            .expect("fixture binary path is provided by the VM gate"),
    );
    let fixture_bytes = fs::read(&fixture_source).expect("fixture binary is readable");
    let host_boundary_fixture = PathBuf::from(
        std::env::var_os(HOST_BOUNDARY_FIXTURE_BINARY_ENV)
            .expect("Host boundary fixture path is provided by the VM gate"),
    );
    let release_digest = ReleaseDigest::from_bytes(Sha256::digest(&fixture_bytes).into());
    let release_directory = release_directory(release_digest);
    let fixture_target = release_directory.join("dirextalk-agent-connector");
    let host_id = parse::<HostId>(HOST_ID);
    let codex_id = parse::<ConnectorId>(CODEX_ID);
    let openclaw_id = parse::<ConnectorId>(OPENCLAW_ID);
    collision_preflight(host_id, [codex_id, openclaw_id], &release_directory);
    let mut cleanup = Cleanup::new(host_id, [codex_id, openclaw_id], release_directory);
    provision_release(&fixture_source, &fixture_target);
    cleanup.imds_probe = Some(ImdsProbe::start());
    cleanup.control_listener = Some(provision_control_socket());
    assert_host_supervisor_boundary(&host_boundary_fixture);

    let mut host = AgentHost::register(
        parse::<TenantId>(TENANT_ID),
        host_id,
        IdentityId::from_str(OWNER_ID).expect("fixed owner identity"),
    );
    host.enroll(Revision::INITIAL, HostCredentialId::new())
        .expect("Host enrolls");
    let mut supervisor = HostSupervisor::new(&host).expect("active Host starts a supervisor");
    let codex_release = CatalogRelease::approved(
        AdapterKind::Codex,
        release_digest,
        ResourceProfile::Standard,
        Revision::INITIAL,
    );
    let openclaw_release = CatalogRelease::approved(
        AdapterKind::OpenClawAcp,
        release_digest,
        ResourceProfile::LowLatency,
        Revision::INITIAL,
    );
    let mut catalog = FixedCatalog::new([codex_release, openclaw_release]);
    let mut credentials = FixtureCredentials::default();
    let codex_v1 = credentials.register(b"generation=1\nadapter=codex\n");
    let openclaw_v1 = credentials.register(b"generation=1\nadapter=openclaw\n");
    let openclaw_v2 = credentials.register(b"generation=2\nadapter=openclaw\n");
    let mut journal = FileJournal::for_host(host_id);
    let mut process = LinuxProcessController::new();

    execute(
        &mut supervisor,
        HostCommand::Ensure {
            connector_id: codex_id,
            adapter_kind: AdapterKind::Codex,
            release_digest,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut process,
    );
    execute(
        &mut supervisor,
        HostCommand::RotateCredential {
            connector_id: codex_id,
            credential_ref: codex_v1,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut process,
    );
    execute(
        &mut supervisor,
        HostCommand::Start {
            connector_id: codex_id,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut process,
    );
    execute(
        &mut supervisor,
        HostCommand::Ensure {
            connector_id: openclaw_id,
            adapter_kind: AdapterKind::OpenClawAcp,
            release_digest,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut process,
    );
    execute(
        &mut supervisor,
        HostCommand::RotateCredential {
            connector_id: openclaw_id,
            credential_ref: openclaw_v1,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut process,
    );
    execute(
        &mut supervisor,
        HostCommand::Start {
            connector_id: openclaw_id,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut process,
    );

    let codex_initial = wait_for_state(codex_id, |state| state.credential_generation == 1);
    let openclaw_initial = wait_for_state(openclaw_id, |state| state.credential_generation == 1);
    assert_ne!(codex_initial.pid, openclaw_initial.pid);
    assert_ne!(codex_initial.uid, openclaw_initial.uid);
    assert!(codex_initial.cgroup.contains(&unit(codex_id)));
    assert!(openclaw_initial.cgroup.contains(&unit(openclaw_id)));
    assert!(!codex_initial.cgroup.contains(&openclaw_id.to_string()));
    assert!(!openclaw_initial.cgroup.contains(&codex_id.to_string()));
    assert_isolated(&codex_initial);
    assert_isolated(&openclaw_initial);
    assert_release_manifest(codex_id, "adapter=codex");
    assert_release_manifest(openclaw_id, "adapter=openclaw-acp");
    assert_distinct_credentials(codex_id, openclaw_id);

    execute(
        &mut supervisor,
        HostCommand::Restart {
            connector_id: codex_id,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut process,
    );
    let codex_restarted = wait_for_state(codex_id, |state| state.pid != codex_initial.pid);
    let openclaw_after_codex_restart = wait_for_state(openclaw_id, |_| true);
    assert_eq!(openclaw_after_codex_restart.pid, openclaw_initial.pid);

    execute(
        &mut supervisor,
        HostCommand::RotateCredential {
            connector_id: openclaw_id,
            credential_ref: openclaw_v2,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut process,
    );
    let openclaw_rotated = wait_for_state(openclaw_id, |state| state.credential_generation == 2);
    assert_eq!(openclaw_rotated.pid, openclaw_initial.pid);

    let predecessor = supervisor.snapshot();
    let restart_after_crash = envelope(
        &supervisor,
        HostCommand::Restart {
            connector_id: codex_id,
        },
    );
    let mut failing_journal = FailCompleteOnce::new(journal);
    let error = supervisor
        .execute(
            &restart_after_crash,
            &mut failing_journal,
            &mut catalog,
            &mut credentials,
            &mut process,
        )
        .expect_err("the injected crash leaves the post-effect intent pending");
    assert!(matches!(
        error,
        dtx_agent_host_supervisor::SupervisorError::Journal(_)
    ));
    let codex_after_effect = wait_for_state(codex_id, |state| state.pid != codex_restarted.pid);
    drop(supervisor);
    drop(failing_journal);

    let mut journal = FileJournal::for_host(host_id);
    assert_eq!(
        journal
            .load_snapshot(host_id)
            .expect("durable snapshot loads"),
        Some(predecessor)
    );
    let snapshot = journal
        .load_snapshot(host_id)
        .expect("durable snapshot loads")
        .expect("a predecessor snapshot was committed with the intent");
    let mut supervisor = HostSupervisor::try_from_snapshot(&host, snapshot, &mut catalog)
        .expect("validated snapshot rehydrates");
    let reconciled = supervisor
        .reconcile(&mut journal, &mut catalog, &mut credentials, &mut process)
        .expect("pending restart reconciles");
    assert_eq!(reconciled.len(), 1);
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        wait_for_state(codex_id, |_| true).pid,
        codex_after_effect.pid
    );

    let openclaw_before_reboot = wait_for_state(openclaw_id, |_| true);
    let snapshot_before_reboot = supervisor.snapshot();
    simulate_host_reboot([codex_id, openclaw_id]);
    let reboot_observations = process
        .reconcile_snapshot(&snapshot_before_reboot, &mut catalog)
        .expect("durable desired state reconciles after reboot");
    assert_eq!(reboot_observations.len(), 2);
    assert!(
        reboot_observations.iter().all(|observation| {
            observation.status() == LinuxReconcileStatus::CredentialRequired
        })
    );
    for connector_id in [codex_id, openclaw_id] {
        assert_eq!(
            process
                .restore_snapshot_credential(
                    &snapshot_before_reboot,
                    connector_id,
                    &mut credentials,
                )
                .expect("snapshot credential restores without a desired revision change"),
            ProcessObservation::Stopped
        );
    }
    let restored = process
        .reconcile_snapshot(&snapshot_before_reboot, &mut catalog)
        .expect("credential-complete snapshot starts both desired workers");
    assert!(restored.iter().all(|observation| {
        observation.status() == LinuxReconcileStatus::Observed(ProcessObservation::Running)
    }));
    assert_eq!(supervisor.snapshot(), snapshot_before_reboot);
    let codex_after_reboot = wait_for_state(codex_id, |state| {
        state.pid != codex_after_effect.pid && state.credential_generation == 1
    });
    let openclaw_after_reboot = wait_for_state(openclaw_id, |state| {
        state.pid != openclaw_before_reboot.pid && state.credential_generation == 2
    });
    assert_isolated(&codex_after_reboot);
    assert_isolated(&openclaw_after_reboot);

    let crash_flag = workspace_dir(openclaw_id).join("crash-loop");
    fs::write(&crash_flag, b"fixture crash loop").expect("crash loop fixture enables");
    wait_for_unit_state(openclaw_id, "failed", CRASH_LOOP_TIMEOUT);
    assert_eq!(
        wait_for_state(codex_id, |_| true).pid,
        codex_after_reboot.pid,
        "one crash loop does not restart its sibling"
    );
    let blocked = process
        .reconcile_snapshot(&supervisor.snapshot(), &mut catalog)
        .expect("ordinary reconcile records the crash-loop breaker");
    assert!(blocked.iter().any(|observation| {
        observation.connector_id() == openclaw_id
            && observation.status() == LinuxReconcileStatus::CrashLoopBlocked
    }));
    command(SYSTEMCTL, ["reset-failed", "--", &unit(openclaw_id)]);
    fs::remove_file(&crash_flag).expect("crash loop fixture clears");
    let still_blocked = process
        .reconcile_snapshot(&supervisor.snapshot(), &mut catalog)
        .expect("durable breaker survives systemd state reset");
    assert!(still_blocked.iter().any(|observation| {
        observation.connector_id() == openclaw_id
            && observation.status() == LinuxReconcileStatus::CrashLoopBlocked
    }));
    execute(
        &mut supervisor,
        HostCommand::Restart {
            connector_id: openclaw_id,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut process,
    );
    let openclaw_after_breaker_reset =
        wait_for_state(openclaw_id, |state| state.pid != openclaw_after_reboot.pid);
    assert_isolated(&openclaw_after_breaker_reset);

    let codex_before_release_revocation = wait_for_state(codex_id, |_| true);
    catalog.revoke(openclaw_release);
    for attempt in 0..2 {
        let observations = process
            .reconcile_snapshot(&supervisor.snapshot(), &mut catalog)
            .expect("a revoked running release reconciles fail closed");
        assert!(observations.iter().any(|observation| {
            observation.connector_id() == openclaw_id
                && observation.status() == LinuxReconcileStatus::ReleaseBlocked
        }));
        wait_for_unit_state(openclaw_id, "inactive", WAIT_TIMEOUT);
        assert_eq!(
            wait_for_state(openclaw_id, |_| true).pid,
            openclaw_after_breaker_reset.pid,
            "release revocation reconcile attempt {attempt} must not create a new invocation"
        );
        assert_eq!(
            wait_for_state(codex_id, |_| true).pid,
            codex_before_release_revocation.pid,
            "release revocation must not restart the sibling"
        );
    }

    let retained = data_dir(codex_id).join("retained.acceptance");
    fs::write(&retained, b"retain").expect("retained data fixture writes");
    execute(
        &mut supervisor,
        HostCommand::Remove {
            connector_id: codex_id,
            policy: RemovalPolicy::RetainData,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut process,
    );
    assert_eq!(
        supervisor
            .observe::<LinuxCredentialArtifact, _>(codex_id, &mut process)
            .expect("removed Connector observes"),
        ProcessObservation::Absent
    );
    assert_eq!(fs::read(&retained).expect("data was retained"), b"retain");
    assert_eq!(
        wait_for_state(openclaw_id, |_| true).pid,
        openclaw_after_breaker_reset.pid
    );

    execute(
        &mut supervisor,
        HostCommand::Remove {
            connector_id: openclaw_id,
            policy: RemovalPolicy::RetainData,
        },
        &mut journal,
        &mut catalog,
        &mut credentials,
        &mut process,
    );
    assert_eq!(
        supervisor
            .observe::<LinuxCredentialArtifact, _>(openclaw_id, &mut process)
            .expect("removed Connector observes"),
        ProcessObservation::Absent
    );
}

#[allow(clippy::large_types_passed_by_value)]
fn execute(
    supervisor: &mut HostSupervisor,
    command: HostCommand,
    journal: &mut impl Journal,
    catalog: &mut FixedCatalog,
    credentials: &mut FixtureCredentials,
    process: &mut LinuxProcessController,
) {
    let envelope = envelope(supervisor, command);
    supervisor
        .execute(&envelope, journal, catalog, credentials, process)
        .unwrap_or_else(|error| {
            panic!(
                "closed Host command {command:?} failed: {error:?}\n{}",
                unit_diagnostics(command.connector_id())
            )
        });
}

fn unit_diagnostics(connector_id: ConnectorId) -> String {
    let output = Command::new(SYSTEMCTL)
        .args([
            "show",
            "--no-pager",
            "--property=LoadState,ActiveState,Type,ExecStart,User,ControlGroup,Slice,IPAddressDeny,SyslogIdentifier,NoNewPrivileges,ProtectSystem,PrivateTmp,PrivateDevices,ProtectHome,ProtectKernelTunables,ProtectKernelModules,ProtectControlGroups,RestrictSUIDSGID,CapabilityBoundingSet,KillMode,MemoryMax,CPUQuotaPerSecUSec,TasksMax,IOAccounting,IOWeight,Restart,RestartUSec,StartLimitIntervalUSec,StartLimitBurst,OOMPolicy,StandardOutput,StandardError,LogRateLimitIntervalUSec,LogRateLimitBurst,UMask,WorkingDirectory,ReadWritePaths",
            "--",
            &unit(connector_id),
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    output.map_or_else(
        |_| "systemd diagnostics unavailable".to_owned(),
        |output| String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

#[allow(clippy::large_types_passed_by_value)]
fn envelope(supervisor: &HostSupervisor, command: HostCommand) -> HostCommandEnvelope {
    HostCommandEnvelope::new(
        supervisor.tenant_id(),
        supervisor.host_id(),
        HostOperationId::new(),
        supervisor.revision_fence(),
        command,
    )
}

struct FixedCatalog {
    known: Vec<CatalogRelease>,
    runnable: Vec<CatalogRelease>,
}

impl FixedCatalog {
    fn new(releases: impl IntoIterator<Item = CatalogRelease>) -> Self {
        let known = releases.into_iter().collect::<Vec<_>>();
        Self {
            runnable: known.clone(),
            known,
        }
    }

    fn revoke(&mut self, release: CatalogRelease) {
        self.runnable.retain(|candidate| *candidate != release);
    }
}

impl ReleaseCatalog for FixedCatalog {
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

#[derive(Default)]
struct FixtureCredentials {
    bodies: BTreeMap<[u8; 32], Vec<u8>>,
    next_reference: u8,
}

impl FixtureCredentials {
    fn register(&mut self, body: &[u8]) -> CredentialArtifactRef {
        self.next_reference = self
            .next_reference
            .checked_add(1)
            .expect("fixture reference");
        let reference = [self.next_reference; 32];
        self.bodies.insert(reference, body.to_vec());
        CredentialArtifactRef::from_bytes(reference)
    }
}

impl CredentialArtifactProvider for FixtureCredentials {
    type Artifact = LinuxCredentialArtifact;

    fn materialize(
        &mut self,
        operation_id: HostOperationId,
        target: dtx_agent_host_supervisor::ConnectorTarget,
        reference: CredentialArtifactRef,
    ) -> Result<Self::Artifact, PortError> {
        let body = self
            .bodies
            .get(&reference.as_bytes())
            .ok_or_else(|| PortError::new(PortErrorKind::NotApproved))?;
        let staged = LinuxCredentialArtifact::staged_path(operation_id, target);
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options
            .open(&staged)
            .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| file.write_all(body))
            .and_then(|()| file.sync_all())
            .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        File::open(
            staged
                .parent()
                .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?,
        )
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        LinuxCredentialArtifact::verify_staged(operation_id, target, reference)
    }
}

struct FailCompleteOnce<J> {
    inner: J,
    fail_complete: bool,
}

impl<J> FailCompleteOnce<J> {
    const fn new(inner: J) -> Self {
        Self {
            inner,
            fail_complete: true,
        }
    }
}

impl<J: Journal> Journal for FailCompleteOnce<J> {
    fn lookup(
        &mut self,
        host_id: HostId,
        operation_id: HostOperationId,
    ) -> Result<Option<JournalRecord>, PortError> {
        self.inner.lookup(host_id, operation_id)
    }

    fn load_snapshot(&mut self, host_id: HostId) -> Result<Option<SupervisorSnapshot>, PortError> {
        self.inner.load_snapshot(host_id)
    }

    fn persist_intent(
        &mut self,
        intent: OperationIntent,
        predecessor: &SupervisorSnapshot,
    ) -> Result<(), PortError> {
        self.inner.persist_intent(intent, predecessor)
    }

    fn complete(
        &mut self,
        receipt: OperationReceipt,
        resulting: &SupervisorSnapshot,
    ) -> Result<(), PortError> {
        if self.fail_complete {
            self.fail_complete = false;
            Err(PortError::new(PortErrorKind::Unavailable))
        } else {
            self.inner.complete(receipt, resulting)
        }
    }

    fn pending(&mut self, host_id: HostId) -> Result<Vec<OperationIntent>, PortError> {
        self.inner.pending(host_id)
    }
}

#[derive(Debug)]
struct FixtureState {
    pid: u32,
    uid: u32,
    credential_generation: u64,
    cgroup: String,
    isolation: [bool; 4],
}

fn wait_for_state(
    connector_id: ConnectorId,
    predicate: impl Fn(&FixtureState) -> bool,
) -> FixtureState {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        if let Ok(state) = read_state(connector_id)
            && predicate(&state)
        {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "Connector fixture state timed out"
        );
        thread::sleep(WAIT_STEP);
    }
}

fn wait_for_unit_state(connector_id: ConnectorId, expected: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let state = Command::new(SYSTEMCTL)
            .args([
                "show",
                "--property=ActiveState",
                "--value",
                "--",
                &unit(connector_id),
            ])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|value| value.trim().to_owned());
        if state.as_deref() == Some(expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "unit state did not reach {expected}"
        );
        thread::sleep(WAIT_STEP);
    }
}

fn read_state(connector_id: ConnectorId) -> Result<FixtureState, ()> {
    let value =
        fs::read_to_string(runtime_dir(connector_id).join("fixture.state")).map_err(|_| ())?;
    let fields = value
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect::<BTreeMap<_, _>>();
    Ok(FixtureState {
        pid: parse_field(&fields, "pid")?,
        uid: parse_field(&fields, "uid")?,
        credential_generation: parse_field(&fields, "credential_generation")?,
        cgroup: fields.get("cgroup").ok_or(())?.to_string(),
        isolation: [
            parse_field(&fields, "sibling_data_inaccessible")?,
            parse_field(&fields, "control_socket_inaccessible")?,
            parse_field(&fields, "imds_v4_inaccessible")?,
            parse_field(&fields, "imds_v6_inaccessible")?,
        ],
    })
}

fn parse_field<T: FromStr>(fields: &BTreeMap<&str, &str>, key: &str) -> Result<T, ()> {
    fields.get(key).ok_or(())?.parse().map_err(|_| ())
}

fn assert_isolated(state: &FixtureState) {
    assert!(
        state.isolation.into_iter().all(|denied| denied),
        "isolation evidence was not fully denied: {:?}",
        state.isolation
    );
}

fn assert_release_manifest(connector_id: ConnectorId, expected_adapter: &str) {
    let value = fs::read_to_string(config_dir(connector_id).join("release.manifest"))
        .expect("release manifest reads");
    assert!(value.lines().any(|line| line == expected_adapter));
}

fn assert_distinct_credentials(left: ConnectorId, right: ConnectorId) {
    let left = fs::read(credential_file(left)).expect("left credential reads");
    let right = fs::read(credential_file(right)).expect("right credential reads");
    assert!(
        Sha256::digest(left) != Sha256::digest(right),
        "sibling credentials must be distinct"
    );
}

fn provision_release(source: &Path, target: &Path) {
    fs::create_dir_all(target.parent().expect("release target has a parent"))
        .expect("release directory creates");
    fs::copy(source, target).expect("fixture release copies");
    fs::set_permissions(target, fs::Permissions::from_mode(0o755))
        .expect("fixture release is executable");
}

fn simulate_host_reboot(connector_ids: [ConnectorId; 2]) {
    for connector_id in connector_ids {
        command(SYSTEMCTL, ["stop", "--", &unit(connector_id)]);
        command(SYSTEMCTL, ["reset-failed", "--", &unit(connector_id)]);
        fs::remove_dir_all(PathBuf::from(format!(
            "/run/dirextalk/connect/{connector_id}"
        )))
        .expect("volatile Connector runtime is cleared by the reboot fixture");
    }
}

fn provision_control_socket() -> UnixListener {
    let path = Path::new(CONTROL_SOCKET);
    let parent = path.parent().expect("control socket has a parent");
    fs::create_dir_all(parent).expect("control socket directory creates");
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .expect("control socket directory is private");
    let listener = UnixListener::bind(path).expect("control socket fixture binds");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("control socket fixture is root-only");
    UnixStream::connect(path).expect("the root namespace can reach the control socket fixture");
    listener
}

fn assert_host_supervisor_boundary(fixture: &Path) {
    let status = Command::new(SYSTEMD_RUN)
        .args([
            format!("--unit={HOST_SUPERVISOR_UNIT}"),
            "--slice=system.slice".to_owned(),
            "--service-type=exec".to_owned(),
            "--property=NoNewPrivileges=yes".to_owned(),
            "--property=ProtectSystem=strict".to_owned(),
            "--property=ProtectHome=yes".to_owned(),
            "--property=PrivateTmp=yes".to_owned(),
            "--property=PrivateDevices=yes".to_owned(),
            "--property=IPAddressDeny=169.254.169.254/32".to_owned(),
            "--property=IPAddressDeny=fd00:ec2::254/128".to_owned(),
            "--property=CapabilityBoundingSet=CAP_NET_ADMIN".to_owned(),
            "--property=ReadWritePaths=/run/dirextalk/host-supervisor".to_owned(),
            "--".to_owned(),
            fixture.to_string_lossy().into_owned(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("Host Supervisor boundary unit launches");
    assert!(status.success(), "Host Supervisor boundary unit starts");

    let layered = wait_for_host_boundary_state(1);
    assert_host_boundary_denied(&layered);
    assert_eq!(
        unit_property(HOST_SUPERVISOR_UNIT, "ControlGroup"),
        "/system.slice/dirextalk-host-supervisor.service"
    );
    assert_eq!(unit_property(HOST_SUPERVISOR_UNIT, "Slice"), "system.slice");
    let mut address_denies = unit_property(HOST_SUPERVISOR_UNIT, "IPAddressDeny")
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    address_denies.sort_unstable();
    assert_eq!(address_denies, ["169.254.169.254/32", "fd00:ec2::254/128"]);
    assert_eq!(
        unit_property(HOST_SUPERVISOR_UNIT, "ActiveState"),
        "active",
        "the unit must remain running while the systemd ACL is removed"
    );

    checked_command(
        SYSTEMCTL,
        [
            "set-property",
            "--runtime",
            "--",
            HOST_SUPERVISOR_UNIT,
            "IPAddressDeny=",
        ],
    );
    assert_eq!(
        unit_property(HOST_SUPERVISOR_UNIT, "IPAddressDeny"),
        "",
        "the second probe must not retain systemd IPAddressDeny"
    );
    fs::write(HOST_BOUNDARY_PROBE_TRIGGER, b"probe nft only")
        .expect("the nft-only probe trigger writes");
    let nft_only = wait_for_host_boundary_state(2);
    assert_host_boundary_denied(&nft_only);
    assert_eq!(
        unit_property(HOST_SUPERVISOR_UNIT, "ActiveState"),
        "active",
        "the nft-only probe runs in the original unit invocation"
    );
    checked_command(SYSTEMCTL, ["stop", "--", HOST_SUPERVISOR_UNIT]);
    command(SYSTEMCTL, ["reset-failed", "--", HOST_SUPERVISOR_UNIT]);
}

fn wait_for_host_boundary_state(generation: u64) -> String {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        if let Ok(body) = fs::read_to_string(HOST_BOUNDARY_STATE)
            && body
                .lines()
                .any(|line| line == format!("probe_generation={generation}"))
        {
            return body;
        }
        assert!(
            Instant::now() < deadline,
            "Host Supervisor boundary probe generation {generation} timed out"
        );
        thread::sleep(WAIT_STEP);
    }
}

fn assert_host_boundary_denied(body: &str) {
    assert!(body.lines().any(|line| line == "imds_v4_inaccessible=true"));
    assert!(body.lines().any(|line| line == "imds_v6_inaccessible=true"));
}

fn collision_preflight(host_id: HostId, connector_ids: [ConnectorId; 2], release_directory: &Path) {
    assert_eq!(
        fs::read_to_string("/proc/1/comm")
            .expect("PID 1 identity reads")
            .trim(),
        "systemd",
        "the destructive acceptance requires systemd as PID 1"
    );
    assert!(
        Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "the destructive acceptance requires unified cgroup v2"
    );

    for connector_id in connector_ids {
        let user = connector_user(connector_id);
        let status = Command::new(GETENT)
            .args(["passwd", &user])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("getent is available for the collision preflight");
        assert_eq!(
            status.code(),
            Some(2),
            "disposable VM resource collision or NSS failure for user {user}"
        );
    }

    for unit_name in [
        HOST_SUPERVISOR_UNIT.to_owned(),
        unit(connector_ids[0]),
        unit(connector_ids[1]),
    ] {
        assert_eq!(
            unit_property(&unit_name, "LoadState"),
            "not-found",
            "disposable VM resource collision for unit {unit_name}"
        );
    }
    for ancestor_slice in ["-.slice", "system.slice"] {
        assert_eq!(
            unit_property(ancestor_slice, "IPAddressDeny"),
            "",
            "the nft-only probe requires no inherited systemd deny on {ancestor_slice}"
        );
    }

    let mut paths = vec![
        PathBuf::from("/run/dirextalk/host-supervisor"),
        PathBuf::from(format!(
            "/var/lib/dirextalk/host-supervisor/journals/{host_id}"
        )),
        release_directory.to_path_buf(),
    ];
    for connector_id in connector_ids {
        paths.extend([
            config_dir(connector_id),
            PathBuf::from(format!(
                "/var/lib/dirextalk/connect/instances/{connector_id}"
            )),
            PathBuf::from(format!("/run/dirextalk/connect/{connector_id}")),
        ]);
    }
    for path in paths {
        assert!(
            fs::symlink_metadata(&path)
                .is_err_and(|error| { error.kind() == std::io::ErrorKind::NotFound }),
            "disposable VM resource collision at {}",
            path.display()
        );
    }

    let nft_tables = checked_output(NFT, ["list", "tables"]);
    assert!(
        !nft_tables
            .lines()
            .any(|line| line.contains("dtx_hs_") || line.contains(HOST_SUPERVISOR_NFT_TABLE)),
        "disposable VM resource collision with a Dirextalk nft table"
    );
    let loopback = checked_output(IP, ["address", "show", "dev", "lo"]);
    assert!(
        !loopback.contains("169.254.169.254") && !loopback.contains("fd00:ec2::254"),
        "disposable VM resource collision with an IMDS loopback probe address"
    );
}

fn unit_property(unit_name: &str, property: &str) -> String {
    let property_argument = format!("--property={property}");
    checked_output(
        SYSTEMCTL,
        [
            "show",
            "--no-pager",
            property_argument.as_str(),
            "--value",
            "--",
            unit_name,
        ],
    )
    .trim()
    .to_owned()
}

fn checked_output<'a>(program: &str, arguments: impl IntoIterator<Item = &'a str>) -> String {
    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("{program} failed to launch: {error}"));
    assert!(output.status.success(), "{program} returned failure");
    String::from_utf8(output.stdout).expect("checked command output is UTF-8")
}

fn checked_command<'a>(program: &str, arguments: impl IntoIterator<Item = &'a str>) {
    let status = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|error| panic!("{program} failed to launch: {error}"));
    assert!(status.success(), "{program} returned failure");
}

struct ImdsProbe {
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    added_v4: bool,
    added_v6: bool,
}

impl ImdsProbe {
    fn start() -> Self {
        let added_v4 = status(IP, ["address", "add", IMDS_V4, "dev", "lo"]);
        let added_v6 = status(IP, ["-6", "address", "add", IMDS_V6, "dev", "lo"]);
        let addresses = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)),
                80,
            ),
        ];
        let stop = Arc::new(AtomicBool::new(false));
        let mut probe = Self {
            stop,
            workers: Vec::new(),
            added_v4,
            added_v6,
        };
        for address in addresses {
            let listener = TcpListener::bind(address).expect("root IMDS probe endpoint binds");
            listener
                .set_nonblocking(true)
                .expect("root IMDS probe is nonblocking");
            let worker_stop = Arc::clone(&probe.stop);
            probe.workers.push(thread::spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((_stream, _peer)) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => break,
                    }
                }
            }));
            TcpStream::connect_timeout(&address, Duration::from_secs(1))
                .expect("root namespace can reach the dummy IMDS endpoint");
        }
        probe
    }
}

impl Drop for ImdsProbe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        if self.added_v4 {
            command(IP, ["address", "del", IMDS_V4, "dev", "lo"]);
        }
        if self.added_v6 {
            command(IP, ["-6", "address", "del", IMDS_V6, "dev", "lo"]);
        }
    }
}

struct Cleanup {
    host_id: HostId,
    connector_ids: [ConnectorId; 2],
    release_directory: PathBuf,
    control_listener: Option<UnixListener>,
    imds_probe: Option<ImdsProbe>,
}

impl Cleanup {
    const fn new(
        host_id: HostId,
        connector_ids: [ConnectorId; 2],
        release_directory: PathBuf,
    ) -> Self {
        Self {
            host_id,
            connector_ids,
            release_directory,
            control_listener: None,
            imds_probe: None,
        }
    }

    fn run(&mut self) {
        self.control_listener = None;
        let _ = fs::remove_file(CONTROL_SOCKET);
        self.imds_probe = None;
        command(SYSTEMCTL, ["stop", "--", HOST_SUPERVISOR_UNIT]);
        command(SYSTEMCTL, ["reset-failed", "--", HOST_SUPERVISOR_UNIT]);
        command(NFT, ["delete", "table", "inet", HOST_SUPERVISOR_NFT_TABLE]);
        let _ = fs::remove_file(HOST_BOUNDARY_STATE);
        let _ = fs::remove_file(Path::new(HOST_BOUNDARY_STATE).with_extension("tmp"));
        let _ = fs::remove_file(HOST_BOUNDARY_PROBE_TRIGGER);
        let _ = fs::remove_file("/run/dirextalk/host-supervisor/imds-policy.nft");
        let _ = fs::remove_file("/run/dirextalk/host-supervisor/imds-policy.tmp");
        let _ = fs::remove_dir("/run/dirextalk/host-supervisor");
        for connector_id in self.connector_ids {
            command(SYSTEMCTL, ["stop", "--", &unit(connector_id)]);
            command(SYSTEMCTL, ["reset-failed", "--", &unit(connector_id)]);
            command(
                NFT,
                [
                    "delete",
                    "table",
                    "inet",
                    &network_policy_table(connector_id),
                ],
            );
            for path in [
                config_dir(connector_id),
                data_dir(connector_id)
                    .parent()
                    .expect("data directory has an instance parent")
                    .to_path_buf(),
                PathBuf::from(format!("/run/dirextalk/connect/{connector_id}")),
            ] {
                let _ = fs::remove_dir_all(path);
            }
            let user = connector_user(connector_id);
            command(USERDEL, ["--force", &user]);
        }
        let _ = fs::remove_dir_all(PathBuf::from(format!(
            "/var/lib/dirextalk/host-supervisor/journals/{}",
            self.host_id
        )));
        let _ = fs::remove_dir_all(&self.release_directory);
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.run();
    }
}

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const GETENT: &str = "/usr/bin/getent";
const USERDEL: &str = "/usr/sbin/userdel";
const IP: &str = "/usr/sbin/ip";
const NFT: &str = "/usr/sbin/nft";
const HOST_SUPERVISOR_UNIT: &str = "dirextalk-host-supervisor.service";
const HOST_SUPERVISOR_NFT_TABLE: &str = "dtx_host_supervisor";
const HOST_BOUNDARY_STATE: &str = "/run/dirextalk/host-supervisor/network-boundary.state";

fn command<'a>(program: &str, arguments: impl IntoIterator<Item = &'a str>) {
    let _ = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn status<'a>(program: &str, arguments: impl IntoIterator<Item = &'a str>) -> bool {
    Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn config_dir(connector_id: ConnectorId) -> PathBuf {
    PathBuf::from(format!("/etc/dirextalk/connect/instances/{connector_id}"))
}

fn network_policy_table(connector_id: ConnectorId) -> String {
    format!("dtx_hs_{connector_id}").replace('-', "")
}

fn data_dir(connector_id: ConnectorId) -> PathBuf {
    PathBuf::from(format!(
        "/var/lib/dirextalk/connect/instances/{connector_id}/data"
    ))
}

fn workspace_dir(connector_id: ConnectorId) -> PathBuf {
    PathBuf::from(format!(
        "/var/lib/dirextalk/connect/instances/{connector_id}/workspace"
    ))
}

fn runtime_dir(connector_id: ConnectorId) -> PathBuf {
    PathBuf::from(format!("/run/dirextalk/connect/{connector_id}/worker"))
}

fn credential_file(connector_id: ConnectorId) -> PathBuf {
    PathBuf::from(format!(
        "/run/dirextalk/connect/{connector_id}/credentials/control.credential"
    ))
}

fn unit(connector_id: ConnectorId) -> String {
    format!("dirextalk-connect@{connector_id}.service")
}

fn release_directory(digest: ReleaseDigest) -> PathBuf {
    let mut encoded = String::with_capacity(64);
    for byte in digest.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("hex encodes");
    }
    PathBuf::from(format!("/opt/dirextalk/connect/versions/{encoded}"))
}

fn connector_user(connector_id: ConnectorId) -> String {
    const BASE32: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut value = Uuid::from(connector_id).as_u128();
    let mut encoded = [b'0'; 26];
    for byte in encoded.iter_mut().rev() {
        *byte = BASE32[(value & 31) as usize];
        value >>= 5;
    }
    format!(
        "dtx{}",
        std::str::from_utf8(&encoded).expect("base32 is UTF-8")
    )
}

fn effective_uid() -> u32 {
    let status = fs::read_to_string("/proc/self/status").expect("proc status reads");
    status
        .lines()
        .find(|line| line.starts_with("Uid:\t"))
        .and_then(|line| line[5..].split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .expect("effective UID parses")
}

fn parse<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().expect("fixed typed ID parses")
}
