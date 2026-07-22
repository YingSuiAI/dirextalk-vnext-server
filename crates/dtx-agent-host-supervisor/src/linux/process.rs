use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const MAX_NONSECRET_STATE_BYTES: u64 = 64 * 1024;

use dtx_domain::{ConnectorId, Revision};
use sha2::{Digest, Sha256};

use crate::{
    CatalogRelease, ConnectorTarget, CredentialArtifactProvider, CredentialArtifactRef,
    HostOperationId, HostRevisionFence, ManagedConnectorDesiredState, PortError, PortErrorKind,
    ProcessController, ProcessMutationId, ProcessMutationPhase, ProcessObservation, ReleaseCatalog,
    ResourceProfile, SupervisorSnapshot,
};

use super::{
    bootstrap::LinuxMaterialStore,
    command::{FixedCommand, FixedCommandOutput, FixedCommandRunner, StdCommandRunner},
    credential::{
        CredentialFileProof, LinuxCredentialArtifact, hash_active_credential,
        hash_ready_credential, hash_staged_credential,
    },
    layout::{
        CHOWN, ConnectorLayout, INSTALL, NFT, NOLOGIN, SYSTEMCTL, SYSTEMD_RUN, USERADD,
        adapter_name, digest_hex, profile_name,
    },
};

/// Fixed cgroup-v2 resource limits selected only from an allowlisted profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxResourceLimits {
    memory_max: &'static str,
    cpu_quota: &'static str,
    tasks_max: &'static str,
    io_weight: &'static str,
}

/// One Connector's observed state after replaying a durable desired snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxReconcileObservation {
    connector_id: ConnectorId,
    status: LinuxReconcileStatus,
}

/// Result of restoring one durable Connector desired state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxReconcileStatus {
    Observed(ProcessObservation),
    CredentialRequired,
    ReleaseBlocked,
    CrashLoopBlocked,
}

impl LinuxReconcileObservation {
    #[must_use]
    pub const fn connector_id(self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn status(self) -> LinuxReconcileStatus {
        self.status
    }
}

impl LinuxResourceLimits {
    /// Maps the closed resource profile to fixed systemd limits.
    #[must_use]
    pub const fn for_profile(profile: ResourceProfile) -> Self {
        match profile {
            ResourceProfile::Standard => Self {
                memory_max: "1073741824",
                cpu_quota: "100%",
                tasks_max: "256",
                io_weight: "100",
            },
            ResourceProfile::Compute => Self {
                memory_max: "4294967296",
                cpu_quota: "300%",
                tasks_max: "512",
                io_weight: "200",
            },
            ResourceProfile::LowLatency => Self {
                memory_max: "2147483648",
                cpu_quota: "200%",
                tasks_max: "256",
                io_weight: "300",
            },
        }
    }

    #[must_use]
    pub const fn memory_max(self) -> &'static str {
        self.memory_max
    }

    #[must_use]
    pub const fn cpu_quota(self) -> &'static str {
        self.cpu_quota
    }

    #[must_use]
    pub const fn tasks_max(self) -> &'static str {
        self.tasks_max
    }

    #[must_use]
    pub const fn io_weight(self) -> &'static str {
        self.io_weight
    }
}

/// Linux process adapter for the fixed `dirextalk-connect` Supervisor-mode
/// capability. Production construction exposes no path, command, service,
/// environment, image, or Unix-user input.
pub struct LinuxProcessController {
    root: PathBuf,
    runner: Box<dyn FixedCommandRunner>,
}

impl LinuxProcessController {
    /// Lifecycle-only fixed target wrappers avoid exposing a caller-constructible
    /// process target at the production bootstrap boundary.
    #[allow(clippy::missing_errors_doc)]
    pub fn ensure_lifecycle(
        &mut self,
        mutation_id: ProcessMutationId,
        facts: crate::ConnectorLifecycleFacts,
        release: CatalogRelease,
    ) -> Result<ProcessObservation, PortError> {
        self.ensure(
            mutation_id,
            ConnectorTarget::new(
                facts.tenant_id(),
                facts.host_id(),
                facts.connector_id(),
                facts.adapter_kind(),
            ),
            release,
        )
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn observe_lifecycle(
        &mut self,
        facts: crate::ConnectorLifecycleFacts,
    ) -> Result<ProcessObservation, PortError> {
        self.observe(ConnectorTarget::new(
            facts.tenant_id(),
            facts.host_id(),
            facts.connector_id(),
            facts.adapter_kind(),
        ))
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn adopt_lifecycle_bootstrap_artifacts(
        &mut self,
        mutation_id: ProcessMutationId,
        facts: crate::ConnectorLifecycleFacts,
        credential_ref: CredentialArtifactRef,
        bearer_ref: crate::McpBearerRef,
    ) -> Result<(), PortError> {
        self.adopt_bootstrap_artifacts(
            mutation_id,
            ConnectorTarget::new(
                facts.tenant_id(),
                facts.host_id(),
                facts.connector_id(),
                facts.adapter_kind(),
            ),
            credential_ref,
            bearer_ref,
        )
    }
    /// Uses the fixed production filesystem layout and direct absolute command
    /// capabilities.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/"),
            runner: Box::new(StdCommandRunner),
        }
    }

    /// Restores fixed local process state from an already-durable and
    /// server-validated non-secret Supervisor snapshot after host reboot.
    /// This does not create a new desired revision; the snapshot itself is the
    /// durable authority for these idempotent restoration effects.
    ///
    /// # Errors
    ///
    /// Fails closed on malformed snapshot facts, release/layout drift, or any
    /// sanitized process-control failure.
    #[allow(clippy::too_many_lines)] // One fail-closed cold-recovery audit boundary.
    pub fn reconcile_snapshot<R: ReleaseCatalog>(
        &mut self,
        snapshot: &SupervisorSnapshot,
        catalog: &mut R,
    ) -> Result<Vec<LinuxReconcileObservation>, PortError> {
        self.verify_host_runtime()?;
        validate_reconcile_snapshot(snapshot)?;
        let mut observations = Vec::with_capacity(snapshot.instances.len());
        for instance in &snapshot.instances {
            let target = ConnectorTarget::new(
                snapshot.tenant_id,
                snapshot.host_id,
                instance.connector_id,
                instance.adapter_kind,
            );
            let layout = self.layout(target);
            Self::validate_privileged_layout(&layout)?;
            let known = catalog.resolve_known(instance.adapter_kind, instance.release.digest())?;
            if known != instance.release {
                return Err(PortError::new(PortErrorKind::InvalidArtifact));
            }
            if instance.desired_state == ManagedConnectorDesiredState::Running {
                match catalog.resolve_runnable(instance.adapter_kind, instance.release.digest()) {
                    Ok(runnable) if runnable == instance.release => {}
                    Ok(_) => return Err(PortError::new(PortErrorKind::InvalidArtifact)),
                    Err(error) if error.kind() == PortErrorKind::NotApproved => {
                        self.restore_stopped(&layout)?;
                        observations.push(LinuxReconcileObservation {
                            connector_id: instance.connector_id,
                            status: LinuxReconcileStatus::ReleaseBlocked,
                        });
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            let status = match instance.desired_state {
                ManagedConnectorDesiredState::Running => {
                    self.ensure_user(&layout)?;
                    self.ensure_directories(&layout)?;
                    Self::verify_prepared(&layout, instance.release)?;
                    if Self::crash_loop_is_blocked(&layout, instance.release)? {
                        self.restore_stopped(&layout)?;
                        LinuxReconcileStatus::CrashLoopBlocked
                    } else {
                        let credential_ref = instance
                            .credential_ref
                            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
                        if layout
                            .active_credential()
                            .try_exists()
                            .map_err(|_| PortError::new(PortErrorKind::Unavailable))?
                        {
                            Self::verify_active_credential(&layout, credential_ref)?;
                            match self.observe_internal(&layout)? {
                                ProcessObservation::Running => {
                                    self.verify_network_policy(&layout)?;
                                    self.verify_running_release(&layout, instance.release)?;
                                    LinuxReconcileStatus::Observed(ProcessObservation::Running)
                                }
                                ProcessObservation::Absent | ProcessObservation::Stopped => {
                                    self.replace_network_policy(&layout)?;
                                    let observed = self.start_or_replace(
                                        &layout,
                                        instance.release,
                                        credential_ref,
                                    )?;
                                    if observed == ProcessObservation::Failed {
                                        Self::block_crash_loop(&layout, instance.release)?;
                                        LinuxReconcileStatus::CrashLoopBlocked
                                    } else {
                                        LinuxReconcileStatus::Observed(observed)
                                    }
                                }
                                ProcessObservation::Failed => {
                                    Self::block_crash_loop(&layout, instance.release)?;
                                    LinuxReconcileStatus::CrashLoopBlocked
                                }
                                ProcessObservation::Starting => {
                                    self.verify_network_policy(&layout)?;
                                    LinuxReconcileStatus::Observed(ProcessObservation::Starting)
                                }
                            }
                        } else {
                            self.restore_stopped(&layout)?;
                            self.replace_network_policy(&layout)?;
                            LinuxReconcileStatus::CredentialRequired
                        }
                    }
                }
                ManagedConnectorDesiredState::EnsuredStopped
                | ManagedConnectorDesiredState::Stopped => {
                    self.ensure_user(&layout)?;
                    self.ensure_directories(&layout)?;
                    Self::verify_prepared(&layout, instance.release)?;
                    let observed = self.restore_stopped(&layout)?;
                    self.replace_network_policy(&layout)?;
                    LinuxReconcileStatus::Observed(observed)
                }
                ManagedConnectorDesiredState::RemovedRetainingData => {
                    LinuxReconcileStatus::Observed(self.remove_layout(&layout)?)
                }
            };
            observations.push(LinuxReconcileObservation {
                connector_id: instance.connector_id,
                status,
            });
        }
        Ok(observations)
    }

    /// Adopts fixed bootstrap artifacts for one already-ensured Connector.
    /// The store only stages opaque material; control credential activation is
    /// deliberately routed through `rotate_credential` to bind its metadata.
    #[allow(clippy::missing_errors_doc)]
    pub fn adopt_bootstrap_artifacts(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
        credential_ref: CredentialArtifactRef,
        bearer_ref: crate::McpBearerRef,
    ) -> Result<(), PortError> {
        let operation_id = require_requested_mutation(mutation_id)?;
        self.verify_host_runtime()?;
        let layout = self.layout(target);
        Self::validate_privileged_layout(&layout)?;
        let material = LinuxMaterialStore::for_runtime_adoption(target, operation_id);
        match self.observe_internal(&layout)? {
            ProcessObservation::Running => {
                Self::verify_active_credential(&layout, credential_ref)?;
                material.verify_active_bearer(bearer_ref)
            }
            ProcessObservation::Starting => Err(PortError::new(PortErrorKind::Unavailable)),
            ProcessObservation::Absent
            | ProcessObservation::Stopped
            | ProcessObservation::Failed => {
                let artifact = material.materialize_durable(credential_ref, bearer_ref)?;
                self.rotate_credential(mutation_id, target, credential_ref, &artifact)?;
                material.activate_staged_bearer(bearer_ref)
            }
        }
    }

    /// Restages and atomically activates the snapshot's current opaque
    /// credential without creating a new desired revision or generation. This
    /// is the credential half of cold-start restoration after
    /// [`Self::reconcile_snapshot`] returns
    /// [`LinuxReconcileStatus::CredentialRequired`].
    ///
    /// # Errors
    ///
    /// Rejects a malformed snapshot, unknown/removed Connector, absent current
    /// credential reference, provider mismatch, or fixed-layout activation
    /// failure.
    pub fn restore_snapshot_credential<C>(
        &mut self,
        snapshot: &SupervisorSnapshot,
        connector_id: ConnectorId,
        credentials: &mut C,
    ) -> Result<ProcessObservation, PortError>
    where
        C: CredentialArtifactProvider<Artifact = LinuxCredentialArtifact>,
    {
        self.verify_host_runtime()?;
        validate_reconcile_snapshot(snapshot)?;
        let instance = snapshot
            .instances
            .iter()
            .find(|instance| instance.connector_id == connector_id)
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        if instance.desired_state == ManagedConnectorDesiredState::RemovedRetainingData {
            return Err(PortError::new(PortErrorKind::Conflict));
        }
        if instance.desired_state != ManagedConnectorDesiredState::Running {
            return Err(PortError::new(PortErrorKind::Conflict));
        }
        let credential_ref = instance
            .credential_ref
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        let operation_id = instance
            .credential_operation_id
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        let target = ConnectorTarget::new(
            snapshot.tenant_id,
            snapshot.host_id,
            connector_id,
            instance.adapter_kind,
        );
        let layout = self.layout(target);
        Self::validate_privileged_layout(&layout)?;
        self.ensure_user(&layout)?;
        self.ensure_directories(&layout)?;
        Self::verify_prepared(&layout, instance.release)?;
        self.restore_stopped(&layout)?;
        self.replace_network_policy(&layout)?;
        let artifact = credentials.materialize(operation_id, target, credential_ref)?;
        self.rotate_credential(
            ProcessMutationId::requested(operation_id),
            target,
            credential_ref,
            &artifact,
        )
    }

    #[cfg(test)]
    fn for_test(root: PathBuf, runner: Box<dyn FixedCommandRunner>) -> Self {
        Self { root, runner }
    }

    fn layout(&self, target: ConnectorTarget) -> ConnectorLayout {
        ConnectorLayout::under(self.root.clone(), target)
    }

    fn verify_host_runtime(&self) -> Result<(), PortError> {
        let pid_one = fs::read_to_string(self.root.join("proc/1/comm"))
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if pid_one.trim_end() != "systemd" || pid_one.lines().count() != 1 {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let pid_one_cgroup = fs::read_to_string(self.root.join("proc/1/cgroup"))
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if pid_one_cgroup.lines().count() != 1
            || !pid_one_cgroup
                .lines()
                .next()
                .is_some_and(|line| line.starts_with("0::/"))
        {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let controllers_path = self.root.join("sys/fs/cgroup/cgroup.controllers");
        let metadata = fs::symlink_metadata(&controllers_path)
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let controllers = fs::read_to_string(controllers_path)
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        for required in ["cpu", "io", "memory", "pids"] {
            if !controllers
                .split_ascii_whitespace()
                .any(|value| value == required)
            {
                return Err(PortError::new(PortErrorKind::InvalidArtifact));
            }
        }
        Ok(())
    }

    fn verify_release(layout: &ConnectorLayout, release: CatalogRelease) -> Result<(), PortError> {
        let actual = hash_regular_file(&layout.executable(release))?;
        if actual == release.digest().as_bytes() {
            Ok(())
        } else {
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        }
    }

    fn validate_privileged_layout(layout: &ConnectorLayout) -> Result<(), PortError> {
        for directory in layout.directories() {
            validate_existing_privileged_directory_chain(&directory)?;
        }
        let passwd = layout.passwd();
        let passwd_parent = passwd
            .parent()
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        validate_existing_privileged_directory_chain(passwd_parent)
    }

    fn ensure_user(&mut self, layout: &ConnectorLayout) -> Result<UnixUserIdentity, PortError> {
        if let Some(identity) = lookup_user(&layout.passwd(), &layout.user())? {
            return Ok(identity);
        }
        let user = layout.user();
        self.run_required(&FixedCommand::new(
            USERADD,
            strings([
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                NOLOGIN,
                user.as_str(),
            ]),
        ))?;
        lookup_user(&layout.passwd(), &layout.user())?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))
    }

    fn ensure_directories(&mut self, layout: &ConnectorLayout) -> Result<(), PortError> {
        let user = layout.user();
        for directory in layout.directories() {
            ensure_plain_directory(&directory)?;
            let is_operations = directory.ends_with("operations");
            let is_staged = directory.ends_with("staged");
            let is_config = directory == layout.config_dir();
            let is_trust = directory == layout.trust_dir();
            let is_credentials = directory == layout.credential_dir();
            let is_durable_credentials = directory == layout.durable_credential_dir();
            let is_runtime_root = directory == layout.runtime_dir();
            let (owner, group, mode) = if is_operations || is_staged || is_durable_credentials {
                ("root", "root", "0700")
            } else if is_config || is_trust || is_credentials || is_runtime_root {
                ("root", user.as_str(), "0750")
            } else {
                (user.as_str(), user.as_str(), "0700")
            };
            self.run_required(&FixedCommand::new(
                INSTALL,
                vec![
                    "-d".into(),
                    "-m".into(),
                    mode.into(),
                    "-o".into(),
                    owner.into(),
                    "-g".into(),
                    group.into(),
                    directory.into_os_string(),
                ],
            ))?;
        }
        Ok(())
    }

    fn write_release_manifest(
        layout: &ConnectorLayout,
        release: CatalogRelease,
    ) -> Result<(), PortError> {
        let value = format!(
            "schema=1\nadapter={}\ndigest={}\nprofile={}\ncatalog_revision={}\n",
            adapter_name(release.adapter_kind()),
            digest_hex(release.digest()),
            profile_name(release.resource_profile()),
            release.catalog_revision().get(),
        );
        atomic_write(&layout.release_manifest(), value.as_bytes(), 0o600)
    }

    fn verify_release_manifest(
        layout: &ConnectorLayout,
        release: CatalogRelease,
    ) -> Result<(), PortError> {
        let expected = format!(
            "schema=1\nadapter={}\ndigest={}\nprofile={}\ncatalog_revision={}\n",
            adapter_name(release.adapter_kind()),
            digest_hex(release.digest()),
            profile_name(release.resource_profile()),
            release.catalog_revision().get(),
        );
        let actual = read_secure_nonsecret(&layout.release_manifest())
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if actual == expected.as_bytes() {
            Ok(())
        } else {
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        }
    }

    fn prepare(
        &mut self,
        layout: &ConnectorLayout,
        release: CatalogRelease,
    ) -> Result<(), PortError> {
        Self::verify_release(layout, release)?;
        let identity = self.ensure_user(layout)?;
        self.ensure_directories(layout)?;
        Self::write_release_manifest(layout, release)?;
        Self::write_network_policy(layout, identity)?;
        Self::verify_prepared(layout, release)
    }

    fn verify_prepared(layout: &ConnectorLayout, release: CatalogRelease) -> Result<(), PortError> {
        Self::verify_release(layout, release)?;
        Self::verify_release_manifest(layout, release)?;
        for directory in layout.directories() {
            validate_plain_directory(&directory)?;
        }
        let identity = lookup_user(&layout.passwd(), &layout.user())?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        Self::verify_network_policy_file(layout, identity)?;
        verify_directory_ownership(layout, identity)?;
        Ok(())
    }

    fn write_network_policy(
        layout: &ConnectorLayout,
        identity: UnixUserIdentity,
    ) -> Result<(), PortError> {
        atomic_write(
            &layout.network_policy(),
            network_policy_file(layout, identity.uid).as_bytes(),
            0o600,
        )
    }

    fn verify_network_policy_file(
        layout: &ConnectorLayout,
        identity: UnixUserIdentity,
    ) -> Result<(), PortError> {
        let actual = read_secure_nonsecret(&layout.network_policy())
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if actual == network_policy_file(layout, identity.uid).as_bytes() {
            Ok(())
        } else {
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        }
    }

    fn network_policy_list_command(layout: &ConnectorLayout) -> FixedCommand {
        FixedCommand::new(
            NFT,
            vec![
                "-n".into(),
                "-n".into(),
                "-n".into(),
                "-n".into(),
                "list".into(),
                "table".into(),
                "inet".into(),
                layout.network_policy_table().into(),
            ],
        )
    }

    fn verify_network_policy(&mut self, layout: &ConnectorLayout) -> Result<(), PortError> {
        let identity = lookup_user(&layout.passwd(), &layout.user())?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        Self::verify_network_policy_file(layout, identity)?;
        let output = self
            .runner
            .run(&Self::network_policy_list_command(layout))?;
        if !output.success {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        validate_network_policy_listing(&output.stdout, layout, identity.uid)
    }

    fn replace_network_policy(&mut self, layout: &ConnectorLayout) -> Result<(), PortError> {
        let identity = lookup_user(&layout.passwd(), &layout.user())?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        Self::verify_network_policy_file(layout, identity)?;
        self.run_required(&FixedCommand::new(
            NFT,
            vec![
                "--check".into(),
                "--file".into(),
                layout.network_policy().into_os_string(),
            ],
        ))?;
        self.run_required(&FixedCommand::new(
            NFT,
            vec!["--file".into(), layout.network_policy().into_os_string()],
        ))?;
        self.verify_network_policy(layout)
    }

    fn remove_network_policy(&mut self, layout: &ConnectorLayout) -> Result<(), PortError> {
        let listed = self
            .runner
            .run(&Self::network_policy_list_command(layout))?;
        if !listed.success {
            return Ok(());
        }
        self.run_required(&FixedCommand::new(
            NFT,
            vec![
                "delete".into(),
                "table".into(),
                "inet".into(),
                layout.network_policy_table().into(),
            ],
        ))?;
        let after = self
            .runner
            .run(&Self::network_policy_list_command(layout))?;
        if after.success {
            Err(PortError::new(PortErrorKind::Unavailable))
        } else {
            Ok(())
        }
    }

    fn crash_loop_is_blocked(
        layout: &ConnectorLayout,
        release: CatalogRelease,
    ) -> Result<bool, PortError> {
        match read_secure_nonsecret(&layout.crash_loop_marker()) {
            Ok(value) => {
                let expected = crash_loop_marker_value(release);
                if value == expected.as_bytes() {
                    Ok(true)
                } else {
                    Err(PortError::new(PortErrorKind::InvalidArtifact))
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(PortError::new(PortErrorKind::InvalidArtifact)),
        }
    }

    fn block_crash_loop(
        layout: &ConnectorLayout,
        release: CatalogRelease,
    ) -> Result<(), PortError> {
        atomic_write(
            &layout.crash_loop_marker(),
            crash_loop_marker_value(release).as_bytes(),
            0o600,
        )
    }

    fn clear_crash_loop(layout: &ConnectorLayout) -> Result<(), PortError> {
        match fs::remove_file(layout.crash_loop_marker()) {
            Ok(()) => sync_parent(&layout.crash_loop_marker()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(PortError::new(PortErrorKind::Unavailable)),
        }
    }

    fn start_command(layout: &ConnectorLayout, release: CatalogRelease) -> FixedCommand {
        let limits = LinuxResourceLimits::for_profile(release.resource_profile());
        let mut arguments = vec![
            format!("--unit={}", layout.unit()).into(),
            "--service-type=exec".into(),
            format!("--uid={}", layout.user()).into(),
            property("NoNewPrivileges", "yes"),
            property("ProtectSystem", "strict"),
            property("PrivateTmp", "yes"),
            property("PrivateDevices", "yes"),
            property("ProtectHome", "yes"),
            property("ProtectKernelTunables", "yes"),
            property("ProtectKernelModules", "yes"),
            property("ProtectControlGroups", "yes"),
            property("RestrictSUIDSGID", "yes"),
            property("CapabilityBoundingSet", ""),
            property("KillMode", "control-group"),
            property("Slice", "system.slice"),
            property("IPAddressDeny", "169.254.169.254"),
            property("IPAddressDeny", "fd00:ec2::254"),
            property("MemoryMax", limits.memory_max()),
            property("CPUQuota", limits.cpu_quota()),
            property("TasksMax", limits.tasks_max()),
            property("IOAccounting", "yes"),
            property("IOWeight", limits.io_weight()),
            property("Restart", "on-failure"),
            property("RestartSec", "5s"),
            property("StartLimitIntervalSec", "300s"),
            property("StartLimitBurst", "5"),
            property("OOMPolicy", "stop"),
            property("StandardOutput", "journal"),
            property("StandardError", "journal"),
            property("LogRateLimitIntervalSec", "30s"),
            property("LogRateLimitBurst", "1000"),
            property(
                "SyslogIdentifier",
                &format!("dirextalk-connect-{}", layout.connector_id()),
            ),
            property("UMask", "0077"),
            property_path("WorkingDirectory", &layout.workspace_dir()),
            property_path("ReadWritePaths", &layout.config_dir()),
            property_path("ReadWritePaths", &layout.data_dir()),
            property_path("ReadWritePaths", &layout.workspace_dir()),
            property_path("ReadWritePaths", &layout.worker_runtime_dir()),
            property_path("ReadWritePaths", &layout.log_dir()),
            "--".into(),
            layout.executable(release).into_os_string(),
            "supervisor".into(),
            "--instance-id".into(),
            layout.connector_id().to_string().into(),
            "--tenant-id".into(),
            layout.target().tenant_id().to_string().into(),
            "--host-id".into(),
            layout.target().host_id().to_string().into(),
            "--config-dir".into(),
            layout.config_dir().into_os_string(),
            "--data-dir".into(),
            layout.data_dir().into_os_string(),
            "--workspace-dir".into(),
            layout.workspace_dir().into_os_string(),
            "--runtime-dir".into(),
            layout.worker_runtime_dir().into_os_string(),
            "--credential-file".into(),
            layout.active_credential().into_os_string(),
        ];
        arguments.shrink_to_fit();
        FixedCommand::new(SYSTEMD_RUN, arguments)
    }

    fn systemctl(
        &mut self,
        action: &'static str,
        layout: &ConnectorLayout,
    ) -> Result<(), PortError> {
        self.run_required(&FixedCommand::new(
            SYSTEMCTL,
            vec![action.into(), "--".into(), layout.unit().into()],
        ))
    }

    fn show(
        &mut self,
        layout: &ConnectorLayout,
        property_name: &'static str,
    ) -> Result<Option<String>, PortError> {
        let output = self.runner.run(&FixedCommand::new(
            SYSTEMCTL,
            vec![
                "show".into(),
                "--no-pager".into(),
                format!("--property={property_name}").into(),
                "--value".into(),
                "--".into(),
                layout.unit().into(),
            ],
        ))?;
        let value = parse_stdout(&output)?;
        if output.success {
            Ok(Some(value))
        } else if value == "not-found" {
            Ok(None)
        } else {
            Err(PortError::new(PortErrorKind::Unavailable))
        }
    }

    fn observe_internal(
        &mut self,
        layout: &ConnectorLayout,
    ) -> Result<ProcessObservation, PortError> {
        let Some(load_state) = self.show(layout, "LoadState")? else {
            return Ok(ProcessObservation::Absent);
        };
        if load_state == "not-found" {
            return Ok(ProcessObservation::Absent);
        }
        if load_state != "loaded" {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let active = self
            .show(layout, "ActiveState")?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        match active.as_str() {
            "active" => {
                self.verify_running_identity(layout)?;
                Ok(ProcessObservation::Running)
            }
            "activating" => Ok(ProcessObservation::Starting),
            "inactive" | "deactivating" => {
                let pid = self
                    .show(layout, "MainPID")?
                    .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
                if pid == "0" {
                    Ok(ProcessObservation::Stopped)
                } else {
                    Err(PortError::new(PortErrorKind::InvalidArtifact))
                }
            }
            "failed" => Ok(ProcessObservation::Failed),
            _ => Err(PortError::new(PortErrorKind::InvalidArtifact)),
        }
    }

    fn verify_running_identity(&mut self, layout: &ConnectorLayout) -> Result<(), PortError> {
        let pid = self.main_pid(layout)?;
        let user = self
            .show(layout, "User")?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        if user != layout.user() {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let expected_uid = lookup_user(&layout.passwd(), &user)?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        let status = fs::read_to_string(layout.proc_status(pid))
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if parse_process_uid(&status) != Some(expected_uid.uid) {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let control_group = self
            .show(layout, "ControlGroup")?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        if control_group != format!("/system.slice/{}", layout.unit()) {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let process_cgroup = fs::read_to_string(layout.proc_cgroup(pid))
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if process_cgroup != format!("0::{control_group}\n") {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        Ok(())
    }

    fn verify_running_release(
        &mut self,
        layout: &ConnectorLayout,
        release: CatalogRelease,
    ) -> Result<(), PortError> {
        let expected = layout.executable(release);
        if !expected.is_absolute() {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let executable = expected.to_string_lossy().into_owned();
        let exec_start = self
            .show(layout, "ExecStart")?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        let supervisor_mode = exec_start
            .split(|character: char| {
                !character.is_ascii_alphanumeric() && character != '-' && character != '_'
            })
            .any(|field| field == "supervisor");
        if !exec_start.contains(&executable) || !supervisor_mode {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        self.verify_running_unit_properties(layout, release, &exec_start)?;
        #[cfg(target_os = "linux")]
        {
            let canonical = fs::canonicalize(&expected)
                .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
            let actual = fs::read_link(layout.proc_executable(self.main_pid(layout)?))
                .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
            if actual != canonical || hash_regular_file(&actual)? != release.digest().as_bytes() {
                return Err(PortError::new(PortErrorKind::InvalidArtifact));
            }
        }
        Ok(())
    }

    fn verify_running_unit_properties(
        &mut self,
        layout: &ConnectorLayout,
        release: CatalogRelease,
        exec_start: &str,
    ) -> Result<(), PortError> {
        let command = Self::start_command(layout, release);
        let separator = command
            .arguments
            .iter()
            .position(|value| value == "--")
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        let expected_argv = command.arguments[separator + 1..]
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        let executable_path = layout.executable(release);
        let executable = executable_path.to_string_lossy();
        if exec_start.matches("path=").count() != 1
            || exec_start.matches("argv[]=").count() != 1
            || !exec_start.contains(&format!("path={executable} ;"))
            || !exec_start.contains(&format!("argv[]={expected_argv} ;"))
        {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let limits = LinuxResourceLimits::for_profile(release.resource_profile());
        let cpu_quota = match release.resource_profile() {
            ResourceProfile::Standard => "1s",
            ResourceProfile::Compute => "3s",
            ResourceProfile::LowLatency => "2s",
        };
        let read_write_paths = [
            layout.config_dir(),
            layout.data_dir(),
            layout.workspace_dir(),
            layout.worker_runtime_dir(),
            layout.log_dir(),
        ]
        .iter()
        .map(|path| path.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
        for (property_name, expected) in [
            ("Type", "exec".to_owned()),
            ("NoNewPrivileges", "yes".to_owned()),
            ("ProtectSystem", "strict".to_owned()),
            ("PrivateTmp", "yes".to_owned()),
            ("PrivateDevices", "yes".to_owned()),
            ("ProtectHome", "yes".to_owned()),
            ("ProtectKernelTunables", "yes".to_owned()),
            ("ProtectKernelModules", "yes".to_owned()),
            ("ProtectControlGroups", "yes".to_owned()),
            ("RestrictSUIDSGID", "yes".to_owned()),
            ("CapabilityBoundingSet", String::new()),
            ("KillMode", "control-group".to_owned()),
            ("Slice", "system.slice".to_owned()),
            (
                "IPAddressDeny",
                "169.254.169.254/32 fd00:ec2::254/128".to_owned(),
            ),
            ("MemoryMax", limits.memory_max().to_owned()),
            ("CPUQuotaPerSecUSec", cpu_quota.to_owned()),
            ("TasksMax", limits.tasks_max().to_owned()),
            ("IOAccounting", "yes".to_owned()),
            ("IOWeight", limits.io_weight().to_owned()),
            ("Restart", "on-failure".to_owned()),
            ("RestartUSec", "5s".to_owned()),
            ("StartLimitIntervalUSec", "5min".to_owned()),
            ("StartLimitBurst", "5".to_owned()),
            ("OOMPolicy", "stop".to_owned()),
            ("StandardOutput", "journal".to_owned()),
            ("StandardError", "journal".to_owned()),
            ("LogRateLimitIntervalUSec", "30s".to_owned()),
            ("LogRateLimitBurst", "1000".to_owned()),
            (
                "SyslogIdentifier",
                format!("dirextalk-connect-{}", layout.connector_id()),
            ),
            ("UMask", "0077".to_owned()),
            (
                "WorkingDirectory",
                layout.workspace_dir().to_string_lossy().into_owned(),
            ),
            ("ReadWritePaths", read_write_paths),
        ] {
            if self.show(layout, property_name)?.as_deref() != Some(expected.as_str()) {
                return Err(PortError::new(PortErrorKind::InvalidArtifact));
            }
        }
        Ok(())
    }

    fn main_pid(&mut self, layout: &ConnectorLayout) -> Result<u32, PortError> {
        let pid = self
            .show(layout, "MainPID")?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?
            .parse::<u32>()
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if pid <= 1 {
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        } else {
            Ok(pid)
        }
    }

    fn invocation_id(&mut self, layout: &ConnectorLayout) -> Result<Option<String>, PortError> {
        let Some(value) = self.show(layout, "InvocationID")? else {
            return Ok(None);
        };
        if value.is_empty() {
            Ok(None)
        } else if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Some(value))
        } else {
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        }
    }

    fn run_required(&mut self, command: &FixedCommand) -> Result<(), PortError> {
        let output = self.runner.run(command)?;
        if output.success {
            Ok(())
        } else {
            Err(PortError::new(PortErrorKind::Unavailable))
        }
    }

    fn start_or_replace(
        &mut self,
        layout: &ConnectorLayout,
        release: CatalogRelease,
        credential_ref: CredentialArtifactRef,
    ) -> Result<ProcessObservation, PortError> {
        Self::verify_active_credential(layout, credential_ref)?;
        self.verify_network_policy(layout)?;
        self.run_required(&Self::start_command(layout, release))?;
        let observed = self.observe_internal(layout)?;
        if observed == ProcessObservation::Running {
            self.verify_running_release(layout, release)?;
        } else if observed == ProcessObservation::Failed {
            Self::block_crash_loop(layout, release)?;
        }
        Ok(observed)
    }

    fn verify_active_credential(
        layout: &ConnectorLayout,
        credential_ref: CredentialArtifactRef,
    ) -> Result<(), PortError> {
        let identity = lookup_user(&layout.passwd(), &layout.user())?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        let record = read_credential_activation_record(&layout.active_credential_record())?;
        if record.reference == credential_ref
            && hash_active_credential(&layout.active_credential(), identity.gid)? == record.proof
        {
            Ok(())
        } else {
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        }
    }

    fn prepare_ready_credential(
        &mut self,
        layout: &ConnectorLayout,
        mutation_id: ProcessMutationId,
        artifact: &LinuxCredentialArtifact,
        identity: UnixUserIdentity,
    ) -> Result<PathBuf, PortError> {
        let operation_id = mutation_id.operation_id();
        let staged = layout.staged_credential(operation_id);
        if hash_staged_credential(&staged)? != artifact.proof() {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let ready = layout.ready_credential(mutation_id);
        match fs::symlink_metadata(&ready) {
            Ok(_) => {
                if hash_ready_credential(&ready, identity.gid)? != artifact.proof() {
                    return Err(PortError::new(PortErrorKind::InvalidArtifact));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                copy_bounded_credential(&staged, &ready)?;
                if hash_ready_credential(&ready, identity.gid)? != artifact.proof() {
                    return Err(PortError::new(PortErrorKind::InvalidArtifact));
                }
            }
            Err(_) => return Err(PortError::new(PortErrorKind::InvalidArtifact)),
        }
        self.run_required(&FixedCommand::new(
            CHOWN,
            vec![
                "--no-dereference".into(),
                format!("root:{}", layout.user()).into(),
                "--".into(),
                ready.clone().into_os_string(),
            ],
        ))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&ready, fs::Permissions::from_mode(0o440))
                .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        }
        if hash_active_credential(&ready, identity.gid)? != artifact.proof() {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        Ok(ready)
    }

    fn restore_stopped(
        &mut self,
        layout: &ConnectorLayout,
    ) -> Result<ProcessObservation, PortError> {
        match self.observe_internal(layout)? {
            ProcessObservation::Absent | ProcessObservation::Stopped => {
                return Ok(ProcessObservation::Stopped);
            }
            ProcessObservation::Starting
            | ProcessObservation::Running
            | ProcessObservation::Failed => self.systemctl("stop", layout)?,
        }
        match self.observe_internal(layout)? {
            ProcessObservation::Absent | ProcessObservation::Stopped => {
                Ok(ProcessObservation::Stopped)
            }
            _ => Err(PortError::new(PortErrorKind::Unavailable)),
        }
    }

    fn remove_layout(&mut self, layout: &ConnectorLayout) -> Result<ProcessObservation, PortError> {
        if !matches!(
            self.observe_internal(layout)?,
            ProcessObservation::Absent | ProcessObservation::Stopped
        ) {
            self.systemctl("stop", layout)?;
        }
        let _ = self.systemctl("reset-failed", layout);
        Self::clear_crash_loop(layout)?;
        self.remove_network_policy(layout)?;
        remove_runtime_tree(&layout.runtime_dir())?;
        match self.observe_internal(layout)? {
            ProcessObservation::Absent => Ok(ProcessObservation::Absent),
            _ => Err(PortError::new(PortErrorKind::Unavailable)),
        }
    }
}

impl Default for LinuxProcessController {
    fn default() -> Self {
        Self::new()
    }
}

fn require_requested_mutation(
    mutation_id: ProcessMutationId,
) -> Result<HostOperationId, PortError> {
    if mutation_id.phase() == ProcessMutationPhase::RequestedEffect {
        Ok(mutation_id.operation_id())
    } else {
        Err(PortError::new(PortErrorKind::InvalidArtifact))
    }
}

impl ProcessController<LinuxCredentialArtifact> for LinuxProcessController {
    fn ensure(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
        release: CatalogRelease,
    ) -> Result<ProcessObservation, PortError> {
        require_requested_mutation(mutation_id)?;
        self.verify_host_runtime()?;
        let layout = self.layout(target);
        Self::validate_privileged_layout(&layout)?;
        Self::verify_release(&layout, release)?;
        self.restore_stopped(&layout)?;
        self.prepare(&layout, release)?;
        Self::clear_crash_loop(&layout)?;
        self.replace_network_policy(&layout)?;
        self.restore_stopped(&layout)
    }

    fn start(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
        release: CatalogRelease,
        credential_ref: CredentialArtifactRef,
    ) -> Result<ProcessObservation, PortError> {
        require_requested_mutation(mutation_id)?;
        self.verify_host_runtime()?;
        let layout = self.layout(target);
        Self::validate_privileged_layout(&layout)?;
        Self::verify_prepared(&layout, release)?;
        Self::verify_active_credential(&layout, credential_ref)?;
        if Self::crash_loop_is_blocked(&layout, release)? {
            return Err(PortError::new(PortErrorKind::Conflict));
        }
        self.verify_network_policy(&layout)?;
        match self.observe_internal(&layout)? {
            ProcessObservation::Running => {
                self.verify_running_release(&layout, release)?;
                return Ok(ProcessObservation::Running);
            }
            ProcessObservation::Failed => {
                Self::block_crash_loop(&layout, release)?;
                return Ok(ProcessObservation::Failed);
            }
            ProcessObservation::Absent
            | ProcessObservation::Stopped
            | ProcessObservation::Starting => {}
        }
        self.start_or_replace(&layout, release, credential_ref)
    }

    fn stop(
        &mut self,
        _mutation_id: ProcessMutationId,
        target: ConnectorTarget,
    ) -> Result<ProcessObservation, PortError> {
        let layout = self.layout(target);
        match self.observe_internal(&layout)? {
            ProcessObservation::Absent | ProcessObservation::Stopped => {
                Self::clear_crash_loop(&layout)?;
                return Ok(ProcessObservation::Stopped);
            }
            ProcessObservation::Starting
            | ProcessObservation::Running
            | ProcessObservation::Failed => {}
        }
        self.systemctl("stop", &layout)?;
        match self.observe_internal(&layout)? {
            ProcessObservation::Absent | ProcessObservation::Stopped => {
                Self::clear_crash_loop(&layout)?;
                Ok(ProcessObservation::Stopped)
            }
            _ => Err(PortError::new(PortErrorKind::Unavailable)),
        }
    }

    fn restart(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
        release: CatalogRelease,
        credential_ref: CredentialArtifactRef,
    ) -> Result<ProcessObservation, PortError> {
        require_requested_mutation(mutation_id)?;
        self.verify_host_runtime()?;
        let layout = self.layout(target);
        Self::validate_privileged_layout(&layout)?;
        Self::verify_prepared(&layout, release)?;
        Self::verify_active_credential(&layout, credential_ref)?;
        Self::clear_crash_loop(&layout)?;
        let _ = self.systemctl("reset-failed", &layout);
        self.verify_network_policy(&layout)?;
        let marker = layout.restart_marker(mutation_id);
        let (before, marker_was_new) = match read_restart_marker(&marker)? {
            Some(RestartMarker::Completed(_)) => {
                return match self.observe_internal(&layout)? {
                    ProcessObservation::Running => {
                        self.verify_running_release(&layout, release)?;
                        let current = self
                            .invocation_id(&layout)?
                            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
                        write_restart_marker(&marker, RestartMarker::Completed(current))?;
                        Ok(ProcessObservation::Running)
                    }
                    ProcessObservation::Starting => Err(PortError::new(PortErrorKind::Unavailable)),
                    ProcessObservation::Absent
                    | ProcessObservation::Stopped
                    | ProcessObservation::Failed => {
                        Self::block_crash_loop(&layout, release)?;
                        Ok(ProcessObservation::Failed)
                    }
                };
            }
            Some(RestartMarker::Pending(before)) => (before, false),
            None => {
                let before = self
                    .invocation_id(&layout)?
                    .unwrap_or_else(|| "absent".to_owned());
                write_restart_marker(&marker, RestartMarker::Pending(before.clone()))?;
                (before, true)
            }
        };
        let current_invocation = self.invocation_id(&layout)?;
        if let Some(current) = current_invocation.as_ref()
            && current != &before
        {
            return match self.observe_internal(&layout)? {
                ProcessObservation::Running => {
                    self.verify_running_release(&layout, release)?;
                    write_restart_marker(&marker, RestartMarker::Completed(current.clone()))?;
                    Ok(ProcessObservation::Running)
                }
                ProcessObservation::Starting => Ok(ProcessObservation::Starting),
                ProcessObservation::Failed
                | ProcessObservation::Absent
                | ProcessObservation::Stopped => {
                    Self::block_crash_loop(&layout, release)?;
                    Ok(ProcessObservation::Failed)
                }
            };
        }
        if !marker_was_new {
            // Recovery cannot distinguish a crash immediately before issuing
            // the effect from one immediately after systemd accepted it. Never
            // repeat that effect without a changed InvocationID. Wait while an
            // activation is still converging; otherwise force a safe stopped
            // boundary before completing this ambiguous operation as failed.
            match self.observe_internal(&layout)? {
                ProcessObservation::Starting => {
                    return Err(PortError::new(PortErrorKind::Unavailable));
                }
                ProcessObservation::Running => {
                    self.restore_stopped(&layout)?;
                }
                ProcessObservation::Absent
                | ProcessObservation::Stopped
                | ProcessObservation::Failed => {}
            }
            Self::block_crash_loop(&layout, release)?;
            return Ok(ProcessObservation::Failed);
        }

        let observed = if self.observe_internal(&layout)? == ProcessObservation::Absent {
            self.start_or_replace(&layout, release, credential_ref)?
        } else {
            self.systemctl("restart", &layout)?;
            self.observe_internal(&layout)?
        };
        if observed != ProcessObservation::Running {
            if observed == ProcessObservation::Failed {
                Self::block_crash_loop(&layout, release)?;
            }
            return Ok(observed);
        }
        self.verify_running_release(&layout, release)?;
        let after = self
            .invocation_id(&layout)?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        if after == before {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        write_restart_marker(&marker, RestartMarker::Completed(after))?;
        Ok(ProcessObservation::Running)
    }

    fn restore_installed_runtime(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
        credential_ref: CredentialArtifactRef,
        bearer_ref: crate::McpBearerRef,
    ) -> Result<(), PortError> {
        self.adopt_bootstrap_artifacts(mutation_id, target, credential_ref, bearer_ref)
    }

    fn rotate_credential(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
        credential_ref: CredentialArtifactRef,
        artifact: &LinuxCredentialArtifact,
    ) -> Result<ProcessObservation, PortError> {
        let operation_id = require_requested_mutation(mutation_id)?;
        let layout = self.layout(target);
        Self::validate_privileged_layout(&layout)?;
        if artifact.operation_id() != operation_id
            || artifact.target() != target
            || artifact.reference() != credential_ref
        {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let staged = layout.staged_credential(operation_id);
        let active = layout.active_credential();
        let identity = lookup_user(&layout.passwd(), &layout.user())?
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        let already_active = hash_active_credential(&active, identity.gid)
            .is_ok_and(|proof| proof == artifact.proof());
        if !already_active {
            let ready = self.prepare_ready_credential(&layout, mutation_id, artifact, identity)?;
            reject_link_if_present(&active)?;
            fs::rename(&ready, &active).map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
            #[cfg(unix)]
            OpenOptions::new()
                .read(true)
                .open(&active)
                .and_then(|file| file.sync_all())
                .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
            sync_parent(&active)?;
        }
        if hash_active_credential(&active, identity.gid)? != artifact.proof() {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        write_credential_activation_record(
            &layout.active_credential_record(),
            CredentialActivationRecord {
                reference: credential_ref,
                proof: artifact.proof(),
            },
        )?;
        match fs::remove_file(&staged) {
            Ok(()) => sync_parent(&staged)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PortError::new(PortErrorKind::Unavailable)),
        }
        match self.observe_internal(&layout)? {
            observation @ (ProcessObservation::Running
            | ProcessObservation::Stopped
            | ProcessObservation::Failed) => Ok(observation),
            ProcessObservation::Absent => Ok(ProcessObservation::Stopped),
            _ => Err(PortError::new(PortErrorKind::InvalidArtifact)),
        }
    }

    fn remove_retaining_data(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
    ) -> Result<ProcessObservation, PortError> {
        require_requested_mutation(mutation_id)?;
        let layout = self.layout(target);
        self.remove_layout(&layout)
    }

    fn observe(&mut self, target: ConnectorTarget) -> Result<ProcessObservation, PortError> {
        let layout = self.layout(target);
        self.observe_internal(&layout)
    }
}

fn validate_reconcile_snapshot(snapshot: &SupervisorSnapshot) -> Result<(), PortError> {
    let fence =
        HostRevisionFence::from_revisions(snapshot.desired_revision, snapshot.observed_revision)
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !snapshot.instances.is_empty()
        && (fence.desired() == Revision::INITIAL || fence.observed() != Some(fence.desired()))
    {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    let mut connector_ids = BTreeSet::new();
    for instance in &snapshot.instances {
        if !connector_ids.insert(instance.connector_id)
            || instance.adapter_kind != instance.release.adapter_kind()
            || instance.credential_generation > Revision::MAX
            || (instance.credential_generation == 0) != instance.credential_ref.is_none()
            || instance.credential_ref.is_none() != instance.credential_operation_id.is_none()
            || !matches!(
                (instance.desired_state, instance.observation),
                (
                    ManagedConnectorDesiredState::EnsuredStopped
                        | ManagedConnectorDesiredState::Stopped,
                    ProcessObservation::Stopped
                ) | (
                    ManagedConnectorDesiredState::Running,
                    ProcessObservation::Running | ProcessObservation::Failed
                ) | (
                    ManagedConnectorDesiredState::RemovedRetainingData,
                    ProcessObservation::Absent
                )
            )
        {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
    }
    Ok(())
}

fn network_policy_file(layout: &ConnectorLayout, uid: u32) -> String {
    let table = layout.network_policy_table();
    format!(
        concat!(
            "destroy table inet {table}\n",
            "add table inet {table}\n",
            "add chain inet {table} output {{ type filter hook output priority -147; policy accept; }}\n",
            "add rule inet {table} output meta skuid {uid} ip daddr 169.254.169.254 drop\n",
            "add rule inet {table} output meta skuid {uid} ip6 daddr fd00:ec2::254 drop\n"
        ),
        table = table,
        uid = uid,
    )
}

fn crash_loop_marker_value(release: CatalogRelease) -> String {
    format!("schema=1\nrelease={}\n", digest_hex(release.digest()))
}

fn network_policy_listing(layout: &ConnectorLayout, uid: u32) -> String {
    format!(
        concat!(
            "table inet {} {{\n",
            "chain output {{\n",
            "type filter hook output priority -147; policy accept;\n",
            "meta skuid {uid} ip daddr 169.254.169.254 drop\n",
            "meta skuid {uid} ip6 daddr fd00:ec2::254 drop\n",
            "}}\n",
            "}}"
        ),
        layout.network_policy_table(),
        uid = uid,
    )
}

fn normalize_network_policy_listing(value: &[u8]) -> Result<String, PortError> {
    let value =
        std::str::from_utf8(value).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if value.contains(['\0', '\r']) {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    Ok(value
        .lines()
        .map(|line| line.split_ascii_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n"))
}

fn validate_network_policy_listing(
    value: &[u8],
    layout: &ConnectorLayout,
    uid: u32,
) -> Result<(), PortError> {
    if normalize_network_policy_listing(value)? == network_policy_listing(layout, uid) {
        Ok(())
    } else {
        Err(PortError::new(PortErrorKind::InvalidArtifact))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CredentialActivationRecord {
    reference: CredentialArtifactRef,
    proof: CredentialFileProof,
}

fn copy_bounded_credential(source: &Path, target: &Path) -> Result<(), PortError> {
    reject_link_if_present(target)?;
    let source = File::open(source).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut target_file = options
        .open(target)
        .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    let result = (|| {
        let mut bounded = source.take(super::credential::MAX_CREDENTIAL_BYTES + 1);
        let copied = std::io::copy(&mut bounded, &mut target_file)
            .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        if copied == 0 || copied > super::credential::MAX_CREDENTIAL_BYTES {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        target_file
            .sync_all()
            .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        sync_parent(target)
    })();
    if result.is_err() {
        drop(target_file);
        if fs::remove_file(target).is_ok() {
            let _ = sync_parent(target);
        }
    }
    result
}

fn write_credential_activation_record(
    path: &Path,
    record: CredentialActivationRecord,
) -> Result<(), PortError> {
    let value = format!(
        "schema=1\nreference={}\nsha256={}\nlength={}\n",
        encode_32(record.reference.as_bytes()),
        encode_32(record.proof.digest()),
        record.proof.length(),
    );
    atomic_write(path, value.as_bytes(), 0o600)
}

fn read_credential_activation_record(path: &Path) -> Result<CredentialActivationRecord, PortError> {
    let value =
        read_secure_nonsecret(path).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    let value =
        std::str::from_utf8(&value).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    let lines = value.lines().collect::<Vec<_>>();
    let ["schema=1", reference, digest, length] = lines.as_slice() else {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    };
    let reference = reference
        .strip_prefix("reference=")
        .and_then(decode_32)
        .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
    let digest = digest
        .strip_prefix("sha256=")
        .and_then(decode_32)
        .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
    let length = length
        .strip_prefix("length=")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=super::credential::MAX_CREDENTIAL_BYTES).contains(value))
        .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
    Ok(CredentialActivationRecord {
        reference: CredentialArtifactRef::from_bytes(reference),
        proof: CredentialFileProof::new(digest, length),
    })
}

fn encode_32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = decode_nibble(pair[0])?
            .checked_mul(16)?
            .checked_add(decode_nibble(pair[1])?)?;
    }
    Some(decoded)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<OsString> {
    values.into_iter().map(Into::into).collect()
}

fn property(name: &'static str, value: &str) -> OsString {
    format!("--property={name}={value}").into()
}

fn property_path(name: &'static str, value: &Path) -> OsString {
    property(name, &value.to_string_lossy())
}

fn parse_stdout(output: &FixedCommandOutput) -> Result<String, PortError> {
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?
        .trim();
    if value.contains('\0') || value.contains('\r') || value.lines().count() > 1 {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    Ok(value.to_owned())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct UnixUserIdentity {
    pub(super) uid: u32,
    pub(super) gid: u32,
}

pub(super) fn lookup_user(
    path: &Path,
    username: &str,
) -> Result<Option<UnixUserIdentity>, PortError> {
    let value = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(PortError::new(PortErrorKind::InvalidArtifact)),
    };
    let mut matched = None;
    for line in value.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.first().copied() == Some(username) {
            if matched.is_some()
                || fields.len() != 7
                || fields[1] != "x"
                || fields[5] != "/nonexistent"
                || fields[6] != NOLOGIN
            {
                return Err(PortError::new(PortErrorKind::InvalidArtifact));
            }
            let uid = fields[2]
                .parse::<u32>()
                .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
            let gid = fields[3]
                .parse::<u32>()
                .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
            if uid == 0 || gid == 0 {
                return Err(PortError::new(PortErrorKind::InvalidArtifact));
            }
            matched = Some(UnixUserIdentity { uid, gid });
        }
    }
    Ok(matched)
}

fn parse_process_uid(status: &str) -> Option<u32> {
    let line = status.lines().find(|line| line.starts_with("Uid:\t"))?;
    let mut values = line[5..].split_ascii_whitespace();
    let real = values.next()?.parse::<u32>().ok()?;
    let effective = values.next()?.parse::<u32>().ok()?;
    (real == effective).then_some(real)
}

fn hash_regular_file(path: &Path) -> Result<[u8; 32], PortError> {
    validate_privileged_ancestor_chain(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    #[cfg(all(unix, not(test)))]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mode = metadata.permissions().mode();
        if metadata.uid() != 0 || metadata.nlink() != 1 || mode & 0o022 != 0 || mode & 0o100 == 0 {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
    }
    let mut file = File::open(path).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    let opened = file
        .metadata()
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !same_file_identity(&metadata, &opened) {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let after = file
        .metadata()
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !same_file_identity(&opened, &after) {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    Ok(digest.finalize().into())
}

fn ensure_plain_directory(path: &Path) -> Result<(), PortError> {
    if path.exists() {
        return validate_plain_directory(path);
    }
    let mut missing = Vec::new();
    let mut current = path;
    while !current.exists() {
        missing.push(current.to_path_buf());
        current = current
            .parent()
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
    }
    validate_privileged_directory(current)?;
    for directory in missing.into_iter().rev() {
        fs::create_dir(&directory).map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        validate_privileged_directory(&directory)?;
    }
    validate_plain_directory(path)
}

fn validate_plain_directory(path: &Path) -> Result<(), PortError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(PortError::new(PortErrorKind::InvalidArtifact))
    }
}

fn validate_privileged_ancestor_chain(path: &Path) -> Result<(), PortError> {
    let parent = path
        .parent()
        .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
    for ancestor in parent.ancestors() {
        validate_privileged_directory(ancestor)?;
    }
    Ok(())
}

fn validate_existing_privileged_directory_chain(path: &Path) -> Result<(), PortError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_plain_directory(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(PortError::new(PortErrorKind::InvalidArtifact)),
    }
    let mut current = path
        .parent()
        .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
    loop {
        match fs::symlink_metadata(current) {
            Ok(_) => {
                for ancestor in current.ancestors() {
                    validate_privileged_directory(ancestor)?;
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                current = current
                    .parent()
                    .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
            }
            Err(_) => return Err(PortError::new(PortErrorKind::InvalidArtifact)),
        }
    }
}

fn validate_privileged_directory(path: &Path) -> Result<(), PortError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    #[cfg(all(target_os = "linux", not(test)))]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
    }
    Ok(())
}

fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    if !left.file_type().is_file() || !right.file_type().is_file() || left.len() != right.len() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg_attr(
    not(all(target_os = "linux", not(test))),
    allow(clippy::unnecessary_wraps)
)]
fn verify_directory_ownership(
    layout: &ConnectorLayout,
    connector_identity: UnixUserIdentity,
) -> Result<(), PortError> {
    #[cfg(all(target_os = "linux", not(test)))]
    {
        let UnixUserIdentity { uid, gid } = connector_identity;
        verify_owned_directory(&layout.config_dir(), 0, gid, 0o750)?;
        verify_owned_directory(&layout.trust_dir(), 0, gid, 0o750)?;
        verify_owned_directory(&layout.config_dir().join("operations"), 0, 0, 0o700)?;
        verify_owned_directory(&layout.data_dir(), uid, gid, 0o700)?;
        verify_owned_directory(&layout.workspace_dir(), uid, gid, 0o700)?;
        verify_owned_directory(&layout.runtime_dir(), 0, gid, 0o750)?;
        verify_owned_directory(&layout.worker_runtime_dir(), uid, gid, 0o700)?;
        verify_owned_directory(&layout.credential_dir(), 0, gid, 0o750)?;
        verify_owned_directory(&layout.credential_dir().join("staged"), 0, 0, 0o700)?;
        verify_owned_directory(&layout.durable_credential_dir(), 0, 0, 0o700)?;
        verify_owned_directory(&layout.log_dir(), uid, gid, 0o700)?;
        verify_owned_file(&layout.release_manifest(), 0, 0o600)?;
        verify_owned_file(&layout.network_policy(), 0, 0o600)?;
    }
    #[cfg(not(all(target_os = "linux", not(test))))]
    let _ = (layout, connector_identity);
    Ok(())
}

#[cfg(all(target_os = "linux", not(test)))]
fn verify_owned_directory(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), PortError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(test)))]
fn verify_owned_file(path: &Path, uid: u32, mode: u32) -> Result<(), PortError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    Ok(())
}

fn reject_link_if_present(path: &Path) -> Result<(), PortError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(PortError::new(PortErrorKind::InvalidArtifact)),
    }
}

fn remove_runtime_tree(path: &Path) -> Result<(), PortError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path).map_err(|_| PortError::new(PortErrorKind::Unavailable))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(PortError::new(PortErrorKind::InvalidArtifact)),
    }
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), PortError> {
    let parent = path
        .parent()
        .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
    validate_privileged_ancestor_chain(path)?;
    validate_plain_directory(parent)?;
    reject_link_if_present(path)?;
    let temporary = path.with_extension("tmp");
    reject_link_if_present(&temporary)?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    fs::rename(&temporary, path).map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    sync_parent(path)
}

#[allow(clippy::unnecessary_wraps)]
fn sync_parent(path: &Path) -> Result<(), PortError> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RestartMarker {
    Pending(String),
    Completed(String),
}

fn read_restart_marker(path: &Path) -> Result<Option<RestartMarker>, PortError> {
    let value = match read_secure_nonsecret(path) {
        Ok(value) => {
            String::from_utf8(value).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(PortError::new(PortErrorKind::InvalidArtifact)),
    };
    let Some((state, invocation)) = value.trim_end().split_once('\n') else {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    };
    if invocation != "absent"
        && (invocation.len() != 32 || !invocation.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    match state {
        "pending" => Ok(Some(RestartMarker::Pending(invocation.to_owned()))),
        "completed" if invocation != "absent" => {
            Ok(Some(RestartMarker::Completed(invocation.to_owned())))
        }
        _ => Err(PortError::new(PortErrorKind::InvalidArtifact)),
    }
}

fn read_secure_nonsecret(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    validate_privileged_ancestor_chain(path)
        .map_err(|_| io::Error::other("invalid supervisor state ancestor"))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_NONSECRET_STATE_BYTES
    {
        return Err(std::io::Error::other("invalid supervisor state file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.permissions().mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
            return Err(std::io::Error::other(
                "invalid supervisor state permissions",
            ));
        }
        #[cfg(all(target_os = "linux", not(test)))]
        if metadata.uid() != 0 || metadata.gid() != 0 {
            return Err(std::io::Error::other("invalid supervisor state ownership"));
        }
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !same_file_identity(&metadata, &opened) {
        return Err(io::Error::other("unstable supervisor state file"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    Read::by_ref(&mut file)
        .take(MAX_NONSECRET_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).ok() != Some(opened.len())
        || !same_file_identity(&opened, &after)
    {
        return Err(io::Error::other("unstable supervisor state file"));
    }
    Ok(bytes)
}

fn write_restart_marker(path: &Path, marker: RestartMarker) -> Result<(), PortError> {
    let (state, invocation) = match marker {
        RestartMarker::Pending(invocation) => ("pending", invocation),
        RestartMarker::Completed(invocation) => ("completed", invocation),
    };
    atomic_write(path, format!("{state}\n{invocation}\n").as_bytes(), 0o600)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::BTreeMap,
        rc::Rc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use dtx_connect_registry::AdapterKind;
    use dtx_domain::{ConnectorId, HostId, Revision, TenantId};

    use super::*;
    use crate::ReleaseDigest;

    const fn requested(operation_id: HostOperationId) -> ProcessMutationId {
        ProcessMutationId::requested(operation_id)
    }

    fn new_requested() -> ProcessMutationId {
        requested(HostOperationId::new())
    }

    #[derive(Default)]
    struct FakeState {
        commands: Vec<FixedCommand>,
        root: PathBuf,
        load_state: String,
        active_state: String,
        user: String,
        unit: String,
        executable: String,
        exec_start: String,
        properties: BTreeMap<String, String>,
        invocation: u64,
        network_policy: Option<String>,
    }

    #[derive(Clone)]
    struct FakeRunner(Rc<RefCell<FakeState>>);

    struct TestCredentialProvider {
        root: PathBuf,
        operations: Vec<HostOperationId>,
    }

    struct TestReleaseCatalog {
        release: CatalogRelease,
        runnable: bool,
    }

    impl TestReleaseCatalog {
        const fn runnable(release: CatalogRelease) -> Self {
            Self {
                release,
                runnable: true,
            }
        }

        const fn blocked(release: CatalogRelease) -> Self {
            Self {
                release,
                runnable: false,
            }
        }
    }

    impl ReleaseCatalog for TestReleaseCatalog {
        fn resolve_known(
            &mut self,
            adapter_kind: AdapterKind,
            digest: ReleaseDigest,
        ) -> Result<CatalogRelease, PortError> {
            if self.release.adapter_kind() == adapter_kind && self.release.digest() == digest {
                Ok(self.release)
            } else {
                Err(PortError::new(PortErrorKind::NotApproved))
            }
        }

        fn resolve_runnable(
            &mut self,
            adapter_kind: AdapterKind,
            digest: ReleaseDigest,
        ) -> Result<CatalogRelease, PortError> {
            if self.runnable {
                self.resolve_known(adapter_kind, digest)
            } else {
                Err(PortError::new(PortErrorKind::NotApproved))
            }
        }
    }

    impl CredentialArtifactProvider for TestCredentialProvider {
        type Artifact = LinuxCredentialArtifact;

        fn materialize(
            &mut self,
            operation_id: HostOperationId,
            target: ConnectorTarget,
            reference: CredentialArtifactRef,
        ) -> Result<Self::Artifact, PortError> {
            self.operations.push(operation_id);
            let layout = ConnectorLayout::for_test(self.root.clone(), target);
            let bytes = format!("credential-for-{}", target.connector_id());
            let staged = layout.staged_credential(operation_id);
            fs::write(&staged, bytes.as_bytes()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).unwrap();
            }
            LinuxCredentialArtifact::verify_staged_in(&layout, operation_id, reference)
        }
    }

    impl FixedCommandRunner for FakeRunner {
        #[allow(clippy::too_many_lines)] // One closed fake models the complete fixed command surface.
        fn run(&mut self, command: &FixedCommand) -> Result<FixedCommandOutput, PortError> {
            let mut state = self.0.borrow_mut();
            state.commands.push(command.clone());
            let arguments = command
                .arguments
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            match command.program {
                USERADD => {
                    let user = arguments.last().cloned().unwrap();
                    state.user = user.clone();
                    let passwd = state.root.join("etc/passwd");
                    fs::create_dir_all(passwd.parent().unwrap()).unwrap();
                    fs::write(
                        passwd,
                        format!("{user}:x:24001:24001::/nonexistent:{NOLOGIN}\n"),
                    )
                    .unwrap();
                    success("")
                }
                INSTALL | CHOWN => success(""),
                NFT => run_fake_nft(&mut state, &arguments),
                SYSTEMD_RUN => {
                    state.load_state = "loaded".to_owned();
                    state.active_state = "active".to_owned();
                    state.unit = arguments
                        .iter()
                        .find_map(|value| value.strip_prefix("--unit="))
                        .unwrap()
                        .to_owned();
                    state.user = arguments
                        .iter()
                        .find_map(|value| value.strip_prefix("--uid="))
                        .unwrap()
                        .to_owned();
                    let separator = arguments.iter().position(|value| value == "--").unwrap();
                    state.executable = arguments[separator + 1].clone();
                    state.exec_start = format!(
                        "{{ path={} ; argv[]={} ; ignore_errors=no ; }}",
                        state.executable,
                        arguments[separator + 1..].join(" ")
                    );
                    state.properties.clear();
                    state
                        .properties
                        .insert("Type".to_owned(), "exec".to_owned());
                    let mut read_write_paths = Vec::new();
                    for argument in &arguments[..separator] {
                        let Some(property) = argument.strip_prefix("--property=") else {
                            continue;
                        };
                        let (name, value) = property.split_once('=').unwrap();
                        match name {
                            "ReadWritePaths" => read_write_paths.push(value.to_owned()),
                            "CPUQuota" => {
                                let seconds =
                                    value.trim_end_matches('%').parse::<u32>().unwrap() / 100;
                                state
                                    .properties
                                    .insert("CPUQuotaPerSecUSec".to_owned(), format!("{seconds}s"));
                            }
                            "RestartSec" => {
                                state
                                    .properties
                                    .insert("RestartUSec".to_owned(), value.to_owned());
                            }
                            "StartLimitIntervalSec" => {
                                state.properties.insert(
                                    "StartLimitIntervalUSec".to_owned(),
                                    if value == "300s" {
                                        "5min".to_owned()
                                    } else {
                                        value.to_owned()
                                    },
                                );
                            }
                            "LogRateLimitIntervalSec" => {
                                state.properties.insert(
                                    "LogRateLimitIntervalUSec".to_owned(),
                                    value.to_owned(),
                                );
                            }
                            "IPAddressDeny" => {
                                let normalized = match value {
                                    "169.254.169.254" => "169.254.169.254/32",
                                    "fd00:ec2::254" => "fd00:ec2::254/128",
                                    _ => value,
                                };
                                state
                                    .properties
                                    .entry(name.to_owned())
                                    .and_modify(|current| {
                                        current.push(' ');
                                        current.push_str(normalized);
                                    })
                                    .or_insert_with(|| normalized.to_owned());
                            }
                            _ => {
                                state.properties.insert(name.to_owned(), value.to_owned());
                            }
                        }
                    }
                    state
                        .properties
                        .insert("ReadWritePaths".to_owned(), read_write_paths.join(" "));
                    state.invocation += 1;
                    write_fake_proc(&state);
                    success("")
                }
                SYSTEMCTL if arguments.first().is_some_and(|value| value == "show") => {
                    let property = arguments
                        .iter()
                        .find_map(|value| value.strip_prefix("--property="))
                        .unwrap();
                    match property {
                        "LoadState" | "InvocationID" if state.load_state.is_empty() => {
                            failure("not-found")
                        }
                        "LoadState" => success(&state.load_state),
                        "ActiveState" => success(&state.active_state),
                        "MainPID" if state.active_state == "active" => success("4242"),
                        "MainPID" => success("0"),
                        "User" => success(&state.user),
                        "ControlGroup" => success(&format!("/system.slice/{}", state.unit)),
                        "ExecStart" => success(&state.exec_start),
                        "InvocationID" if state.invocation == 0 => success(""),
                        "InvocationID" => success(&format!("{:032x}", state.invocation)),
                        property if state.properties.contains_key(property) => {
                            success(&state.properties[property])
                        }
                        _ => failure("invalid"),
                    }
                }
                SYSTEMCTL => match arguments.first().map(String::as_str) {
                    Some("stop") => {
                        state.active_state = "inactive".to_owned();
                        success("")
                    }
                    Some("restart") => {
                        state.active_state = "active".to_owned();
                        state.invocation += 1;
                        write_fake_proc(&state);
                        success("")
                    }
                    Some("reset-failed") => {
                        if state.active_state == "failed" {
                            state.active_state = "inactive".to_owned();
                        } else if state.active_state == "inactive" {
                            // Model systemd collecting an already-inactive transient
                            // unit. A failed unit keeps its invocation visible for the
                            // restart replay fence until a later observation.
                            state.load_state.clear();
                        }
                        success("")
                    }
                    _ => failure("invalid"),
                },
                _ => failure("invalid"),
            }
        }
    }

    fn run_fake_nft(
        state: &mut FakeState,
        arguments: &[String],
    ) -> Result<FixedCommandOutput, PortError> {
        if arguments.get(4).is_some_and(|value| value == "list") {
            return state
                .network_policy
                .as_deref()
                .map_or_else(|| failure("not-found"), success);
        }
        if arguments.first().is_some_and(|value| value == "delete") {
            state.network_policy = None;
            return success("");
        }
        let (check_only, path) = match arguments {
            [check, file, path] if check == "--check" && file == "--file" => (true, path),
            [file, path] if file == "--file" => (false, path),
            _ => return failure("invalid"),
        };
        let policy = fs::read_to_string(path).unwrap();
        let table = policy
            .lines()
            .find(|line| line.starts_with("add table "))
            .and_then(|line| line.split_ascii_whitespace().last())
            .unwrap();
        let uid = policy
            .lines()
            .find(|line| line.contains(" skuid "))
            .and_then(|line| {
                let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
                let index = fields.iter().position(|field| *field == "skuid")?;
                fields.get(index + 1)?.parse::<u32>().ok()
            })
            .unwrap();
        if check_only {
            return success("");
        }
        state.network_policy = Some(format!(
            concat!(
                "table inet {table} {{\n",
                "\tchain output {{\n",
                "\t\ttype filter hook output priority -147; policy accept;\n",
                "\t\tmeta skuid {uid} ip daddr 169.254.169.254 drop\n",
                "\t\tmeta skuid {uid} ip6 daddr fd00:ec2::254 drop\n",
                "\t}}\n",
                "}}\n"
            ),
            table = table,
            uid = uid,
        ));
        success("")
    }

    #[allow(clippy::unnecessary_wraps)]
    fn success(value: &str) -> Result<FixedCommandOutput, PortError> {
        Ok(FixedCommandOutput {
            success: true,
            stdout: format!("{value}\n").into_bytes(),
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn failure(value: &str) -> Result<FixedCommandOutput, PortError> {
        Ok(FixedCommandOutput {
            success: false,
            stdout: format!("{value}\n").into_bytes(),
        })
    }

    fn write_fake_proc(state: &FakeState) {
        let process = state.root.join("proc/4242");
        fs::create_dir_all(&process).unwrap();
        fs::write(
            process.join("status"),
            "Name:\tdirextalk\nUid:\t24001\t24001\t24001\t24001\n",
        )
        .unwrap();
        fs::write(
            process.join("cgroup"),
            format!("0::/system.slice/{}\n", state.unit),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let executable = process.join("exe");
            let _ = fs::remove_file(&executable);
            symlink(&state.executable, executable).unwrap();
        }
    }

    fn fixture() -> (
        PathBuf,
        ConnectorTarget,
        CatalogRelease,
        Rc<RefCell<FakeState>>,
        LinuxProcessController,
    ) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("dtx-linux-supervisor-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(root.join("proc/1")).unwrap();
        fs::write(root.join("proc/1/comm"), "systemd\n").unwrap();
        fs::write(root.join("proc/1/cgroup"), "0::/init.scope\n").unwrap();
        fs::create_dir_all(root.join("sys/fs/cgroup")).unwrap();
        fs::write(
            root.join("sys/fs/cgroup/cgroup.controllers"),
            "cpu io memory pids\n",
        )
        .unwrap();
        let target = ConnectorTarget::new(
            TenantId::new(),
            HostId::new(),
            ConnectorId::new(),
            AdapterKind::Codex,
        );
        let payload = b"fixed dirextalk-connect release";
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let release = CatalogRelease::approved(
            AdapterKind::Codex,
            ReleaseDigest::from_bytes(digest),
            ResourceProfile::Standard,
            Revision::INITIAL,
        );
        let layout = ConnectorLayout::for_test(root.clone(), target);
        fs::create_dir_all(layout.executable(release).parent().unwrap()).unwrap();
        fs::write(layout.executable(release), payload).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                layout.executable(release),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let state = Rc::new(RefCell::new(FakeState {
            root: root.clone(),
            ..FakeState::default()
        }));
        let controller =
            LinuxProcessController::for_test(root.clone(), Box::new(FakeRunner(Rc::clone(&state))));
        (root, target, release, state, controller)
    }

    fn provision_test_credential(
        controller: &mut LinuxProcessController,
        root: &Path,
        target: ConnectorTarget,
    ) -> CredentialArtifactRef {
        provision_test_credential_with_operation(controller, root, target).0
    }

    fn provision_test_credential_with_operation(
        controller: &mut LinuxProcessController,
        root: &Path,
        target: ConnectorTarget,
    ) -> (CredentialArtifactRef, HostOperationId) {
        let operation = HostOperationId::new();
        let layout = ConnectorLayout::for_test(root.to_owned(), target);
        let staged = layout.staged_credential(operation);
        let bytes = format!("credential-for-{}", target.connector_id());
        fs::write(&staged, bytes.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let reference = CredentialArtifactRef::from_bytes([0xa5; 32]);
        let artifact =
            LinuxCredentialArtifact::verify_staged_in(&layout, operation, reference).unwrap();
        assert_eq!(
            controller
                .rotate_credential(requested(operation), target, reference, &artifact)
                .unwrap(),
            ProcessObservation::Stopped
        );
        (reference, operation)
    }

    #[test]
    fn fixed_command_plan_enforces_isolation_and_resource_properties() {
        let (root, target, release, state, mut controller) = fixture();
        let operation = HostOperationId::new();
        assert_eq!(
            controller
                .ensure(requested(operation), target, release)
                .unwrap(),
            ProcessObservation::Stopped
        );
        let credential_ref = provision_test_credential(&mut controller, &root, target);
        assert_eq!(
            controller
                .start(requested(operation), target, release, credential_ref)
                .unwrap(),
            ProcessObservation::Running
        );

        let commands = &state.borrow().commands;
        let start = commands
            .iter()
            .find(|command| command.program == SYSTEMD_RUN)
            .unwrap();
        let arguments = start
            .arguments
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for expected in [
            "--property=NoNewPrivileges=yes",
            "--property=ProtectSystem=strict",
            "--property=PrivateTmp=yes",
            "--property=PrivateDevices=yes",
            "--property=ProtectHome=yes",
            "--property=ProtectKernelTunables=yes",
            "--property=ProtectKernelModules=yes",
            "--property=ProtectControlGroups=yes",
            "--property=RestrictSUIDSGID=yes",
            "--property=CapabilityBoundingSet=",
            "--property=KillMode=control-group",
            "--property=IPAddressDeny=169.254.169.254",
            "--property=IPAddressDeny=fd00:ec2::254",
            "--property=MemoryMax=1073741824",
            "--property=CPUQuota=100%",
            "--property=TasksMax=256",
            "--property=IOAccounting=yes",
            "--property=IOWeight=100",
            "--property=Restart=on-failure",
            "--property=RestartSec=5s",
            "--property=StartLimitIntervalSec=300s",
            "--property=StartLimitBurst=5",
            "--property=OOMPolicy=stop",
            "--property=StandardOutput=journal",
            "--property=StandardError=journal",
            "--property=LogRateLimitIntervalSec=30s",
            "--property=LogRateLimitBurst=1000",
        ] {
            assert!(arguments.iter().any(|argument| argument == expected));
        }
        assert!(arguments.iter().any(|argument| argument == "supervisor"));
        assert!(
            arguments.iter().all(|argument| argument != "--replace"),
            "the Ubuntu 24.04 systemd-run capability has no --replace option"
        );
        assert!(
            arguments
                .iter()
                .all(|argument| argument != "-c" && !argument.contains("/bin/sh"))
        );
        assert_fixed_network_policy_commands(commands, &root, target);

        let sibling = ConnectorTarget::new(
            target.tenant_id(),
            target.host_id(),
            ConnectorId::new(),
            AdapterKind::Codex,
        );
        let sibling_id = sibling.connector_id().to_string();
        assert!(
            arguments
                .iter()
                .all(|argument| !argument.contains(&sibling_id))
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn assert_fixed_network_policy_commands(
        commands: &[FixedCommand],
        root: &Path,
        target: ConnectorTarget,
    ) {
        let nft_commands = commands
            .iter()
            .filter(|command| command.program == NFT)
            .collect::<Vec<_>>();
        assert!(
            nft_commands.iter().any(|command| {
                command
                    .arguments
                    .first()
                    .is_some_and(|value| value == "--check")
                    && command
                        .arguments
                        .get(1)
                        .is_some_and(|value| value == "--file")
            }),
            "the replacement batch must validate before its atomic commit"
        );
        assert!(
            nft_commands.iter().any(|command| {
                command
                    .arguments
                    .first()
                    .is_some_and(|value| value == "--file")
                    && command.arguments.get(1).is_some_and(|value| {
                        value
                            == &ConnectorLayout::for_test(root.to_owned(), target)
                                .network_policy()
                                .into_os_string()
                    })
            }),
            "a fixed atomic nft policy must be installed before the worker starts"
        );
        assert!(
            nft_commands.iter().any(|command| {
                command.arguments.iter().any(|value| value == "list")
                    && command.arguments.last().is_some_and(|value| {
                        value.to_string_lossy()
                            == ConnectorLayout::for_test(root.to_owned(), target)
                                .network_policy_table()
                    })
            }),
            "the installed kernel policy must be read back"
        );
    }

    #[test]
    fn credential_rotation_activates_only_an_opaque_fixed_stage() {
        let (root, target, release, _state, mut controller) = fixture();
        let ensure = HostOperationId::new();
        controller
            .ensure(requested(ensure), target, release)
            .unwrap();
        let operation = HostOperationId::new();
        let layout = ConnectorLayout::for_test(root.clone(), target);
        let staged = layout.staged_credential(operation);
        fs::write(&staged, b"secret credential bytes").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let proof = CredentialArtifactRef::from_bytes([0xb6; 32]);
        let artifact =
            LinuxCredentialArtifact::verify_staged_in(&layout, operation, proof).unwrap();
        assert!(!format!("{artifact:?}").contains("secret"));

        assert_eq!(
            controller
                .rotate_credential(requested(operation), target, proof, &artifact)
                .unwrap(),
            ProcessObservation::Stopped
        );
        assert!(!staged.exists());
        assert_eq!(
            fs::read(layout.active_credential()).unwrap(),
            b"secret credential bytes"
        );
        assert_ne!(
            proof.as_bytes(),
            <[u8; 32]>::from(Sha256::digest(b"secret credential bytes")),
            "the provider reference remains opaque and is not a content digest"
        );
        assert!(
            !fs::read(layout.active_credential_record())
                .unwrap()
                .windows(b"secret".len())
                .any(|window| window == b"secret")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(layout.active_credential())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o440
            );
            assert!(
                OpenOptions::new()
                    .append(true)
                    .open(layout.active_credential())
                    .is_err(),
                "the worker-readable active credential is not writable"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_file_or_live_network_policy_fails_closed_before_process_start() {
        let (root, target, release, state, mut controller) = fixture();
        controller.ensure(new_requested(), target, release).unwrap();
        let credential_ref = provision_test_credential(&mut controller, &root, target);
        let layout = ConnectorLayout::for_test(root.clone(), target);
        fs::write(
            layout.network_policy(),
            "include \"/tmp/attacker-controlled.nft\"\n",
        )
        .unwrap();

        assert_eq!(
            controller.start(new_requested(), target, release, credential_ref),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
        assert!(
            state
                .borrow()
                .commands
                .iter()
                .all(|command| command.program != SYSTEMD_RUN)
        );

        let identity = lookup_user(&layout.passwd(), &layout.user())
            .unwrap()
            .unwrap();
        let mut unexpected = network_policy_listing(&layout, identity.uid);
        unexpected.insert_str(
            unexpected.rfind('}').unwrap(),
            "meta skuid 24001 ip daddr 10.0.0.0/8 accept\n",
        );
        assert_eq!(
            validate_network_policy_listing(unexpected.as_bytes(), &layout, identity.uid),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lifecycle_is_idempotent_and_remove_retains_connector_data() {
        let (root, target, release, state, mut controller) = fixture();
        let ensure = HostOperationId::new();
        controller
            .ensure(requested(ensure), target, release)
            .unwrap();
        let credential_ref = provision_test_credential(&mut controller, &root, target);
        controller
            .start(new_requested(), target, release, credential_ref)
            .unwrap();
        let layout = ConnectorLayout::for_test(root.clone(), target);
        fs::write(layout.data_dir().join("retained.db"), b"data").unwrap();
        fs::write(layout.workspace_dir().join("retained.txt"), b"workspace").unwrap();

        let restart = HostOperationId::new();
        assert_eq!(
            controller
                .restart(requested(restart), target, release, credential_ref)
                .unwrap(),
            ProcessObservation::Running
        );
        let restart_calls = state
            .borrow()
            .commands
            .iter()
            .filter(|command| {
                command.program == SYSTEMCTL
                    && command
                        .arguments
                        .first()
                        .is_some_and(|argument| argument == "restart")
            })
            .count();
        {
            let mut state = state.borrow_mut();
            state.invocation += 1;
            write_fake_proc(&state);
        }
        assert_eq!(
            controller
                .restart(requested(restart), target, release, credential_ref)
                .unwrap(),
            ProcessObservation::Running
        );
        assert_eq!(
            state
                .borrow()
                .commands
                .iter()
                .filter(|command| {
                    command.program == SYSTEMCTL
                        && command
                            .arguments
                            .first()
                            .is_some_and(|argument| argument == "restart")
                })
                .count(),
            restart_calls
        );

        assert_eq!(
            controller.stop(new_requested(), target).unwrap(),
            ProcessObservation::Stopped
        );
        assert_eq!(
            controller.observe(target).unwrap(),
            ProcessObservation::Stopped
        );
        controller
            .start(new_requested(), target, release, credential_ref)
            .unwrap();
        assert_eq!(
            controller
                .remove_retaining_data(new_requested(), target)
                .unwrap(),
            ProcessObservation::Absent
        );
        assert!(!layout.runtime_dir().exists());
        assert_eq!(
            fs::read(layout.data_dir().join("retained.db")).unwrap(),
            b"data"
        );
        assert_eq!(
            fs::read(layout.workspace_dir().join("retained.txt")).unwrap(),
            b"workspace"
        );
        assert!(
            state.borrow().network_policy.is_none(),
            "RemoveRetain deletes the kernel hook while retaining user data"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ensure_rejects_release_digest_mismatch_before_any_command() {
        let (root, target, release, state, mut controller) = fixture();
        let layout = ConnectorLayout::for_test(root.clone(), target);
        fs::write(layout.executable(release), b"tampered release").unwrap();

        assert_eq!(
            controller.ensure(new_requested(), target, release),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
        assert!(state.borrow().commands.is_empty());
        assert!(!layout.release_manifest().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn ensure_rejects_a_symlinked_privileged_ancestor() {
        use std::os::unix::fs::symlink;

        let (root, target, release, state, mut controller) = fixture();
        let redirected = root.join("redirected-etc");
        fs::create_dir(&redirected).unwrap();
        if root.join("etc").try_exists().unwrap() {
            fs::remove_dir_all(root.join("etc")).unwrap();
        }
        symlink(&redirected, root.join("etc")).unwrap();

        assert_eq!(
            controller.ensure(new_requested(), target, release),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
        assert!(state.borrow().commands.iter().all(|command| {
            command.program == SYSTEMCTL
                && command
                    .arguments
                    .first()
                    .is_some_and(|value| value == "show")
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_credential_copy_removes_a_partial_target_on_failure() {
        let (root, _target, _release, _state, _controller) = fixture();
        let source = root.join("oversized.credential");
        let target = root.join("partial.ready");
        fs::write(
            &source,
            vec![
                0_u8;
                usize::try_from(crate::linux::credential::MAX_CREDENTIAL_BYTES + 1).unwrap()
            ],
        )
        .unwrap();

        assert_eq!(
            copy_bounded_credential(&source, &target),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
        assert!(!target.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsupported_host_and_drifted_unit_properties_fail_closed() {
        let (root, target, release, state, mut controller) = fixture();
        fs::write(root.join("proc/1/comm"), "not-systemd\n").unwrap();
        assert_eq!(
            controller.ensure(new_requested(), target, release),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
        assert!(state.borrow().commands.is_empty());
        fs::write(root.join("proc/1/comm"), "systemd\n").unwrap();
        controller.ensure(new_requested(), target, release).unwrap();
        let credential_ref = provision_test_credential(&mut controller, &root, target);
        controller
            .start(new_requested(), target, release, credential_ref)
            .unwrap();
        state
            .borrow_mut()
            .properties
            .insert("MemoryMax".to_owned(), "unlimited".to_owned());
        assert_eq!(
            controller.start(new_requested(), target, release, credential_ref),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pending_restart_with_a_new_invocation_never_restarts_that_invocation_again() {
        let (root, target, release, state, mut controller) = fixture();
        controller.ensure(new_requested(), target, release).unwrap();
        let credential_ref = provision_test_credential(&mut controller, &root, target);
        controller
            .start(new_requested(), target, release, credential_ref)
            .unwrap();
        let mutation_id = new_requested();
        let layout = ConnectorLayout::for_test(root.clone(), target);
        let before = format!("{:032x}", state.borrow().invocation);
        write_restart_marker(
            &layout.restart_marker(mutation_id),
            RestartMarker::Pending(before),
        )
        .unwrap();
        {
            let mut state = state.borrow_mut();
            state.invocation += 1;
            state.active_state = "activating".to_owned();
        }

        assert_eq!(
            controller
                .restart(mutation_id, target, release, credential_ref)
                .unwrap(),
            ProcessObservation::Starting
        );
        state.borrow_mut().active_state = "failed".to_owned();
        assert_eq!(
            controller
                .restart(mutation_id, target, release, credential_ref)
                .unwrap(),
            ProcessObservation::Failed
        );
        assert!(layout.crash_loop_marker().exists());
        assert_eq!(
            state
                .borrow()
                .commands
                .iter()
                .filter(|command| {
                    command.program == SYSTEMCTL
                        && command
                            .arguments
                            .first()
                            .is_some_and(|value| value == "restart")
                })
                .count(),
            0,
            "a changed invocation proves the restart effect already occurred"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pending_restart_without_any_invocation_evidence_never_repeats_the_effect() {
        let (root, target, release, state, mut controller) = fixture();
        controller.ensure(new_requested(), target, release).unwrap();
        let credential_ref = provision_test_credential(&mut controller, &root, target);
        controller
            .start(new_requested(), target, release, credential_ref)
            .unwrap();
        let mutation_id = new_requested();
        let layout = ConnectorLayout::for_test(root.clone(), target);
        write_restart_marker(
            &layout.restart_marker(mutation_id),
            RestartMarker::Pending(format!("{:032x}", state.borrow().invocation)),
        )
        .unwrap();
        {
            let mut state = state.borrow_mut();
            state.load_state.clear();
            state.active_state = "inactive".to_owned();
            state.invocation = 0;
        }
        let effect_calls_before = restart_effect_calls(&state.borrow().commands);

        assert_eq!(
            controller
                .restart(mutation_id, target, release, credential_ref)
                .unwrap(),
            ProcessObservation::Failed
        );
        assert_eq!(
            restart_effect_calls(&state.borrow().commands),
            effect_calls_before,
            "missing InvocationID evidence must fail closed instead of repeating restart"
        );
        assert!(layout.crash_loop_marker().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn completed_restart_with_a_collected_unit_never_starts_another_invocation() {
        let (root, target, release, state, mut controller) = fixture();
        controller.ensure(new_requested(), target, release).unwrap();
        let credential_ref = provision_test_credential(&mut controller, &root, target);
        controller
            .start(new_requested(), target, release, credential_ref)
            .unwrap();
        let mutation_id = new_requested();
        let layout = ConnectorLayout::for_test(root.clone(), target);
        write_restart_marker(
            &layout.restart_marker(mutation_id),
            RestartMarker::Completed(format!("{:032x}", state.borrow().invocation)),
        )
        .unwrap();
        {
            let mut state = state.borrow_mut();
            state.load_state.clear();
            state.active_state = "inactive".to_owned();
            state.invocation = 0;
        }
        let effect_calls_before = restart_effect_calls(&state.borrow().commands);

        assert_eq!(
            controller
                .restart(mutation_id, target, release, credential_ref)
                .unwrap(),
            ProcessObservation::Failed
        );
        assert_eq!(
            restart_effect_calls(&state.borrow().commands),
            effect_calls_before
        );
        assert!(layout.crash_loop_marker().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pending_restart_with_the_old_running_invocation_stops_instead_of_repeating() {
        let (root, target, release, state, mut controller) = fixture();
        controller.ensure(new_requested(), target, release).unwrap();
        let credential_ref = provision_test_credential(&mut controller, &root, target);
        controller
            .start(new_requested(), target, release, credential_ref)
            .unwrap();
        let mutation_id = new_requested();
        let layout = ConnectorLayout::for_test(root.clone(), target);
        write_restart_marker(
            &layout.restart_marker(mutation_id),
            RestartMarker::Pending(format!("{:032x}", state.borrow().invocation)),
        )
        .unwrap();
        let effect_calls_before = restart_effect_calls(&state.borrow().commands);

        assert_eq!(
            controller
                .restart(mutation_id, target, release, credential_ref)
                .unwrap(),
            ProcessObservation::Failed
        );
        assert_eq!(
            restart_effect_calls(&state.borrow().commands),
            effect_calls_before
        );
        assert_eq!(state.borrow().active_state, "inactive");
        assert!(layout.crash_loop_marker().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pending_restart_with_the_old_starting_invocation_remains_retryable() {
        let (root, target, release, state, mut controller) = fixture();
        controller.ensure(new_requested(), target, release).unwrap();
        let credential_ref = provision_test_credential(&mut controller, &root, target);
        controller
            .start(new_requested(), target, release, credential_ref)
            .unwrap();
        let mutation_id = new_requested();
        let layout = ConnectorLayout::for_test(root.clone(), target);
        write_restart_marker(
            &layout.restart_marker(mutation_id),
            RestartMarker::Pending(format!("{:032x}", state.borrow().invocation)),
        )
        .unwrap();
        state.borrow_mut().active_state = "activating".to_owned();
        let effect_calls_before = restart_effect_calls(&state.borrow().commands);

        assert_eq!(
            controller.restart(mutation_id, target, release, credential_ref),
            Err(PortError::new(PortErrorKind::Unavailable))
        );
        assert_eq!(
            restart_effect_calls(&state.borrow().commands),
            effect_calls_before
        );
        assert!(!layout.crash_loop_marker().exists());
        assert!(matches!(
            read_restart_marker(&layout.restart_marker(mutation_id)).unwrap(),
            Some(RestartMarker::Pending(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    fn restart_effect_calls(commands: &[FixedCommand]) -> usize {
        commands
            .iter()
            .filter(|command| {
                command.program == SYSTEMD_RUN
                    || (command.program == SYSTEMCTL
                        && command
                            .arguments
                            .first()
                            .is_some_and(|value| value == "restart"))
            })
            .count()
    }

    #[test]
    fn crash_loop_marker_survives_runtime_reset_until_explicit_restart() {
        let (root, target, release, state, mut controller) = fixture();
        controller.ensure(new_requested(), target, release).unwrap();
        let (credential_ref, credential_operation_id) =
            provision_test_credential_with_operation(&mut controller, &root, target);
        controller
            .start(new_requested(), target, release, credential_ref)
            .unwrap();
        state.borrow_mut().active_state = "failed".to_owned();
        let revision = Revision::new(2).unwrap();
        let snapshot = SupervisorSnapshot {
            tenant_id: target.tenant_id(),
            host_id: target.host_id(),
            desired_revision: revision,
            observed_revision: Some(revision),
            instances: vec![crate::ManagedConnectorSnapshot {
                connector_id: target.connector_id(),
                adapter_kind: target.adapter_kind(),
                release,
                desired_state: ManagedConnectorDesiredState::Running,
                observation: ProcessObservation::Failed,
                credential_generation: 1,
                credential_ref: Some(credential_ref),
                credential_operation_id: Some(credential_operation_id),
            }],
        };
        let mut catalog = TestReleaseCatalog::runnable(release);
        assert_eq!(
            controller
                .reconcile_snapshot(&snapshot, &mut catalog)
                .unwrap(),
            vec![LinuxReconcileObservation {
                connector_id: target.connector_id(),
                status: LinuxReconcileStatus::CrashLoopBlocked,
            }]
        );
        state.borrow_mut().load_state.clear();
        state.borrow_mut().active_state.clear();
        assert_eq!(
            controller
                .reconcile_snapshot(&snapshot, &mut catalog)
                .unwrap()[0]
                .status(),
            LinuxReconcileStatus::CrashLoopBlocked
        );
        assert_eq!(
            controller
                .restart(new_requested(), target, release, credential_ref)
                .unwrap(),
            ProcessObservation::Running
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cold_reconcile_stops_a_running_release_that_is_no_longer_runnable() {
        let (root, target, release, state, mut controller) = fixture();
        controller.ensure(new_requested(), target, release).unwrap();
        let (credential_ref, credential_operation_id) =
            provision_test_credential_with_operation(&mut controller, &root, target);
        controller
            .start(new_requested(), target, release, credential_ref)
            .unwrap();
        let revision = Revision::new(2).unwrap();
        let snapshot = SupervisorSnapshot {
            tenant_id: target.tenant_id(),
            host_id: target.host_id(),
            desired_revision: revision,
            observed_revision: Some(revision),
            instances: vec![crate::ManagedConnectorSnapshot {
                connector_id: target.connector_id(),
                adapter_kind: target.adapter_kind(),
                release,
                desired_state: ManagedConnectorDesiredState::Running,
                observation: ProcessObservation::Running,
                credential_generation: 1,
                credential_ref: Some(credential_ref),
                credential_operation_id: Some(credential_operation_id),
            }],
        };
        let starts_before = state
            .borrow()
            .commands
            .iter()
            .filter(|command| command.program == SYSTEMD_RUN)
            .count();
        let mut catalog = TestReleaseCatalog::blocked(release);

        assert_eq!(
            controller
                .reconcile_snapshot(&snapshot, &mut catalog)
                .unwrap(),
            vec![LinuxReconcileObservation {
                connector_id: target.connector_id(),
                status: LinuxReconcileStatus::ReleaseBlocked,
            }]
        );
        assert_eq!(state.borrow().active_state, "inactive");
        assert_eq!(
            state
                .borrow()
                .commands
                .iter()
                .filter(|command| command.program == SYSTEMD_RUN)
                .count(),
            starts_before,
            "cold reconciliation must not revive a revoked release"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ensure_stops_a_drifted_running_process_before_updating_release() {
        let (root, target, initial, _state, mut controller) = fixture();
        controller.ensure(new_requested(), target, initial).unwrap();
        let credential_ref = provision_test_credential(&mut controller, &root, target);
        controller
            .start(new_requested(), target, initial, credential_ref)
            .unwrap();
        let layout = ConnectorLayout::for_test(root.clone(), target);
        let payload = b"replacement dirextalk-connect release";
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let replacement = CatalogRelease::approved(
            AdapterKind::Codex,
            ReleaseDigest::from_bytes(digest),
            ResourceProfile::Compute,
            Revision::new(2).unwrap(),
        );
        fs::create_dir_all(layout.executable(replacement).parent().unwrap()).unwrap();
        fs::write(layout.executable(replacement), payload).unwrap();

        assert_eq!(
            controller
                .ensure(new_requested(), target, replacement)
                .unwrap(),
            ProcessObservation::Stopped
        );
        assert_eq!(
            controller.observe(target).unwrap(),
            ProcessObservation::Stopped
        );
        assert!(
            String::from_utf8(fs::read(layout.release_manifest()).unwrap())
                .unwrap()
                .contains(&digest_hex(replacement.digest()))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_snapshot_restores_a_running_connector_after_host_reboot() {
        let (root, target, release, state, mut controller) = fixture();
        controller.ensure(new_requested(), target, release).unwrap();
        let (credential_ref, credential_operation_id) =
            provision_test_credential_with_operation(&mut controller, &root, target);
        controller
            .start(new_requested(), target, release, credential_ref)
            .unwrap();
        let layout = ConnectorLayout::for_test(root.clone(), target);
        fs::write(layout.data_dir().join("retained.db"), b"data").unwrap();
        fs::remove_dir_all(layout.runtime_dir()).unwrap();
        {
            let mut state = state.borrow_mut();
            state.load_state.clear();
            state.active_state.clear();
            state.invocation = 0;
        }
        let revision = Revision::new(2).unwrap();
        let snapshot = SupervisorSnapshot {
            tenant_id: target.tenant_id(),
            host_id: target.host_id(),
            desired_revision: revision,
            observed_revision: Some(revision),
            instances: vec![crate::ManagedConnectorSnapshot {
                connector_id: target.connector_id(),
                adapter_kind: target.adapter_kind(),
                release,
                desired_state: ManagedConnectorDesiredState::Running,
                observation: ProcessObservation::Running,
                credential_generation: 1,
                credential_ref: Some(credential_ref),
                credential_operation_id: Some(credential_operation_id),
            }],
        };
        let mut catalog = TestReleaseCatalog::runnable(release);

        assert_eq!(
            controller
                .reconcile_snapshot(&snapshot, &mut catalog)
                .unwrap(),
            vec![LinuxReconcileObservation {
                connector_id: target.connector_id(),
                status: LinuxReconcileStatus::CredentialRequired,
            }]
        );
        assert_eq!(
            state
                .borrow()
                .commands
                .iter()
                .filter(|command| command.program == SYSTEMD_RUN)
                .count(),
            1
        );
        let mut credentials = TestCredentialProvider {
            root: root.clone(),
            operations: Vec::new(),
        };
        assert_eq!(
            controller
                .restore_snapshot_credential(&snapshot, target.connector_id(), &mut credentials,)
                .unwrap(),
            ProcessObservation::Stopped
        );
        fs::remove_file(layout.active_credential()).unwrap();
        assert_eq!(
            controller
                .restore_snapshot_credential(&snapshot, target.connector_id(), &mut credentials,)
                .unwrap(),
            ProcessObservation::Stopped
        );
        assert_eq!(credentials.operations.len(), 2);
        assert_eq!(credentials.operations[0], credentials.operations[1]);
        assert_eq!(
            controller
                .reconcile_snapshot(&snapshot, &mut catalog)
                .unwrap(),
            vec![LinuxReconcileObservation {
                connector_id: target.connector_id(),
                status: LinuxReconcileStatus::Observed(ProcessObservation::Running),
            }]
        );
        assert_eq!(
            fs::read(layout.data_dir().join("retained.db")).unwrap(),
            b"data"
        );
        assert_eq!(
            state
                .borrow()
                .commands
                .iter()
                .filter(|command| command.program == SYSTEMD_RUN)
                .count(),
            2
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resource_profiles_have_explicit_nonzero_limits() {
        let limits = BTreeMap::from([
            (
                "standard",
                LinuxResourceLimits::for_profile(ResourceProfile::Standard),
            ),
            (
                "compute",
                LinuxResourceLimits::for_profile(ResourceProfile::Compute),
            ),
            (
                "low-latency",
                LinuxResourceLimits::for_profile(ResourceProfile::LowLatency),
            ),
        ]);
        assert_eq!(limits["standard"].tasks_max(), "256");
        assert_eq!(limits["compute"].cpu_quota(), "300%");
        assert_eq!(limits["low-latency"].memory_max(), "2147483648");
    }

    #[test]
    fn system_user_accepts_a_distinct_private_group_id() {
        let (root, target, _release, _state, _controller) = fixture();
        let layout = ConnectorLayout::for_test(root.clone(), target);
        fs::create_dir_all(layout.passwd().parent().unwrap()).unwrap();
        fs::write(
            layout.passwd(),
            format!("{}:x:24001:23999::/nonexistent:{NOLOGIN}\n", layout.user()),
        )
        .unwrap();

        assert_eq!(
            lookup_user(&layout.passwd(), &layout.user()).unwrap(),
            Some(UnixUserIdentity {
                uid: 24001,
                gid: 23999,
            })
        );
        fs::remove_dir_all(root).unwrap();
    }
}
