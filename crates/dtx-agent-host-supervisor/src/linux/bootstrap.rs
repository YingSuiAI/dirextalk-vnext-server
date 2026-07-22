//! Fixed-path, fail-closed bootstrap material storage.
//!
//! This module deliberately has no caller-supplied path API.  It is a local
//! capability only: lifecycle material is written at one layout derived from a
//! Connector target and all secret reads are bounded and revalidated.

use std::{
    ffi::OsString,
    fmt,
    fs::{self, File},
    io::{Read, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

#[cfg(test)]
use rustix::process::{getgid, getuid};
use rustix::{
    fs::{self as rfs, Mode, OFlags},
    process::{Gid, Pid, Signal, Uid, kill_process_group},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    BootstrapCredentialFacts, CatalogRelease, ConfigDigest, ConnectorLifecycleFacts,
    ConnectorLifecycleOperationId, ConnectorTarget, CredentialArtifactRef, HostOperationId,
    McpBearerRef, PlanDigest, PortError, PortErrorKind, ProcessMutationId, TrustDigest,
};
use dtx_domain::Revision;

#[cfg(not(test))]
use super::process::lookup_user;
use super::{
    credential::{LinuxCredentialArtifact, MAX_CREDENTIAL_BYTES},
    layout::ConnectorLayout,
};

const MAX_PLAN_BYTES: u64 = 64 * 1024;
const MAX_BOOTSTRAP_OUTPUT: usize = 65_536;
const TRUST_DIGEST_DOMAIN: &[u8] = b"dirextalk-connect-trust-v1\0";
const SETSID: &str = "/usr/bin/setsid";

#[derive(Clone, Copy)]
struct FootprintIdentity {
    uid: u32,
    gid: Gid,
}

/// Derives the immutable trust-set digest from the three fixed PEM component
/// digests, in filename order. This avoids byte-concatenation ambiguity.
#[must_use]
pub fn derive_trust_digest(
    enrollment_root_ca: [u8; 32],
    control_server_root_ca: [u8; 32],
    connector_issuer_root_ca: [u8; 32],
) -> TrustDigest {
    let mut digest = Sha256::new();
    digest.update(TRUST_DIGEST_DOMAIN);
    digest.update(enrollment_root_ca);
    digest.update(control_server_root_ca);
    digest.update(connector_issuer_root_ca);
    TrustDigest::from_bytes(digest.finalize().into())
}

/// Opaque capability for the one lifecycle-operation plan path.
#[derive(Clone, Eq, PartialEq)]
pub struct LinuxPlanCapability(PathBuf);

impl fmt::Debug for LinuxPlanCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinuxPlanCapability([fixed])")
    }
}

/// Closed capability for invoking the approved Connector bootstrap executable.
/// It contains the derived executable and plan paths and exposes neither.
pub struct LinuxBootstrapCommand {
    executable: File,
    plan: OsString,
    deadline: Duration,
}

impl LinuxBootstrapCommand {
    /// Runs one fixed bootstrap verb with a scrubbed environment and bounded
    /// secret stdin/stdout. No caller-controlled argument crosses this boundary.
    #[allow(clippy::missing_errors_doc, clippy::too_many_lines)]
    pub fn run(
        &self,
        finalize: bool,
        handoff: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, PortError> {
        let verb = if finalize {
            "bootstrap-finalize"
        } else {
            "bootstrap"
        };
        // The descriptor was hash- and metadata-checked immediately before
        // this call.  `/proc/self/fd` makes exec resolve that exact open file,
        // rather than a replaceable caller path.
        let executable = format!("/proc/self/fd/{}", self.executable.as_raw_fd());
        // `setsid` is a fixed host tool. It execs the descriptor capability in
        // a fresh session whose process-group id is the direct child pid.
        let mut child = Command::new(SETSID)
            .arg(executable)
            .arg(verb)
            .arg("--plan-file")
            .arg(&self.plan)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        let Some(process_group) = Pid::from_raw(i32::try_from(child.id()).unwrap_or_default())
        else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(PortError::new(PortErrorKind::Unavailable));
        };
        let Some(mut stdin) = child.stdin.take() else {
            terminate_group_and_reap(&mut child, process_group);
            return Err(PortError::new(PortErrorKind::Unavailable));
        };
        let Some(mut stdout) = child.stdout.take() else {
            terminate_group_and_reap(&mut child, process_group);
            return Err(PortError::new(PortErrorKind::Unavailable));
        };
        let (events, receiver) = mpsc::channel();
        let writer_events = events.clone();
        let writer = std::thread::spawn(move || {
            let result = stdin.write_all(&handoff);
            drop(stdin);
            let _ = writer_events.send((true, result.map(|()| Vec::new())));
        });
        let reader = std::thread::spawn(move || {
            let mut output = Vec::with_capacity(MAX_BOOTSTRAP_OUTPUT);
            let result = stdout
                .by_ref()
                .take((MAX_BOOTSTRAP_OUTPUT + 1) as u64)
                .read_to_end(&mut output)
                .and_then(|_| {
                    if output.len() > MAX_BOOTSTRAP_OUTPUT {
                        Err(std::io::Error::other("bootstrap output limit"))
                    } else {
                        Ok(())
                    }
                })
                .map(|()| output);
            let _ = events.send((false, result));
        });
        let deadline = Instant::now() + self.deadline;
        let mut write_done = false;
        let mut output = None;
        let mut status: Option<ExitStatus> = None;
        loop {
            if status.is_none() {
                if let Ok(observed) = child.try_wait() {
                    status = observed;
                } else {
                    terminate_group_and_reap(&mut child, process_group);
                    let _ = writer.join();
                    let _ = reader.join();
                    return Err(PortError::new(PortErrorKind::Unavailable));
                }
            }
            if let Some(status) = status
                && !status.success()
            {
                terminate_group_and_reap(&mut child, process_group);
                let _ = writer.join();
                let _ = reader.join();
                return Err(PortError::new(PortErrorKind::InvalidArtifact));
            }
            if write_done && output.is_some() && status.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                terminate_group_and_reap(&mut child, process_group);
                let _ = writer.join();
                let _ = reader.join();
                return Err(PortError::new(PortErrorKind::Unavailable));
            }
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok((is_writer, Ok(_))) if is_writer => write_done = true,
                Ok((false, Ok(value))) => output = Some(value),
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    terminate_group_and_reap(&mut child, process_group);
                    let _ = writer.join();
                    let _ = reader.join();
                    return Err(PortError::new(PortErrorKind::InvalidArtifact));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
        let _ = writer.join();
        let _ = reader.join();
        if !status.is_some_and(|observed| observed.success()) {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let Some(output) = output else {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        };
        Ok(Zeroizing::new(output))
    }

    #[cfg(test)]
    fn for_test(executable: &Path, plan: &Path, deadline: Duration) -> Self {
        // Tests exercise the production descriptor-verification and runner
        // path; this helper supplies only a disposable fixed artifact.
        let digest = crate::ReleaseDigest::from_bytes(
            Sha256::digest(fs::read(executable).expect("test executable reads")).into(),
        );
        Self {
            executable: open_verified_release(executable, digest)
                .expect("test executable verifies as a descriptor capability"),
            plan: plan.as_os_str().to_os_string(),
            deadline,
        }
    }
}

/// Kills only the fresh process group created by the fixed `setsid` wrapper,
/// reaps its direct leader, then permits pipe workers to be joined.
fn terminate_group_and_reap(child: &mut Child, process_group: Pid) {
    let _ = kill_process_group(process_group, Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
}

impl LinuxPlanCapability {
    /// Returns the derived fixed plan path. Callers cannot substitute it.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// Exact fixed bytes to be staged for a prepare/finalize lifecycle operation.
#[derive(Clone, Copy)]
pub struct LinuxMaterial<'a> {
    pub config: &'a [u8],
    pub enrollment_root_ca: &'a [u8],
    pub control_server_root_ca: &'a [u8],
    pub connector_issuer_root_ca: &'a [u8],
    pub plan: &'a [u8],
}

/// Secure footprint observation for expired pending recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxPrepareFootprint {
    AllAbsent,
    Present,
    Ambiguous,
}

/// Linux-only fixed material store. It exposes no filesystem-root constructor
/// outside focused tests and no raw secret/proof debug surface.
pub struct LinuxMaterialStore {
    layout: ConnectorLayout,
    host_operation_id: HostOperationId,
    lifecycle_operation_id: Option<ConnectorLifecycleOperationId>,
}

impl LinuxMaterialStore {
    /// Derives the fixed target from already validated lifecycle facts.
    #[must_use]
    pub fn for_lifecycle(
        facts: ConnectorLifecycleFacts,
        host_operation_id: HostOperationId,
    ) -> Self {
        Self::new(
            ConnectorTarget::new(
                facts.tenant_id(),
                facts.host_id(),
                facts.connector_id(),
                facts.adapter_kind(),
            ),
            host_operation_id,
            facts.lifecycle_operation_id(),
        )
    }
    #[must_use]
    pub fn new(
        target: ConnectorTarget,
        host_operation_id: HostOperationId,
        lifecycle_operation_id: ConnectorLifecycleOperationId,
    ) -> Self {
        Self {
            layout: ConnectorLayout::production(target),
            host_operation_id,
            lifecycle_operation_id: Some(lifecycle_operation_id),
        }
    }

    /// Fixed runtime adoption needs only the Host operation identity: its
    /// staged paths and process mutation are Host-scoped and it never touches
    /// a lifecycle plan or receipt path.
    #[must_use]
    pub(super) fn for_runtime_adoption(
        target: ConnectorTarget,
        host_operation_id: HostOperationId,
    ) -> Self {
        Self {
            layout: ConnectorLayout::production(target),
            host_operation_id,
            lifecycle_operation_id: None,
        }
    }

    #[cfg(test)]
    fn for_test(
        root: PathBuf,
        target: ConnectorTarget,
        host_operation_id: HostOperationId,
        lifecycle_operation_id: ConnectorLifecycleOperationId,
    ) -> Self {
        Self {
            layout: ConnectorLayout::for_test(root, target),
            host_operation_id,
            lifecycle_operation_id: Some(lifecycle_operation_id),
        }
    }

    fn lifecycle_operation_id(&self) -> Result<ConnectorLifecycleOperationId, PortError> {
        self.lifecycle_operation_id
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))
    }

    /// Stages fixed config, trust, and lifecycle-plan bytes. Existing files are
    /// accepted only when their exact bytes and security metadata match.
    #[allow(clippy::missing_errors_doc)]
    pub fn stage(
        &self,
        material: LinuxMaterial<'_>,
        config_digest: ConfigDigest,
        trust_digest: TrustDigest,
        plan_digest: PlanDigest,
    ) -> Result<LinuxPlanCapability, PortError> {
        verify_digest(material.config, config_digest.as_bytes())?;
        if derive_trust_digest(
            Sha256::digest(material.enrollment_root_ca).into(),
            Sha256::digest(material.control_server_root_ca).into(),
            Sha256::digest(material.connector_issuer_root_ca).into(),
        )
        .as_bytes()
            != trust_digest.as_bytes()
        {
            return invalid();
        }
        verify_digest(material.plan, plan_digest.as_bytes())?;
        let service_gid = self.service_gid()?;
        ensure_dir(&self.layout.config_dir(), 0o750, service_gid)?;
        ensure_dir(&self.layout.trust_dir(), 0o750, service_gid)?;
        ensure_dir(
            &self.layout.config_dir().join("operations"),
            0o700,
            privileged_gid(),
        )?;
        put_exact(
            &self.layout.config(),
            material.config,
            0o440,
            service_gid,
            MAX_PLAN_BYTES,
        )?;
        put_exact(
            &self.layout.enrollment_root_ca(),
            material.enrollment_root_ca,
            0o440,
            service_gid,
            MAX_PLAN_BYTES,
        )?;
        put_exact(
            &self.layout.control_server_root_ca(),
            material.control_server_root_ca,
            0o440,
            service_gid,
            MAX_PLAN_BYTES,
        )?;
        put_exact(
            &self.layout.connector_issuer_root_ca(),
            material.connector_issuer_root_ca,
            0o440,
            service_gid,
            MAX_PLAN_BYTES,
        )?;
        put_exact(
            &self.layout.lifecycle_plan(self.lifecycle_operation_id()?),
            material.plan,
            0o600,
            privileged_gid(),
            MAX_PLAN_BYTES,
        )?;
        Ok(LinuxPlanCapability(
            self.layout.lifecycle_plan(self.lifecycle_operation_id()?),
        ))
    }

    /// Stages only a finalize plan after proving the previously prepared
    /// config and trust files still match their durable identities.
    #[allow(clippy::missing_errors_doc)]
    pub fn stage_finalize_plan(
        &self,
        plan: &[u8],
        config_digest: ConfigDigest,
        trust_digest: TrustDigest,
        plan_digest: PlanDigest,
    ) -> Result<LinuxPlanCapability, PortError> {
        self.prepare_parents_safe()?;
        verify_digest(
            &read_checked(
                &self.layout.config(),
                0o440,
                self.service_gid()?,
                MAX_PLAN_BYTES,
            )?,
            config_digest.as_bytes(),
        )?;
        let enrollment: [u8; 32] = Sha256::digest(read_checked(
            &self.layout.enrollment_root_ca(),
            0o440,
            self.service_gid()?,
            MAX_PLAN_BYTES,
        )?)
        .into();
        let control: [u8; 32] = Sha256::digest(read_checked(
            &self.layout.control_server_root_ca(),
            0o440,
            self.service_gid()?,
            MAX_PLAN_BYTES,
        )?)
        .into();
        let issuer: [u8; 32] = Sha256::digest(read_checked(
            &self.layout.connector_issuer_root_ca(),
            0o440,
            self.service_gid()?,
            MAX_PLAN_BYTES,
        )?)
        .into();
        if derive_trust_digest(enrollment, control, issuer) != trust_digest {
            return invalid();
        }
        verify_digest(plan, plan_digest.as_bytes())?;
        put_exact(
            &self.layout.lifecycle_plan(self.lifecycle_operation_id()?),
            plan,
            0o600,
            privileged_gid(),
            MAX_PLAN_BYTES,
        )?;
        Ok(LinuxPlanCapability(
            self.layout.lifecycle_plan(self.lifecycle_operation_id()?),
        ))
    }

    /// Derives the exact approved executable and this operation's plan path.
    #[allow(clippy::missing_errors_doc)]
    pub fn bootstrap_command(
        &self,
        release: CatalogRelease,
        plan: &LinuxPlanCapability,
    ) -> Result<LinuxBootstrapCommand, PortError> {
        Ok(LinuxBootstrapCommand {
            executable: open_verified_release(&self.layout.executable(release), release.digest())?,
            plan: plan.path().as_os_str().to_os_string(),
            deadline: Duration::from_secs(45),
        })
    }

    /// Reads a Connector-owned receipt from its one fixed lifecycle path.
    #[allow(clippy::missing_errors_doc)]
    pub fn read_receipt(&self, finalized: bool) -> Result<Zeroizing<Vec<u8>>, PortError> {
        self.prepare_parents_safe()?;
        let path = if finalized {
            self.layout
                .durable_finalized(self.lifecycle_operation_id()?)
        } else {
            self.layout.durable_receipt(self.lifecycle_operation_id()?)
        };
        Ok(Zeroizing::new(read_checked(
            &path,
            0o600,
            privileged_gid(),
            MAX_BOOTSTRAP_OUTPUT as u64,
        )?))
    }

    /// Inspects every known fixed prepare footprint without accepting a path.
    #[allow(clippy::missing_errors_doc)]
    pub fn inspect_prepare_footprint(&self) -> Result<LinuxPrepareFootprint, PortError> {
        Ok(self
            .inspect_prepare_footprint_with_gid(|| self.footprint_identity())
            .unwrap_or(LinuxPrepareFootprint::Ambiguous))
    }

    #[allow(clippy::too_many_lines)]
    fn inspect_prepare_footprint_with_gid(
        &self,
        service_gid: impl FnOnce() -> Result<FootprintIdentity, PortError>,
    ) -> Result<LinuxPrepareFootprint, PortError> {
        let directories = [
            self.layout.config_dir(),
            self.layout.trust_dir(),
            self.layout.config_dir().join("operations"),
            self.layout.data_dir(),
            self.layout.workspace_dir(),
            self.layout.runtime_dir(),
            self.layout.worker_runtime_dir(),
            self.layout.credential_dir(),
            self.layout.credential_dir().join("staged"),
            self.layout.durable_credential_dir(),
            self.layout.log_dir(),
        ];
        let files = [
            self.layout.config(),
            self.layout.release_manifest(),
            self.layout.network_policy(),
            self.layout.enrollment_root_ca(),
            self.layout.control_server_root_ca(),
            self.layout.connector_issuer_root_ca(),
            self.layout.lifecycle_plan(self.lifecycle_operation_id()?),
            self.layout.staged_credential(self.host_operation_id),
            self.layout.staged_bearer(self.host_operation_id),
            self.layout
                .ready_credential(ProcessMutationId::requested(self.host_operation_id)),
            self.layout
                .ready_bearer(ProcessMutationId::requested(self.host_operation_id)),
            self.layout.active_credential(),
            self.layout.active_bearer(),
            self.layout.active_credential_record(),
            self.layout.crash_loop_marker(),
            self.layout.durable_claim(),
            self.layout.durable_pending(),
            self.layout.durable_credential(),
            self.layout.durable_bearer(),
            self.layout.durable_receipt(self.lifecycle_operation_id()?),
            self.layout
                .durable_finalized(self.lifecycle_operation_id()?),
        ];
        let mut present = false;
        for path in directories.iter().chain(files.iter()) {
            match fs::symlink_metadata(path) {
                Ok(_) => present = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if safe_missing_descendant(path).is_err() {
                        return Ok(LinuxPrepareFootprint::Ambiguous);
                    }
                }
                Err(_) => return Ok(LinuxPrepareFootprint::Ambiguous),
            }
        }
        if !present {
            return Ok(LinuxPrepareFootprint::AllAbsent);
        }
        let identity = service_gid()?;
        for (path, uid, mode, gid) in [
            (
                &directories[0],
                expected_uid().as_raw(),
                0o750,
                identity.gid,
            ),
            (
                &directories[1],
                expected_uid().as_raw(),
                0o750,
                identity.gid,
            ),
            (
                &directories[2],
                expected_uid().as_raw(),
                0o700,
                privileged_gid(),
            ),
            (&directories[3], identity.uid, 0o700, identity.gid),
            (&directories[4], identity.uid, 0o700, identity.gid),
            (
                &directories[5],
                expected_uid().as_raw(),
                0o750,
                identity.gid,
            ),
            (&directories[6], identity.uid, 0o700, identity.gid),
            (
                &directories[7],
                expected_uid().as_raw(),
                0o750,
                identity.gid,
            ),
            (
                &directories[8],
                expected_uid().as_raw(),
                0o700,
                privileged_gid(),
            ),
            (
                &directories[9],
                expected_uid().as_raw(),
                0o700,
                privileged_gid(),
            ),
            (&directories[10], identity.uid, 0o700, identity.gid),
        ] {
            if path_exists_nofollow(path) && !valid_fixed_directory(path, uid, mode, gid) {
                return Ok(LinuxPrepareFootprint::Ambiguous);
            }
        }
        for (index, path) in files.iter().enumerate() {
            let (uid, mode, gid) = match index {
                0 | 3..=5 | 9..=12 => (expected_uid().as_raw(), 0o440, identity.gid),
                _ => (expected_uid().as_raw(), 0o600, privileged_gid()),
            };
            if path_exists_nofollow(path)
                && !valid_fixed_file(path, uid, mode, gid, MAX_CREDENTIAL_BYTES)
            {
                return Ok(LinuxPrepareFootprint::Ambiguous);
            }
        }
        Ok(LinuxPrepareFootprint::Present)
    }

    fn prepare_parents_safe(&self) -> Result<(), PortError> {
        let service_gid = self.service_gid()?;
        for (path, mode, gid) in [
            (self.layout.config_dir(), 0o750, service_gid),
            (self.layout.trust_dir(), 0o750, service_gid),
            (
                self.layout.config_dir().join("operations"),
                0o700,
                privileged_gid(),
            ),
            (
                self.layout.durable_credential_dir(),
                0o700,
                privileged_gid(),
            ),
            (self.layout.credential_dir(), 0o750, service_gid),
            (
                self.layout.credential_dir().join("staged"),
                0o700,
                privileged_gid(),
            ),
        ] {
            match ensure_dir(&path, mode, gid) {
                Ok(()) => {}
                Err(error)
                    if error.kind() == PortErrorKind::InvalidArtifact
                        && !path_exists_nofollow(&path) =>
                {
                    safe_missing_descendant(&path)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Materializes bounded durable secrets only into this operation's staged
    /// files. Active credential adoption remains exclusively with the process
    /// controller so its activation metadata is always written and checked.
    #[allow(clippy::missing_errors_doc)]
    pub(super) fn materialize_durable(
        &self,
        credential_ref: CredentialArtifactRef,
        bearer_ref: McpBearerRef,
    ) -> Result<LinuxCredentialArtifact, PortError> {
        self.prepare_parents_safe()?;
        let credential = read_secret(&self.layout.durable_credential(), false)?;
        let bearer = read_secret(&self.layout.durable_bearer(), true)?;
        verify_digest(&credential, credential_ref.as_bytes())?;
        verify_digest(&bearer, bearer_ref.as_bytes())?;
        put_exact(
            &self.layout.staged_credential(self.host_operation_id),
            &credential,
            0o600,
            privileged_gid(),
            MAX_CREDENTIAL_BYTES,
        )?;
        put_exact(
            &self.layout.staged_bearer(self.host_operation_id),
            &bearer,
            0o600,
            privileged_gid(),
            MAX_CREDENTIAL_BYTES,
        )?;
        LinuxCredentialArtifact::verify_staged_in(
            &self.layout,
            self.host_operation_id,
            credential_ref,
        )
    }

    /// Reads the two Connector-owned fixed durable secrets after the caller
    /// has bound a receipt, returning only opaque SHA-256 references.  The
    /// caller supplies the generation/revision it verified from that receipt;
    /// no secret byte or path crosses this capability boundary.
    #[allow(clippy::missing_errors_doc)]
    pub fn adopted_credential_facts(
        &self,
        generation: u64,
        revision: Revision,
    ) -> Result<BootstrapCredentialFacts, PortError> {
        // Prove every fixed parent first. `read_checked` protects the final
        // component; this closes the remaining ancestor substitution path.
        self.prepare_parents_safe()?;
        let credential = read_secret(&self.layout.durable_credential(), false)?;
        let bearer = read_secret(&self.layout.durable_bearer(), true)?;
        Ok(BootstrapCredentialFacts {
            generation,
            revision,
            credential_ref: CredentialArtifactRef::from_bytes(Sha256::digest(&credential).into()),
            mcp_bearer_ref: McpBearerRef::from_bytes(Sha256::digest(&bearer).into()),
        })
    }

    /// Atomically adopts only an already-staged bearer into the fixed active
    /// path, with root:connector-group `0440` metadata and durable fsync.
    #[allow(clippy::missing_errors_doc)]
    pub(super) fn activate_staged_bearer(&self, bearer_ref: McpBearerRef) -> Result<(), PortError> {
        let gid = self.service_gid()?;
        let staged = self.layout.staged_bearer(self.host_operation_id);
        let bearer = read_secret(&staged, true)?;
        verify_digest(&bearer, bearer_ref.as_bytes())?;
        let active = self.layout.active_bearer();
        if read_checked(&active, 0o440, gid, MAX_CREDENTIAL_BYTES)
            .is_ok_and(|existing| existing == *bearer)
        {
            return Ok(());
        }
        reject_regular_or_absent(&active)?;
        let ready = self
            .layout
            .ready_bearer(crate::ProcessMutationId::requested(self.host_operation_id));
        put_exact(&ready, &bearer, 0o440, gid, MAX_CREDENTIAL_BYTES)?;
        fs::rename(&ready, &active).map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        File::open(&active)
            .and_then(|file| file.sync_all())
            .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        let parent = open_directory_chain(
            active
                .parent()
                .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?,
        )?;
        rfs::fsync(&parent).map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        let verified = read_checked(&active, 0o440, gid, MAX_CREDENTIAL_BYTES)?;
        verify_digest(&verified, bearer_ref.as_bytes())
    }

    pub(super) fn verify_active_bearer(&self, bearer_ref: McpBearerRef) -> Result<(), PortError> {
        let bearer = read_checked(
            &self.layout.active_bearer(),
            0o440,
            self.service_gid()?,
            MAX_CREDENTIAL_BYTES,
        )?;
        if canonical_bearer(&bearer) {
            verify_digest(&bearer, bearer_ref.as_bytes())
        } else {
            invalid()
        }
    }

    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    fn service_gid(&self) -> Result<Gid, PortError> {
        #[cfg(test)]
        {
            Ok(getgid())
        }
        #[cfg(not(test))]
        {
            let identity = lookup_user(&self.layout.passwd(), &self.layout.user())?
                .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
            if identity.gid == 0 {
                return invalid();
            }
            Ok(Gid::from_raw(identity.gid))
        }
    }

    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    fn footprint_identity(&self) -> Result<FootprintIdentity, PortError> {
        #[cfg(test)]
        {
            Ok(FootprintIdentity {
                uid: getuid().as_raw(),
                gid: getgid(),
            })
        }
        #[cfg(not(test))]
        {
            let identity = lookup_user(&self.layout.passwd(), &self.layout.user())?
                .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
            if identity.gid == 0 {
                return invalid();
            }
            Ok(FootprintIdentity {
                uid: identity.uid,
                gid: Gid::from_raw(identity.gid),
            })
        }
    }
}

fn invalid<T>() -> Result<T, PortError> {
    Err(PortError::new(PortErrorKind::InvalidArtifact))
}

fn verify_digest(bytes: &[u8], expected: [u8; 32]) -> Result<(), PortError> {
    if Sha256::digest(bytes).as_slice() == expected {
        Ok(())
    } else {
        invalid()
    }
}

/// The process controller is the only production creator of fixed directory
/// trees.  This store never repairs a missing or unsafe ancestor: that would
/// turn a material operation into an unconstrained privileged mkdir/chown API.
fn ensure_dir(path: &Path, mode: u32, gid: Gid) -> Result<(), PortError> {
    let directory = open_directory_chain(path)?;
    let stat =
        rfs::fstat(&directory).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !is_directory(&stat)
        || stat.st_uid != expected_uid().as_raw()
        || stat.st_gid != gid.as_raw()
        || (stat.st_mode & 0o777) != mode
    {
        return invalid();
    }
    Ok(())
}

/// Opens every component independently with `O_NOFOLLOW|O_DIRECTORY`; this
/// makes a later path replacement unable to redirect a write through an
/// ancestor symlink.
fn open_directory_chain(path: &Path) -> Result<std::os::fd::OwnedFd, PortError> {
    let mut current = rfs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        current = rfs::openat(
            &current,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    }
    Ok(current)
}

#[cfg(test)]
fn expected_uid() -> Uid {
    getuid()
}
#[cfg(not(test))]
fn expected_uid() -> Uid {
    Uid::ROOT
}
#[cfg(test)]
fn privileged_gid() -> Gid {
    getgid()
}
#[cfg(not(test))]
fn privileged_gid() -> Gid {
    Gid::ROOT
}

fn is_directory(stat: &rfs::Stat) -> bool {
    rfs::FileType::from_raw_mode(stat.st_mode) == rfs::FileType::Directory
}

fn put_exact(path: &Path, bytes: &[u8], mode: u32, gid: Gid, max: u64) -> Result<(), PortError> {
    if u64::try_from(bytes.len()).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))? > max
    {
        return invalid();
    }
    match read_checked(path, mode, gid, max) {
        Ok(existing) => {
            return if existing == bytes {
                Ok(())
            } else {
                Err(PortError::new(PortErrorKind::Conflict))
            };
        }
        Err(error)
            if error.kind() == PortErrorKind::InvalidArtifact && !path_exists_nofollow(path) => {}
        Err(error) => return Err(error),
    }
    let parent = open_directory_chain(
        path.parent()
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?,
    )?;
    let name = path
        .file_name()
        .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
    let fd = match rfs::openat(
        &parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode),
    ) {
        Ok(fd) => fd,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return put_exact(path, bytes, mode, gid, max);
        }
        Err(_) => return invalid(),
    };
    // Creation is umask-masked. Set and verify the final metadata on the
    // descriptor before bytes become durable.
    rfs::fchmod(&fd, Mode::from_raw_mode(mode))
        .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    rfs::fchown(&fd, Some(expected_uid()), Some(gid))
        .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    file.sync_all()
        .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    drop(file);
    rfs::fsync(&parent).map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    if read_checked(path, mode, gid, max)? == bytes {
        Ok(())
    } else {
        invalid()
    }
}

fn path_exists_nofollow(path: &Path) -> bool {
    rfs::lstat(path).is_ok()
}

fn reject_regular_or_absent(path: &Path) -> Result<(), PortError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => invalid(),
    }
}

fn safe_missing_descendant(path: &Path) -> Result<(), PortError> {
    let mut ancestor = path
        .parent()
        .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
    while !path_exists_nofollow(ancestor) {
        ancestor = ancestor
            .parent()
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
    }
    let directory = open_directory_chain(ancestor)?;
    let stat =
        rfs::fstat(&directory).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !is_directory(&stat) || stat.st_uid != expected_uid().as_raw() || stat.st_mode & 0o022 != 0 {
        return invalid();
    }
    Ok(())
}

fn read_secret(path: &Path, bearer: bool) -> Result<Zeroizing<Vec<u8>>, PortError> {
    let bytes = Zeroizing::new(read_checked(
        path,
        0o600,
        privileged_gid(),
        MAX_CREDENTIAL_BYTES,
    )?);
    if bytes.is_empty() || (bearer && !canonical_bearer(&bytes)) {
        return invalid();
    }
    Ok(bytes)
}

fn canonical_bearer(value: &[u8]) -> bool {
    value.len() == 43
        && value.iter().all(|byte| b64url(*byte).is_some())
        && b64url(value[42]).is_some_and(|sextet| sextet.trailing_zeros() >= 2)
}

const fn b64url(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn read_checked(path: &Path, mode: u32, gid: Gid, max: u64) -> Result<Vec<u8>, PortError> {
    let first =
        fs::symlink_metadata(path).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !valid_regular(&first, max) {
        return invalid();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        if first.permissions().mode() & 0o777 != mode
            || first.uid() != expected_uid().as_raw()
            || first.gid() != gid.as_raw()
        {
            return invalid();
        }
    }
    let fd = rfs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    let mut file = File::from(fd);
    let before = file
        .metadata()
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !same_file(&first, &before) {
        return invalid();
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    let after = file
        .metadata()
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|length| length > max)
        || !same_file(&before, &after)
        || bytes.len() as u64 != before.len()
    {
        return invalid();
    }
    Ok(bytes)
}

fn valid_regular(metadata: &fs::Metadata, max: u64) -> bool {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() || metadata.len() > max
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return false;
        }
    }
    true
}

fn valid_fixed_directory(path: &Path, uid: u32, mode: u32, gid: Gid) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        metadata.uid() == uid
            && metadata.gid() == gid.as_raw()
            && metadata.permissions().mode() & 0o777 == mode
    }
    #[cfg(not(unix))]
    {
        let _ = (mode, gid);
        false
    }
}

fn valid_fixed_file(path: &Path, uid: u32, mode: u32, gid: Gid, max: u64) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !valid_regular(&metadata, max) {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        metadata.uid() == uid
            && metadata.gid() == gid.as_raw()
            && metadata.permissions().mode() & 0o777 == mode
    }
    #[cfg(not(unix))]
    {
        let _ = (mode, gid);
        false
    }
}

/// Opens the catalog-selected executable once, with no-follow and stable
/// metadata checks, and hashes that same descriptor.  Keeping the descriptor
/// inside `LinuxBootstrapCommand` closes replacement between approval and
/// spawn.
fn open_verified_release(path: &Path, digest: crate::ReleaseDigest) -> Result<File, PortError> {
    let first =
        fs::symlink_metadata(path).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !valid_regular(&first, u64::MAX) {
        return invalid();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if first.uid() != expected_uid().as_raw()
            || first.gid() != privileged_gid().as_raw()
            || first.permissions().mode() & 0o022 != 0
        {
            return invalid();
        }
    }
    let fd = rfs::open(path, OFlags::RDONLY | OFlags::NOFOLLOW, Mode::empty())
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    let mut file = File::from(fd);
    let before = file
        .metadata()
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !same_file(&first, &before) {
        return invalid();
    }
    let mut hasher = Sha256::new();
    let mut bounded = (&mut file).take(128 * 1024 * 1024 + 1);
    let mut buffer = [0_u8; 8192];
    loop {
        let count = bounded
            .read(&mut buffer)
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let after = file
        .metadata()
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if before.len() > 128 * 1024 * 1024
        || !same_file(&before, &after)
        || hasher.finalize().as_slice() != digest.as_bytes()
    {
        return invalid();
    }
    Ok(file)
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use dtx_connect_registry::AdapterKind;
    use dtx_domain::{ConnectorId, HostId, TenantId};

    use super::*;

    fn store(name: &str) -> LinuxMaterialStore {
        let root = std::env::temp_dir().join(format!(
            "dtx-material-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let store = LinuxMaterialStore::for_test(
            root,
            ConnectorTarget::new(
                TenantId::new(),
                HostId::new(),
                ConnectorId::new(),
                AdapterKind::Codex,
            ),
            HostOperationId::new(),
            ConnectorLifecycleOperationId::new(),
        );
        for (directory, mode) in [
            (store.layout.config_dir(), 0o750),
            (store.layout.trust_dir(), 0o750),
            (store.layout.config_dir().join("operations"), 0o700),
            (store.layout.durable_credential_dir(), 0o700),
            (store.layout.runtime_dir(), 0o750),
            (store.layout.credential_dir(), 0o750),
            (store.layout.credential_dir().join("staged"), 0o700),
        ] {
            fs::create_dir_all(&directory).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).unwrap();
            }
        }
        store
    }

    fn blank_store(name: &str) -> LinuxMaterialStore {
        let root = std::env::temp_dir().join(format!(
            "dtx-material-blank-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        LinuxMaterialStore::for_test(
            root,
            ConnectorTarget::new(
                TenantId::new(),
                HostId::new(),
                ConnectorId::new(),
                AdapterKind::Codex,
            ),
            HostOperationId::new(),
            ConnectorLifecycleOperationId::new(),
        )
    }

    fn digest<T>(bytes: &[u8], build: impl FnOnce([u8; 32]) -> T) -> T {
        build(Sha256::digest(bytes).into())
    }

    #[test]
    fn fixed_material_replays_exactly_and_conflicts_on_change() {
        let store = store("stage");
        let material = LinuxMaterial {
            config: b"config",
            enrollment_root_ca: b"e",
            control_server_root_ca: b"c",
            connector_issuer_root_ca: b"i",
            plan: b"plan",
        };
        let config = digest(material.config, ConfigDigest::from_bytes);
        let trust = derive_trust_digest(
            Sha256::digest(material.enrollment_root_ca).into(),
            Sha256::digest(material.control_server_root_ca).into(),
            Sha256::digest(material.connector_issuer_root_ca).into(),
        );
        let plan = digest(material.plan, PlanDigest::from_bytes);
        let capability = store.stage(material, config, trust, plan).unwrap();
        assert!(
            capability
                .path()
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".lifecycle.plan"))
        );
        assert!(store.stage(material, config, trust, plan).is_ok());
        let changed = LinuxMaterial {
            config: b"other",
            ..material
        };
        let changed_config = digest(changed.config, ConfigDigest::from_bytes);
        assert_eq!(
            store.stage(changed, changed_config, trust, plan),
            Err(PortError::new(PortErrorKind::Conflict))
        );
    }

    #[test]
    fn footprint_and_durable_recovery_fail_closed() {
        let store = blank_store("recovery");
        assert_eq!(
            store.inspect_prepare_footprint().unwrap(),
            LinuxPrepareFootprint::AllAbsent
        );
        for (directory, mode) in [
            (store.layout.config_dir(), 0o750),
            (store.layout.trust_dir(), 0o750),
            (store.layout.config_dir().join("operations"), 0o700),
            (store.layout.durable_credential_dir(), 0o700),
            (store.layout.runtime_dir(), 0o750),
            (store.layout.credential_dir(), 0o750),
            (store.layout.credential_dir().join("staged"), 0o700),
        ] {
            fs::create_dir_all(&directory).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).unwrap();
            }
        }
        fs::create_dir_all(store.layout.durable_credential_dir()).unwrap();
        fs::write(store.layout.durable_credential(), b"credential").unwrap();
        fs::write(
            store.layout.durable_bearer(),
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopw",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                store.layout.durable_credential(),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            fs::set_permissions(
                store.layout.durable_bearer(),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert_eq!(
            store.inspect_prepare_footprint().unwrap(),
            LinuxPrepareFootprint::Present
        );
        let credential = digest(b"credential", CredentialArtifactRef::from_bytes);
        let bearer_bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopw";
        assert_eq!(bearer_bytes.len(), 43);
        let bearer = digest(bearer_bytes, McpBearerRef::from_bytes);
        let artifact = store.materialize_durable(credential, bearer).unwrap();
        assert_eq!(artifact.reference(), credential);
        store.activate_staged_bearer(bearer).unwrap();
        store.activate_staged_bearer(bearer).unwrap();
        assert_eq!(
            fs::read(store.layout.active_bearer()).unwrap(),
            bearer_bytes
        );
        assert_eq!(
            store.materialize_durable(CredentialArtifactRef::from_bytes([0; 32]), bearer),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );

        let facts = store
            .adopted_credential_facts(7, Revision::INITIAL)
            .expect("secure durable facts");
        assert_eq!(facts.generation, 7);
        assert_eq!(facts.revision, Revision::INITIAL);
        assert_eq!(facts.credential_ref, credential);
        assert_eq!(facts.mcp_bearer_ref, bearer);
        assert_ne!(
            facts.credential_ref,
            digest(
                b"credential-leaf-fingerprint",
                CredentialArtifactRef::from_bytes
            )
        );
    }

    #[test]
    fn all_absent_footprint_does_not_require_service_identity() {
        let store = blank_store("identity-free");
        assert_eq!(
            store
                .inspect_prepare_footprint_with_gid(|| {
                    Err(PortError::new(PortErrorKind::InvalidArtifact))
                })
                .unwrap(),
            LinuxPrepareFootprint::AllAbsent
        );
    }

    #[test]
    fn footprint_rejects_an_unsafe_runtime_directory_as_ambiguous() {
        let store = store("runtime-mode");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                store.layout.runtime_dir(),
                fs::Permissions::from_mode(0o777),
            )
            .unwrap();
        }
        assert_eq!(
            store.inspect_prepare_footprint().unwrap(),
            LinuxPrepareFootprint::Ambiguous
        );
    }

    #[test]
    fn footprint_observes_data_directory_created_by_ensure() {
        let store = blank_store("data-footprint");
        fs::create_dir_all(store.layout.data_dir()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(store.layout.data_dir(), fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        assert_eq!(
            store.inspect_prepare_footprint().unwrap(),
            LinuxPrepareFootprint::Present
        );
    }

    #[test]
    fn linked_and_noncanonical_secret_are_rejected() {
        let store = store("linked");
        fs::create_dir_all(store.layout.durable_credential_dir()).unwrap();
        fs::write(store.layout.durable_credential(), b"credential").unwrap();
        fs::write(store.layout.durable_bearer(), b"not canonical=").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                store.layout.durable_credential(),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            fs::set_permissions(
                store.layout.durable_bearer(),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let credential = digest(b"credential", CredentialArtifactRef::from_bytes);
        let bearer = digest(b"not canonical=", McpBearerRef::from_bytes);
        assert_eq!(
            store.materialize_durable(credential, bearer),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
    }

    #[test]
    fn bearer_requires_the_canonical_32_byte_base64url_tail() {
        for tail in *b"AQgw" {
            let mut value = [b'A'; 43];
            value[42] = tail;
            assert!(canonical_bearer(&value));
        }
        let mut noncanonical = [b'A'; 43];
        noncanonical[42] = b'B';
        assert!(!canonical_bearer(&noncanonical));
    }

    #[test]
    fn trust_digest_is_domain_separated_and_component_ordered() {
        let first = derive_trust_digest([1; 32], [2; 32], [3; 32]);
        assert_ne!(first, derive_trust_digest([2; 32], [1; 32], [3; 32]));
        assert_ne!(
            first,
            TrustDigest::from_bytes(Sha256::digest([1_u8; 96]).into())
        );
    }

    #[cfg(unix)]
    fn test_command(name: &str, body: &str) -> LinuxBootstrapCommand {
        use std::os::unix::fs::PermissionsExt as _;
        let root = std::env::temp_dir().join(format!(
            "dtx-bootstrap-command-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("connector");
        fs::write(&executable, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        LinuxBootstrapCommand::for_test(
            &executable,
            &root.join("fixed.plan"),
            Duration::from_millis(200),
        )
    }

    #[cfg(unix)]
    #[test]
    fn production_runner_uses_fixed_argv_scrubbed_environment_and_stdin() {
        let command = test_command(
            "success",
            "test \"$1\" = bootstrap && test \"$2\" = --plan-file && test -n \"$3\" && test \"$#\" = 3 && cat",
        );
        assert_eq!(
            command
                .run(false, Zeroizing::new(b"handoff".to_vec()))
                .unwrap()
                .as_slice(),
            b"handoff"
        );
    }

    #[cfg(unix)]
    #[test]
    fn production_runner_rejects_nonzero_overflow_and_timeout() {
        assert_eq!(
            test_command("nonzero", "exit 7").run(false, Zeroizing::new(Vec::new())),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
        assert_eq!(
            test_command("overflow", "head -c 65537 /dev/zero")
                .run(false, Zeroizing::new(Vec::new())),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
        assert_eq!(
            test_command("hang", "sleep 5").run(true, Zeroizing::new(vec![0; 1024])),
            Err(PortError::new(PortErrorKind::Unavailable))
        );
    }

    #[cfg(unix)]
    #[test]
    fn production_runner_deadline_cleans_closed_stdout_and_pipe_holding_descendant() {
        for (name, script) in [
            ("closed-stdout", "exec 1>&-; sleep 5"),
            ("pipe-descendant", "sleep 5 & exec 1>&-; exit 0"),
        ] {
            let started = Instant::now();
            assert!(
                test_command(name, script)
                    .run(false, Zeroizing::new(Vec::new()))
                    .is_err()
            );
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "{name} escaped the runner deadline"
            );
        }
    }

    #[test]
    fn footprint_rejects_an_unsafe_fixed_parent_as_ambiguous() {
        let store = store("footprint-parent");
        fs::remove_dir(store.layout.trust_dir()).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/tmp", store.layout.trust_dir()).unwrap();
        assert_eq!(
            store.inspect_prepare_footprint().unwrap(),
            LinuxPrepareFootprint::Ambiguous
        );
    }

    #[test]
    fn adopted_facts_reject_an_unsafe_durable_ancestor() {
        let store = store("adopted-parent");
        fs::remove_dir(store.layout.durable_credential_dir()).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/tmp", store.layout.durable_credential_dir()).unwrap();
        assert_eq!(
            store.adopted_credential_facts(1, Revision::INITIAL),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
    }
}
