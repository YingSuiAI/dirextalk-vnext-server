use std::path::{Path, PathBuf};

use dtx_connect_registry::AdapterKind;
use dtx_domain::ConnectorId;
use uuid::Uuid;

use crate::{
    CatalogRelease, ConnectorLifecycleOperationId, ConnectorTarget, HostOperationId,
    ProcessMutationId, ReleaseDigest, ResourceProfile,
};

pub(super) const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
pub(super) const SYSTEMCTL: &str = "/usr/bin/systemctl";
pub(super) const USERADD: &str = "/usr/sbin/useradd";
pub(super) const INSTALL: &str = "/usr/bin/install";
pub(super) const CHOWN: &str = "/usr/bin/chown";
pub(super) const NFT: &str = "/usr/sbin/nft";
pub(super) const NOLOGIN: &str = "/usr/sbin/nologin";

const BASE32: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ConnectorLayout {
    root: PathBuf,
    target: ConnectorTarget,
}

impl ConnectorLayout {
    pub(super) fn production(target: ConnectorTarget) -> Self {
        Self::under(PathBuf::from("/"), target)
    }

    pub(super) fn under(root: PathBuf, target: ConnectorTarget) -> Self {
        Self { root, target }
    }

    #[cfg(test)]
    pub(super) fn for_test(root: PathBuf, target: ConnectorTarget) -> Self {
        Self::under(root, target)
    }

    pub(super) fn connector_id(&self) -> ConnectorId {
        self.target.connector_id()
    }

    pub(super) fn user(&self) -> String {
        connector_user(self.target.connector_id())
    }

    pub(super) fn unit(&self) -> String {
        format!("dirextalk-connect@{}.service", self.target.connector_id())
    }

    pub(super) fn executable(&self, release: CatalogRelease) -> PathBuf {
        self.rooted(&format!(
            "/opt/dirextalk/connect/versions/{}/dirextalk-agent-connector",
            digest_hex(release.digest())
        ))
    }

    pub(super) fn config_dir(&self) -> PathBuf {
        self.rooted(&format!(
            "/etc/dirextalk/connect/instances/{}",
            self.target.connector_id()
        ))
    }

    pub(super) fn config(&self) -> PathBuf {
        self.config_dir().join("config.toml")
    }

    pub(super) fn current_user_profile(&self) -> PathBuf {
        self.rooted("/etc/dirextalk/connect/current-user.profile")
    }

    pub(super) fn service_profile_binding(&self) -> PathBuf {
        self.config_dir().join("service-profile.binding")
    }

    pub(super) fn trust_dir(&self) -> PathBuf {
        self.config_dir().join("trust")
    }

    pub(super) fn enrollment_root_ca(&self) -> PathBuf {
        self.trust_dir().join("enrollment-root-ca.pem")
    }

    pub(super) fn control_server_root_ca(&self) -> PathBuf {
        self.trust_dir().join("control-server-root-ca.pem")
    }

    pub(super) fn connector_issuer_root_ca(&self) -> PathBuf {
        self.trust_dir().join("connector-issuer-root-ca.pem")
    }

    pub(super) fn lifecycle_plan(&self, operation_id: ConnectorLifecycleOperationId) -> PathBuf {
        self.config_dir()
            .join("operations")
            .join(format!("{}.lifecycle.plan", operation_id.as_request_id()))
    }

    pub(super) fn durable_credential_dir(&self) -> PathBuf {
        self.rooted(&format!(
            "/var/lib/dirextalk/connect/instances/{}/credentials",
            self.target.connector_id()
        ))
    }

    pub(super) fn durable_credential(&self) -> PathBuf {
        self.durable_credential_dir().join("control.credential")
    }

    pub(super) fn durable_bearer(&self) -> PathBuf {
        self.durable_credential_dir().join("mcp.bearer")
    }

    pub(super) fn durable_pending(&self) -> PathBuf {
        self.durable_credential_dir()
            .join("control.credential.bootstrap.pending")
    }
    pub(super) fn durable_claim(&self) -> PathBuf {
        self.durable_credential_dir()
            .join("control.credential.bootstrap.claim")
    }
    pub(super) fn durable_receipt(&self, operation_id: ConnectorLifecycleOperationId) -> PathBuf {
        self.durable_credential_dir().join(format!(
            "control.credential.bootstrap.receipt.{}",
            operation_id.as_request_id()
        ))
    }
    pub(super) fn durable_finalized(&self, operation_id: ConnectorLifecycleOperationId) -> PathBuf {
        self.durable_credential_dir().join(format!(
            "control.credential.bootstrap.receipt.{}.finalized",
            operation_id.as_request_id()
        ))
    }

    pub(super) fn release_manifest(&self) -> PathBuf {
        self.config_dir().join("release.manifest")
    }

    pub(super) fn network_policy(&self) -> PathBuf {
        self.config_dir().join("imds-policy.nft")
    }

    pub(super) fn network_policy_table(&self) -> String {
        format!("dtx_hs_{}", self.target.connector_id()).replace('-', "")
    }

    pub(super) fn data_dir(&self) -> PathBuf {
        self.rooted(&format!(
            "/var/lib/dirextalk/connect/instances/{}/data",
            self.target.connector_id()
        ))
    }

    pub(super) fn workspace_dir(&self) -> PathBuf {
        self.rooted(&format!(
            "/var/lib/dirextalk/connect/instances/{}/workspace",
            self.target.connector_id()
        ))
    }

    pub(super) fn runtime_dir(&self) -> PathBuf {
        self.rooted(&format!(
            "/run/dirextalk/connect/{}",
            self.target.connector_id()
        ))
    }

    pub(super) fn credential_dir(&self) -> PathBuf {
        self.runtime_dir().join("credentials")
    }

    pub(super) fn worker_runtime_dir(&self) -> PathBuf {
        self.runtime_dir().join("worker")
    }

    pub(super) fn active_credential(&self) -> PathBuf {
        self.credential_dir().join("control.credential")
    }

    pub(super) fn active_bearer(&self) -> PathBuf {
        self.credential_dir().join("mcp.bearer")
    }

    pub(super) fn active_credential_record(&self) -> PathBuf {
        self.credential_dir().join("control.credential.meta")
    }

    pub(super) fn staged_credential(&self, operation_id: HostOperationId) -> PathBuf {
        self.credential_dir()
            .join("staged")
            .join(format!("{}.credential", operation_id.as_request_id()))
    }

    pub(super) fn staged_bearer(&self, operation_id: HostOperationId) -> PathBuf {
        self.credential_dir()
            .join("staged")
            .join(format!("{}.mcp.bearer", operation_id.as_request_id()))
    }

    pub(super) fn ready_bearer(&self, mutation_id: ProcessMutationId) -> PathBuf {
        self.credential_dir().join("staged").join(format!(
            "{}.{}.mcp.bearer.ready",
            mutation_id.operation_id().as_request_id(),
            mutation_id.phase().idempotency_label()
        ))
    }

    pub(super) fn ready_credential(&self, mutation_id: ProcessMutationId) -> PathBuf {
        self.credential_dir().join("staged").join(format!(
            "{}.{}.ready",
            mutation_id.operation_id().as_request_id(),
            mutation_id.phase().idempotency_label()
        ))
    }

    pub(super) fn log_dir(&self) -> PathBuf {
        self.rooted(&format!(
            "/var/lib/dirextalk/connect/instances/{}/logs",
            self.target.connector_id()
        ))
    }

    pub(super) fn restart_marker(&self, mutation_id: ProcessMutationId) -> PathBuf {
        self.config_dir().join("operations").join(format!(
            "{}.{}.restart",
            mutation_id.operation_id().as_request_id(),
            mutation_id.phase().idempotency_label()
        ))
    }

    pub(super) fn crash_loop_marker(&self) -> PathBuf {
        self.config_dir().join("crash-loop.blocked")
    }

    pub(super) fn passwd(&self) -> PathBuf {
        self.rooted("/etc/passwd")
    }

    pub(super) fn proc_status(&self, pid: u32) -> PathBuf {
        self.rooted(&format!("/proc/{pid}/status"))
    }

    pub(super) fn proc_cgroup(&self, pid: u32) -> PathBuf {
        self.rooted(&format!("/proc/{pid}/cgroup"))
    }

    pub(super) fn proc_executable(&self, pid: u32) -> PathBuf {
        self.rooted(&format!("/proc/{pid}/exe"))
    }

    pub(super) fn directories(&self) -> [PathBuf; 11] {
        [
            self.config_dir(),
            self.trust_dir(),
            self.config_dir().join("operations"),
            self.data_dir(),
            self.workspace_dir(),
            self.runtime_dir(),
            self.worker_runtime_dir(),
            self.credential_dir(),
            self.credential_dir().join("staged"),
            self.durable_credential_dir(),
            self.log_dir(),
        ]
    }

    pub(super) fn target(&self) -> ConnectorTarget {
        self.target
    }

    fn rooted(&self, absolute: &str) -> PathBuf {
        if self.root == Path::new("/") {
            PathBuf::from(absolute)
        } else {
            self.root.join(absolute.trim_start_matches('/'))
        }
    }
}

pub(super) fn digest_hex(digest: ReleaseDigest) -> String {
    let mut value = String::with_capacity(64);
    for byte in digest.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

pub(super) const fn adapter_name(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::Codex => "codex",
        AdapterKind::OpenClawAcp => "openclaw-acp",
        AdapterKind::Eino => "eino",
        AdapterKind::Rig => "rig",
        AdapterKind::ClaudeCode => "claude-code",
        AdapterKind::CustomAcp => "custom-acp",
        AdapterKind::HermesAcp => "hermes-acp",
    }
}

pub(super) const fn profile_name(profile: ResourceProfile) -> &'static str {
    match profile {
        ResourceProfile::Standard => "standard",
        ResourceProfile::Compute => "compute",
        ResourceProfile::LowLatency => "low-latency",
    }
}

fn connector_user(connector_id: ConnectorId) -> String {
    let mut value = Uuid::from(connector_id).as_u128();
    let mut encoded = [b'0'; 26];
    for byte in encoded.iter_mut().rev() {
        *byte = BASE32[(value & 31) as usize];
        value >>= 5;
    }
    format!(
        "dtx{}",
        std::str::from_utf8(&encoded).expect("base32 alphabet is UTF-8")
    )
}

#[cfg(test)]
mod tests {
    use dtx_connect_registry::AdapterKind;
    use dtx_domain::{ConnectorId, HostId, Revision, TenantId};

    use super::*;
    use crate::ReleaseDigest;

    #[test]
    fn layout_and_user_are_fixed_and_sibling_isolated() {
        let root = PathBuf::from("test-root");
        let target = ConnectorTarget::new(
            TenantId::new(),
            HostId::new(),
            ConnectorId::new(),
            AdapterKind::Codex,
        );
        let sibling = ConnectorTarget::new(
            target.tenant_id(),
            target.host_id(),
            ConnectorId::new(),
            AdapterKind::Codex,
        );
        let layout = ConnectorLayout::for_test(root.clone(), target);
        let sibling = ConnectorLayout::for_test(root, sibling);
        let release = CatalogRelease::approved(
            AdapterKind::Codex,
            ReleaseDigest::from_bytes([0xab; 32]),
            ResourceProfile::Standard,
            Revision::INITIAL,
        );

        assert_eq!(layout.user().len(), 29);
        assert!(layout.user().starts_with("dtx"));
        assert_ne!(layout.user(), sibling.user());
        assert_ne!(layout.config_dir(), sibling.config_dir());
        assert_ne!(layout.workspace_dir(), sibling.workspace_dir());
        assert!(layout.unit().starts_with("dirextalk-connect@"));
        assert!(
            layout
                .executable(release)
                .ends_with(format!("{}/dirextalk-agent-connector", "ab".repeat(32)))
        );

        let host_operation = HostOperationId::new();
        let lifecycle_operation = ConnectorLifecycleOperationId::new();
        assert_ne!(
            layout.staged_credential(host_operation),
            layout.lifecycle_plan(lifecycle_operation)
        );
        let expected_finalized = format!(
            "control.credential.bootstrap.receipt.{}.finalized",
            lifecycle_operation.as_request_id()
        );
        assert_eq!(
            layout
                .durable_finalized(lifecycle_operation)
                .file_name()
                .and_then(|value| value.to_str()),
            Some(expected_finalized.as_str())
        );
    }
}
