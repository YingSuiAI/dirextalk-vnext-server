use std::{collections::BTreeMap, fs, path::Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ProtocolToolError, load_error_registry, load_event_registry};

const MANIFEST_PATH: &str = "protocol/alpha/manifest.json";
const ALPHA_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/v1/api-error.cddl",
    "protocol/cddl/v1/common.cddl",
    "protocol/cddl/v1/event-envelope.cddl",
    "protocol/cddl/v1/event-page.cddl",
    "protocol/cddl/v1/plan-hash-fixture.cddl",
    "protocol/openapi/v1/openapi.yaml",
    "protocol/test-vectors/v1/api-errors.json",
    "protocol/test-vectors/v1/event-envelope.json",
    "protocol/test-vectors/v1/plan-hash.json",
    "protocol/test-vectors/v1/public-ids.json",
    "protocol/cddl/identity-log/v1_1/identity-log-v1-1.cddl",
    "protocol/test-vectors/identity-log/v1_1/identity-log-v1_1.json",
    "protocol/cddl/identity-http/v1/identity-bootstrap-v1.cddl",
    "protocol/openapi/identity/v1/openapi.yaml",
    "protocol/test-vectors/identity-http/v1/identity-bootstrap-v1.json",
    "protocol/cddl/identity-log-page/v1/identity-log-page-v1.cddl",
    "protocol/openapi/identity-log-page/v1/openapi.yaml",
    "protocol/test-vectors/identity-log-page/v1/identity-log-page-v1.json",
    "protocol/cddl/identity-session/v1/device-session-v1.cddl",
    "protocol/openapi/identity-session/v1/openapi.yaml",
    "protocol/test-vectors/identity-session/v1/device-session-v1.json",
    "protocol/cddl/identity-enrollment/v1/identity-enrollment-v1.cddl",
    "protocol/openapi/identity-enrollment/v1/openapi.yaml",
    "protocol/test-vectors/identity-enrollment/v1/identity-enrollment-v1.json",
    "protocol/cddl/contact-card/v1/contact-card-v1.cddl",
    "protocol/test-vectors/contact-card/v1/contact-card-v1.json",
    "protocol/cddl/contact-delivery/v1/contact-delivery-v1.cddl",
    "protocol/openapi/contact-delivery/v1/openapi.yaml",
    "protocol/test-vectors/contact-delivery/v1/contact-request-aad-v1.json",
    "protocol/cddl/conversation-admission/v1/conversation-admission-v1.cddl",
    "protocol/test-vectors/conversation-admission/v1/conversation-admission-v1.json",
    "protocol/cddl/group-membership-discovery/v1/group-membership-discovery-v1.cddl",
    "protocol/openapi/group-membership-discovery/v1/openapi.yaml",
    "protocol/test-vectors/group-membership-discovery/v1/group-query-v1.json",
    "protocol/cddl/group-query-proof/v1/group-query-proof-overlay-v1.cddl",
    "protocol/openapi/group-query-proof/v1/openapi.yaml",
    "protocol/test-vectors/group-query-proof/v1/group-query-proof-overlay-v1.json",
    "protocol/cddl/membership/v2/membership-v2.cddl",
    "protocol/openapi/membership/v2/openapi.yaml",
    "protocol/test-vectors/membership/v2/membership-v2.json",
    "protocol/cddl/membership-federation/v2/membership-federation-v2.cddl",
    "protocol/openapi/membership-federation/v2/openapi.yaml",
    "protocol/test-vectors/membership-federation/v2/membership-federation-v2.json",
    "protocol/cddl/key-package/v4/key-package-v4.cddl",
    "protocol/openapi/key-package/v4/openapi.yaml",
    "protocol/cddl/mls-sequencer/v7/mls-sequencer-v7.cddl",
    "protocol/openapi/mls-sequencer/v7/openapi.yaml",
    "protocol/cddl/history-recovery/v3/history-recovery-v3.cddl",
    "protocol/openapi/history-recovery/v3/openapi.yaml",
    "protocol/cddl/recovery-scope-catalog/v2/recovery-scope-catalog-v2.cddl",
    "protocol/openapi/recovery-scope-catalog/v2/openapi.yaml",
    "protocol/test-vectors/recovery-scope-catalog/v2/recovery-scope-catalog-v2.json",
    "protocol/cddl/realtime-sync/v2/realtime-sync-v2.cddl",
    "protocol/test-vectors/realtime-sync/v2/realtime-sync-v2.json",
    "protocol/cddl/account-read-cursor/v1/account-read-cursor-v1.cddl",
    "protocol/test-vectors/account-read-cursor/v1/account-read-cursor-v1.json",
    "protocol/cddl/mailbox/v1/mailbox-v1.cddl",
    "protocol/openapi/mailbox/v1/openapi.yaml",
    "protocol/test-vectors/mailbox/v1/mailbox-v1.json",
    "protocol/cddl/attachment/v1/attachment-v1.cddl",
    "protocol/openapi/attachment/v1/openapi.yaml",
    "protocol/test-vectors/attachment/v1/attachment-v1.json",
    "protocol/cddl/opaque-push/v1/opaque-push-v1.cddl",
    "protocol/openapi/opaque-push/v1/openapi.yaml",
    "protocol/test-vectors/opaque-push/v1/opaque-push-v1.json",
    "protocol/cddl/private-event/v1/private-event-v1.cddl",
    "protocol/test-vectors/private-event/v1/private-event-v1.json",
    "protocol/cddl/private-event/v8/private-group-reaction-v8.cddl",
    "protocol/test-vectors/private-event/v8/private-group-reaction-v8.json",
];

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AlphaManifest {
    release: String,
    registries: BTreeMap<String, String>,
    artifacts: BTreeMap<String, String>,
}

/// Verifies the exact current Product Core Alpha inventory.
pub fn check_alpha(root: &Path) -> Result<(), ProtocolToolError> {
    let manifest_path = root.join(MANIFEST_PATH);
    let manifest = read_manifest(&manifest_path)?;
    if manifest.release != "product-core-alpha" {
        return Err(ProtocolToolError::new(
            "Alpha manifest release must be product-core-alpha",
        ));
    }
    let current = current_manifest(root)?;
    compare_entries("registry", &manifest.registries, &current.registries)?;
    compare_entries("artifact", &manifest.artifacts, &current.artifacts)
}

/// Writes the current Alpha inventory once during an intentional contract update.
pub fn write_alpha(root: &Path) -> Result<(), ProtocolToolError> {
    let manifest = current_manifest(root)?;
    let path = root.join(MANIFEST_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io_error("create Alpha manifest directory"))?;
    }
    let source = serde_json::to_string_pretty(&manifest)
        .map_err(|error| ProtocolToolError::new(format!("serialize Alpha manifest: {error}")))?
        + "\n";
    fs::write(path, source).map_err(io_error("write Alpha manifest"))
}

fn current_manifest(root: &Path) -> Result<AlphaManifest, ProtocolToolError> {
    let events_path = root.join("protocol/events/registry.yaml");
    let errors_path = root.join("protocol/errors/registry.yaml");
    load_event_registry(&events_path)?;
    load_error_registry(&errors_path)?;

    let mut registries = BTreeMap::new();
    registries.insert(
        "protocol/events/registry.yaml".to_owned(),
        hash_bytes(&fs::read(&events_path).map_err(io_error("read event registry"))?),
    );
    registries.insert(
        "protocol/errors/registry.yaml".to_owned(),
        hash_bytes(&fs::read(&errors_path).map_err(io_error("read error registry"))?),
    );

    let mut artifacts = BTreeMap::new();
    for relative in ALPHA_ARTIFACT_PATHS {
        let path = root.join(relative);
        let metadata =
            fs::symlink_metadata(&path).map_err(io_error("read Alpha artifact metadata"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ProtocolToolError::new(format!(
                "Alpha artifact must be a regular file: {relative}"
            )));
        }
        artifacts.insert(
            (*relative).to_owned(),
            hash_bytes(&fs::read(path).map_err(io_error("read Alpha artifact"))?),
        );
    }
    Ok(AlphaManifest {
        release: "product-core-alpha".to_owned(),
        registries,
        artifacts,
    })
}

fn read_manifest(path: &Path) -> Result<AlphaManifest, ProtocolToolError> {
    let source = fs::read_to_string(path).map_err(io_error("read Alpha manifest"))?;
    serde_json::from_str(&source)
        .map_err(|error| ProtocolToolError::new(format!("parse Alpha manifest: {error}")))
}

fn compare_entries(
    kind: &str,
    expected: &BTreeMap<String, String>,
    actual: &BTreeMap<String, String>,
) -> Result<(), ProtocolToolError> {
    for (path, digest) in expected {
        match actual.get(path) {
            Some(current) if current == digest => {}
            Some(_) => {
                return Err(ProtocolToolError::new(format!(
                    "Alpha {kind} changed: {path}"
                )));
            }
            None => {
                return Err(ProtocolToolError::new(format!(
                    "Alpha {kind} removed: {path}"
                )));
            }
        }
    }
    for path in actual.keys() {
        if !expected.contains_key(path) {
            return Err(ProtocolToolError::new(format!(
                "Alpha {kind} addition is not in protocol/alpha/manifest.json: {path}"
            )));
        }
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn io_error(context: &'static str) -> impl FnOnce(std::io::Error) -> ProtocolToolError {
    move |error| ProtocolToolError::new(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_agent_and_public_sources_are_outside_alpha_inventory() {
        assert!(
            !ALPHA_ARTIFACT_PATHS
                .contains(&"protocol/proto/dirextalk/agent_control/v1/agent_control.proto")
        );
        assert!(
            !ALPHA_ARTIFACT_PATHS
                .contains(&"protocol/test-vectors/public-feed/v1/public-feed-v1.json")
        );
        assert!(!ALPHA_ARTIFACT_PATHS.contains(
            &"protocol/test-vectors/private-event/v6_v7/private-agent-approval-v6-v7.json"
        ));
    }
}
