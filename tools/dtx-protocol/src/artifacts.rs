use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;

use crate::ProtocolToolError;

/// Parses the current Product Core Alpha source schemas and vectors.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] for missing or malformed CDDL, `OpenAPI`, or
/// JSON artifacts. Cross-artifact contract checks live in the dedicated
/// current-version validators.
pub fn validate_artifacts(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl_root = root.join("protocol/cddl/v1");
    let common = read(&cddl_root.join("common.cddl"))?;
    for path in collect_files(&cddl_root, Some("cddl"))? {
        let source = read(&path)?;
        let complete = if path.file_name().and_then(|value| value.to_str()) == Some("common.cddl") {
            source
        } else {
            format!("{common}\n{source}")
        };
        cddl_cat::parse_cddl(&complete).map_err(|error| {
            ProtocolToolError::new(format!("parse CDDL {}: {error}", path.display()))
        })?;
    }

    for relative in [
        "identity-log/v1_1/identity-log-v1-1.cddl",
        "contact-card/v1/contact-card-v1.cddl",
        "contact-delivery/v1/contact-delivery-v1.cddl",
        "conversation-admission/v1/conversation-admission-v1.cddl",
        "group-membership-discovery/v1/group-membership-discovery-v1.cddl",
        "group-query-proof/v1/group-query-proof-overlay-v1.cddl",
        "membership/v2/membership-v2.cddl",
        "membership-federation/v2/membership-federation-v2.cddl",
        "identity-http/v1/identity-bootstrap-v1.cddl",
        "identity-log-page/v1/identity-log-page-v1.cddl",
        "identity-session/v1/device-session-v1.cddl",
        "identity-enrollment/v1/identity-enrollment-v1.cddl",
        "attachment/v1/attachment-v1.cddl",
        "key-package/v4/key-package-v4.cddl",
        "mls-sequencer/v7/mls-sequencer-v7.cddl",
        "history-recovery/v3/history-recovery-v3.cddl",
        "recovery-scope-catalog/v2/recovery-scope-catalog-v2.cddl",
        "realtime-sync/v2/realtime-sync-v2.cddl",
        "account-read-cursor/v1/account-read-cursor-v1.cddl",
        "mailbox/v1/mailbox-v1.cddl",
        "opaque-push/v1/opaque-push-v1.cddl",
        "private-event/v1/private-event-v1.cddl",
        "private-event/v8/private-group-reaction-v8.cddl",
    ] {
        let complete = read(&root.join("protocol/cddl").join(relative))?;
        cddl_cat::parse_cddl(&complete).map_err(|error| {
            ProtocolToolError::new(format!("parse Alpha CDDL {relative}: {error}"))
        })?;
    }

    for relative in [
        "v1/openapi.yaml",
        "identity/v1/openapi.yaml",
        "identity-log-page/v1/openapi.yaml",
        "identity-session/v1/openapi.yaml",
        "identity-enrollment/v1/openapi.yaml",
        "attachment/v1/openapi.yaml",
        "contact-delivery/v1/openapi.yaml",
        "group-membership-discovery/v1/openapi.yaml",
        "group-query-proof/v1/openapi.yaml",
        "membership/v2/openapi.yaml",
        "membership-federation/v2/openapi.yaml",
        "key-package/v4/openapi.yaml",
        "mls-sequencer/v7/openapi.yaml",
        "history-recovery/v3/openapi.yaml",
        "recovery-scope-catalog/v2/openapi.yaml",
        "mailbox/v1/openapi.yaml",
        "opaque-push/v1/openapi.yaml",
    ] {
        let source = read(&root.join("protocol/openapi").join(relative))?;
        oas3::from_yaml(&source).map_err(|error| {
            ProtocolToolError::new(format!("parse Alpha OpenAPI {relative}: {error}"))
        })?;
    }

    for relative in [
        "v1/api-errors.json",
        "v1/event-envelope.json",
        "v1/plan-hash.json",
        "v1/public-ids.json",
        "identity-log/v1_1/identity-log-v1_1.json",
        "contact-card/v1/contact-card-v1.json",
        "contact-delivery/v1/contact-request-aad-v1.json",
        "conversation-admission/v1/conversation-admission-v1.json",
        "group-membership-discovery/v1/group-query-v1.json",
        "group-query-proof/v1/group-query-proof-overlay-v1.json",
        "membership/v2/membership-v2.json",
        "membership-federation/v2/membership-federation-v2.json",
        "identity-http/v1/identity-bootstrap-v1.json",
        "identity-log-page/v1/identity-log-page-v1.json",
        "identity-session/v1/device-session-v1.json",
        "identity-enrollment/v1/identity-enrollment-v1.json",
        "recovery-scope-catalog/v2/recovery-scope-catalog-v2.json",
        "realtime-sync/v2/realtime-sync-v2.json",
        "account-read-cursor/v1/account-read-cursor-v1.json",
        "mailbox/v1/mailbox-v1.json",
        "attachment/v1/attachment-v1.json",
        "opaque-push/v1/opaque-push-v1.json",
        "private-event/v1/private-event-v1.json",
        "private-event/v8/private-group-reaction-v8.json",
    ] {
        read_json(&root.join("protocol/test-vectors").join(relative))?;
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<Value, ProtocolToolError> {
    serde_json::from_str(&read(path)?)
        .map_err(|error| ProtocolToolError::new(format!("parse {}: {error}", path.display())))
}

fn read(path: &Path) -> Result<String, ProtocolToolError> {
    fs::read_to_string(path)
        .map_err(|error| ProtocolToolError::new(format!("read {}: {error}", path.display())))
}

fn collect_files(root: &Path, extension: Option<&str>) -> Result<Vec<PathBuf>, ProtocolToolError> {
    let mut files = Vec::new();
    collect_files_inner(root, extension, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files_inner(
    root: &Path,
    extension: Option<&str>,
    output: &mut Vec<PathBuf>,
) -> Result<(), ProtocolToolError> {
    let entries = fs::read_dir(root).map_err(|error| {
        ProtocolToolError::new(format!("read directory {}: {error}", root.display()))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            ProtocolToolError::new(format!("read directory entry {}: {error}", root.display()))
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            ProtocolToolError::new(format!("read file type {}: {error}", path.display()))
        })?;
        if file_type.is_symlink() {
            return Err(ProtocolToolError::new(format!(
                "protocol artifact cannot be a symlink: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            collect_files_inner(&path, extension, output)?;
        } else if file_type.is_file()
            && extension.is_none_or(|expected| {
                path.extension().and_then(|value| value.to_str()) == Some(expected)
            })
        {
            output.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_alpha_sources_parse() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        validate_artifacts(&root).unwrap();
    }
}
