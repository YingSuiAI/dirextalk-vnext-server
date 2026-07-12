use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::Write as _,
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ProtocolToolError, load_error_registry, load_event_registry};

const BASELINE_PATH: &str = "protocol/baseline/v1/manifest.json";
const FROZEN_ARTIFACT_ROOTS: &[&str] = &[
    "protocol/cddl/v1",
    "protocol/openapi/v1",
    "protocol/proto",
    "protocol/test-vectors/v1",
];

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BaselineManifest {
    version: u16,
    events: BTreeMap<String, String>,
    errors: BTreeMap<String, String>,
    artifacts: BTreeMap<String, String>,
}

/// Creates the initial v1.0 baseline, or verifies an exact existing baseline.
///
/// Once created, the v1.0 manifest is immutable. Any registry or artifact
/// addition, mutation, or removal requires a new versioned contract and cannot
/// be incorporated by rerunning this command.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] for invalid registries, any difference from an
/// existing manifest, serialization, or I/O.
pub fn freeze_baseline(root: &Path) -> Result<(), ProtocolToolError> {
    let current = current_manifest(root)?;
    let path = root.join(BASELINE_PATH);
    if path.exists() {
        let baseline = read_manifest(&path)?;
        validate_manifest_version(&baseline)?;
        compare_exact_entries("event", &baseline.events, &current.events)?;
        compare_exact_entries("error", &baseline.errors, &current.errors)?;
        compare_exact_entries("artifact", &baseline.artifacts, &current.artifacts)
    } else {
        let parent = path
            .parent()
            .ok_or_else(|| ProtocolToolError::new("baseline path has no parent"))?;
        fs::create_dir_all(parent).map_err(|error| {
            ProtocolToolError::new(format!(
                "create baseline directory {}: {error}",
                parent.display()
            ))
        })?;
        write_manifest(&path, &current)
    }
}

/// Rejects removal, mutation, or an unreviewed/unfrozen addition in v1.
///
/// Additions require a new versioned contract; rerunning [`freeze_baseline`]
/// cannot modify an existing v1.0 manifest.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] when the current contract differs from the
/// exact reviewed baseline.
pub fn check_breaking(root: &Path) -> Result<(), ProtocolToolError> {
    let path = root.join(BASELINE_PATH);
    let baseline = read_manifest(&path)?;
    validate_manifest_version(&baseline)?;
    let current = current_manifest(root)?;
    compare_exact_entries("event", &baseline.events, &current.events)?;
    compare_exact_entries("error", &baseline.errors, &current.errors)?;
    compare_exact_entries("artifact", &baseline.artifacts, &current.artifacts)
}

fn current_manifest(root: &Path) -> Result<BaselineManifest, ProtocolToolError> {
    let events = load_event_registry(&root.join("protocol/events/registry.yaml"))?;
    let errors = load_error_registry(&root.join("protocol/errors/registry.yaml"))?;
    let event_hashes = events
        .events
        .iter()
        .map(|event| Ok((event.event_type.clone(), hash_json(event)?)))
        .collect::<Result<_, ProtocolToolError>>()?;
    let error_hashes = errors
        .errors
        .iter()
        .map(|error| Ok((error.code.clone(), hash_json(error)?)))
        .collect::<Result<_, ProtocolToolError>>()?;
    let artifact_hashes = collect_artifact_paths(root)?
        .into_iter()
        .map(|relative| {
            let bytes = fs::read(root.join(&relative)).map_err(|error| {
                ProtocolToolError::new(format!("read frozen artifact {relative}: {error}"))
            })?;
            Ok((relative, hash_bytes(&bytes)))
        })
        .collect::<Result<_, ProtocolToolError>>()?;
    Ok(BaselineManifest {
        version: 1,
        events: event_hashes,
        errors: error_hashes,
        artifacts: artifact_hashes,
    })
}

fn collect_artifact_paths(root: &Path) -> Result<Vec<String>, ProtocolToolError> {
    let mut paths = Vec::new();
    for relative_root in FROZEN_ARTIFACT_ROOTS {
        collect_artifact_paths_inner(root, &root.join(relative_root), &mut paths)?;
    }
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err(ProtocolToolError::new(
            "no protocol artifacts found to freeze",
        ));
    }
    Ok(paths)
}

fn collect_artifact_paths_inner(
    repository_root: &Path,
    directory: &Path,
    output: &mut Vec<String>,
) -> Result<(), ProtocolToolError> {
    let entries = fs::read_dir(directory).map_err(|error| {
        ProtocolToolError::new(format!(
            "read artifact directory {}: {error}",
            directory.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            ProtocolToolError::new(format!(
                "read artifact directory entry {}: {error}",
                directory.display()
            ))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            ProtocolToolError::new(format!(
                "read file type {}: {error}",
                entry.path().display()
            ))
        })?;
        if file_type.is_symlink() {
            return Err(ProtocolToolError::new(format!(
                "frozen protocol artifact cannot be a symlink: {}",
                entry.path().display()
            )));
        }
        if file_type.is_dir() {
            collect_artifact_paths_inner(repository_root, &entry.path(), output)?;
        } else if file_type.is_file() {
            let path = entry.path();
            let relative = path.strip_prefix(repository_root).map_err(|_| {
                ProtocolToolError::new("frozen protocol artifact escaped repository root")
            })?;
            output.push(normalize_relative(relative)?);
        }
    }
    Ok(())
}

fn normalize_relative(path: &Path) -> Result<String, ProtocolToolError> {
    path.components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| ProtocolToolError::new("protocol artifact path must be UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join("/"))
}

fn read_manifest(path: &Path) -> Result<BaselineManifest, ProtocolToolError> {
    serde_json::from_str(&fs::read_to_string(path).map_err(|error| {
        ProtocolToolError::new(format!("read baseline {}: {error}", path.display()))
    })?)
    .map_err(|error| ProtocolToolError::new(format!("parse baseline: {error}")))
}

fn validate_manifest_version(manifest: &BaselineManifest) -> Result<(), ProtocolToolError> {
    if manifest.version == 1 {
        Ok(())
    } else {
        Err(ProtocolToolError::new("baseline version must be 1"))
    }
}

fn write_manifest(path: &Path, manifest: &BaselineManifest) -> Result<(), ProtocolToolError> {
    let source = serde_json::to_string_pretty(manifest)
        .map_err(|error| ProtocolToolError::new(format!("serialize baseline: {error}")))?
        + "\n";
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(path).map_err(|error| {
        ProtocolToolError::new(format!("open baseline {}: {error}", path.display()))
    })?;
    file.write_all(source.as_bytes()).map_err(|error| {
        ProtocolToolError::new(format!("write baseline {}: {error}", path.display()))
    })?;
    file.sync_all().map_err(|error| {
        ProtocolToolError::new(format!("sync baseline {}: {error}", path.display()))
    })
}

fn hash_json<T>(value: &T) -> Result<String, ProtocolToolError>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ProtocolToolError::new(format!("serialize baseline entry: {error}")))?;
    Ok(hash_bytes(&bytes))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn compare_frozen_entries(
    kind: &str,
    baseline: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
) -> Result<(), ProtocolToolError> {
    for (name, expected) in baseline {
        let Some(actual) = current.get(name) else {
            return Err(ProtocolToolError::new(format!(
                "frozen {kind} was removed: {name}; v1.0 is immutable, create a new versioned contract"
            )));
        };
        if actual != expected {
            return Err(ProtocolToolError::new(format!(
                "frozen {kind} changed: {name}; v1.0 is immutable, create a new versioned contract"
            )));
        }
    }
    Ok(())
}

fn compare_exact_entries(
    kind: &str,
    baseline: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
) -> Result<(), ProtocolToolError> {
    compare_frozen_entries(kind, baseline, current)?;
    for name in current.keys() {
        if !baseline.contains_key(name) {
            return Err(ProtocolToolError::new(format!(
                "unfrozen {kind} addition: {name}; v1.0 is immutable, create a new versioned contract"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(values: &[(&str, &str)]) -> BTreeMap<String, String> {
        values
            .iter()
            .map(|(name, hash)| ((*name).to_owned(), (*hash).to_owned()))
            .collect()
    }

    #[test]
    fn exact_check_rejects_an_unfrozen_addition() {
        let baseline = entries(&[("existing", "sha256:1")]);
        let current = entries(&[("existing", "sha256:1"), ("new", "sha256:2")]);
        let error = compare_exact_entries("event", &baseline, &current).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unfrozen event addition: new; v1.0 is immutable, create a new versioned contract"
        );
    }

    #[test]
    fn immutable_freeze_check_rejects_additions_and_old_hash_changes() {
        let baseline = entries(&[("existing", "sha256:1")]);
        let additive = entries(&[("existing", "sha256:1"), ("new", "sha256:2")]);
        assert!(compare_exact_entries("event", &baseline, &additive).is_err());

        let changed = entries(&[("existing", "sha256:changed")]);
        let error = compare_exact_entries("event", &baseline, &changed).unwrap_err();
        assert_eq!(
            error.to_string(),
            "frozen event changed: existing; v1.0 is immutable, create a new versioned contract"
        );
    }

    #[test]
    fn recursive_artifact_discovery_includes_new_nested_files() {
        let unique = format!(
            "dtx-protocol-baseline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        for relative in FROZEN_ARTIFACT_ROOTS {
            fs::create_dir_all(root.join(relative)).unwrap();
            fs::write(root.join(relative).join("artifact.txt"), b"contract").unwrap();
        }
        let nested = root.join("protocol/proto/dirextalk/v1/nested.proto");
        fs::create_dir_all(nested.parent().unwrap()).unwrap();
        fs::write(&nested, b"syntax = \"proto3\";").unwrap();

        let paths = collect_artifact_paths(&root).unwrap();
        assert!(paths.contains(&"protocol/proto/dirextalk/v1/nested.proto".to_owned()));
        assert_eq!(paths.len(), FROZEN_ARTIFACT_ROOTS.len() + 1);

        fs::remove_dir_all(&root).unwrap();
    }
}
