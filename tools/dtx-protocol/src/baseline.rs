use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::Write as _,
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ProtocolToolError, load_error_registry, load_event_registry};

const V1_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/v1",
    "protocol/openapi/v1",
    "protocol/proto/buf.yaml",
    "protocol/proto/dirextalk/v1",
    "protocol/test-vectors/v1",
];
const V2_ARTIFACT_PATHS: &[&str] = &["protocol/proto/dirextalk/agent_control/v1"];
const V3_ARTIFACT_PATHS: &[&str] = &["protocol/proto/dirextalk/agent_control/v1_1"];
const V4_ARTIFACT_PATHS: &[&str] = &["protocol/proto/dirextalk/agent_gateway/v1"];
const V5_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/identity-log/v1",
    "protocol/test-vectors/identity-log/v1",
];
const V6_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/identity-log/v1_1",
    "protocol/test-vectors/identity-log/v1_1",
];
const V7_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/public-descriptor/v1",
    "protocol/test-vectors/public-descriptor/v1",
];
const V8_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/public-descriptor/v1_1",
    "protocol/test-vectors/public-descriptor/v1_1",
];
const V9_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/public-descriptor/v1_2",
    "protocol/test-vectors/public-descriptor/v1_2",
];
const V10_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/identity-http/v1",
    "protocol/openapi/identity/v1",
    "protocol/test-vectors/identity-http/v1",
];
const V11_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/identity-session/v1",
    "protocol/openapi/identity-session/v1",
    "protocol/test-vectors/identity-session/v1",
];
const V12_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/identity-enrollment/v1",
    "protocol/openapi/identity-enrollment/v1",
    "protocol/test-vectors/identity-enrollment/v1",
];
const V13_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/key-package/v1",
    "protocol/openapi/key-package/v1",
    "protocol/test-vectors/key-package/v1",
];
const V14_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/mailbox/v1",
    "protocol/openapi/mailbox/v1",
    "protocol/test-vectors/mailbox/v1",
];
const V15_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/identity-log-page/v1",
    "protocol/openapi/identity-log-page/v1",
    "protocol/test-vectors/identity-log-page/v1",
];
const V16_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/contact-card/v1",
    "protocol/test-vectors/contact-card/v1",
];
const V17_ARTIFACT_PATHS: &[&str] = &[
    "protocol/cddl/membership/v1",
    "protocol/openapi/membership/v1",
    "protocol/test-vectors/membership/v1",
];
const OWNED_ARTIFACT_ROOTS: &[&str] = &[
    "protocol/cddl",
    "protocol/openapi",
    "protocol/proto",
    "protocol/test-vectors",
];

#[derive(Clone, Copy)]
struct BaselineSpec {
    version: u16,
    path: &'static str,
    includes_registries: bool,
    artifact_paths: &'static [&'static str],
}

const BASELINE_SPECS: &[BaselineSpec] = &[
    BaselineSpec {
        version: 1,
        path: "protocol/baseline/v1/manifest.json",
        includes_registries: true,
        artifact_paths: V1_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 2,
        path: "protocol/baseline/v2/manifest.json",
        includes_registries: false,
        artifact_paths: V2_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 3,
        path: "protocol/baseline/v3/manifest.json",
        includes_registries: false,
        artifact_paths: V3_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 4,
        path: "protocol/baseline/v4/manifest.json",
        includes_registries: false,
        artifact_paths: V4_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 5,
        path: "protocol/baseline/v5/manifest.json",
        includes_registries: false,
        artifact_paths: V5_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 6,
        path: "protocol/baseline/v6/manifest.json",
        includes_registries: false,
        artifact_paths: V6_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 7,
        path: "protocol/baseline/v7/manifest.json",
        includes_registries: false,
        artifact_paths: V7_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 8,
        path: "protocol/baseline/v8/manifest.json",
        includes_registries: false,
        artifact_paths: V8_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 9,
        path: "protocol/baseline/v9/manifest.json",
        includes_registries: false,
        artifact_paths: V9_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 10,
        path: "protocol/baseline/v10/manifest.json",
        includes_registries: false,
        artifact_paths: V10_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 11,
        path: "protocol/baseline/v11/manifest.json",
        includes_registries: false,
        artifact_paths: V11_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 12,
        path: "protocol/baseline/v12/manifest.json",
        includes_registries: false,
        artifact_paths: V12_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 13,
        path: "protocol/baseline/v13/manifest.json",
        includes_registries: false,
        artifact_paths: V13_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 14,
        path: "protocol/baseline/v14/manifest.json",
        includes_registries: false,
        artifact_paths: V14_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 15,
        path: "protocol/baseline/v15/manifest.json",
        includes_registries: false,
        artifact_paths: V15_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 16,
        path: "protocol/baseline/v16/manifest.json",
        includes_registries: false,
        artifact_paths: V16_ARTIFACT_PATHS,
    },
    BaselineSpec {
        version: 17,
        path: "protocol/baseline/v17/manifest.json",
        includes_registries: false,
        artifact_paths: V17_ARTIFACT_PATHS,
    },
];

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BaselineManifest {
    version: u16,
    events: BTreeMap<String, String>,
    errors: BTreeMap<String, String>,
    artifacts: BTreeMap<String, String>,
}

/// Creates a configured new versioned baseline, or verifies exact existing
/// baselines without rewriting them.
///
/// The published v1 manifest must already exist and is never regenerated. A
/// missing newer manifest is created only from its explicitly assigned,
/// disjoint artifact set. Any unassigned protocol artifact fails the command.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] for a missing published baseline, invalid
/// registries, an existing manifest difference, overlapping/unassigned
/// artifacts, serialization, or I/O.
pub fn freeze_baseline(root: &Path) -> Result<(), ProtocolToolError> {
    let current = current_manifests(root)?;
    validate_selected_artifact_coverage(root, &current)?;

    let mut missing = Vec::new();
    for (spec, manifest) in BASELINE_SPECS.iter().zip(&current) {
        let path = root.join(spec.path);
        if path.exists() {
            let baseline = read_manifest(&path)?;
            validate_manifest_version(&baseline, spec.version)?;
            compare_manifest(*spec, &baseline, manifest)?;
        } else if spec.version == 1 {
            return Err(ProtocolToolError::new(
                "published v1 baseline is missing and cannot be regenerated",
            ));
        } else {
            missing.push((path, manifest));
        }
    }

    for (path, manifest) in missing {
        let parent = path
            .parent()
            .ok_or_else(|| ProtocolToolError::new("baseline path has no parent"))?;
        fs::create_dir_all(parent).map_err(|error| {
            ProtocolToolError::new(format!(
                "create baseline directory {}: {error}",
                parent.display()
            ))
        })?;
        write_manifest(&path, manifest)?;
    }
    Ok(())
}

/// Rejects removal, mutation, or an unreviewed/unfrozen addition across every
/// configured versioned baseline.
///
/// Versioned artifact sets are exact and disjoint. The v1 registry and schema
/// set remains byte-for-byte immutable while new reviewed artifacts live only
/// in later disjoint manifests.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] when a reviewed contract differs from its
/// baseline, manifests overlap, or any owned artifact is not frozen.
pub fn check_breaking(root: &Path) -> Result<(), ProtocolToolError> {
    let current = current_manifests(root)?;
    validate_selected_artifact_coverage(root, &current)?;

    let mut frozen_artifacts = BTreeMap::new();
    for (spec, manifest) in BASELINE_SPECS.iter().zip(&current) {
        let baseline = read_manifest(&root.join(spec.path))?;
        validate_manifest_version(&baseline, spec.version)?;
        compare_manifest(*spec, &baseline, manifest)?;
        for artifact in baseline.artifacts.keys() {
            if let Some(previous) = frozen_artifacts.insert(artifact.clone(), spec.version) {
                return Err(ProtocolToolError::new(format!(
                    "frozen artifact belongs to both v{previous} and v{}: {artifact}",
                    spec.version
                )));
            }
        }
    }
    Ok(())
}

fn current_manifests(root: &Path) -> Result<Vec<BaselineManifest>, ProtocolToolError> {
    BASELINE_SPECS
        .iter()
        .map(|spec| current_manifest(root, *spec))
        .collect()
}

fn current_manifest(
    root: &Path,
    spec: BaselineSpec,
) -> Result<BaselineManifest, ProtocolToolError> {
    let (events, errors) = if spec.includes_registries {
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
        (event_hashes, error_hashes)
    } else {
        (BTreeMap::new(), BTreeMap::new())
    };
    let artifacts = collect_selected_artifact_paths(root, spec.artifact_paths)?
        .into_iter()
        .map(|relative| {
            let bytes = fs::read(root.join(&relative)).map_err(|error| {
                ProtocolToolError::new(format!("read frozen artifact {relative}: {error}"))
            })?;
            Ok((relative, hash_bytes(&bytes)))
        })
        .collect::<Result<_, ProtocolToolError>>()?;
    Ok(BaselineManifest {
        version: spec.version,
        events,
        errors,
        artifacts,
    })
}

fn compare_manifest(
    spec: BaselineSpec,
    baseline: &BaselineManifest,
    current: &BaselineManifest,
) -> Result<(), ProtocolToolError> {
    compare_exact_entries("event", spec.version, &baseline.events, &current.events)?;
    compare_exact_entries("error", spec.version, &baseline.errors, &current.errors)?;
    compare_exact_entries(
        "artifact",
        spec.version,
        &baseline.artifacts,
        &current.artifacts,
    )
}

fn collect_selected_artifact_paths(
    root: &Path,
    selected_paths: &[&str],
) -> Result<Vec<String>, ProtocolToolError> {
    let mut paths = Vec::new();
    for relative in selected_paths {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            ProtocolToolError::new(format!("read artifact path {}: {error}", path.display()))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ProtocolToolError::new(format!(
                "frozen protocol artifact cannot be a symlink: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_artifact_paths_inner(root, &path, &mut paths)?;
        } else if metadata.is_file() {
            paths.push(normalize_relative(Path::new(relative))?);
        }
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

fn collect_owned_artifact_paths(root: &Path) -> Result<BTreeSet<String>, ProtocolToolError> {
    let mut paths = Vec::new();
    for relative in OWNED_ARTIFACT_ROOTS {
        collect_artifact_paths_inner(root, &root.join(relative), &mut paths)?;
    }
    Ok(paths.into_iter().collect())
}

fn validate_selected_artifact_coverage(
    root: &Path,
    manifests: &[BaselineManifest],
) -> Result<(), ProtocolToolError> {
    let mut selected = BTreeMap::new();
    for manifest in manifests {
        for artifact in manifest.artifacts.keys() {
            if let Some(previous) = selected.insert(artifact.clone(), manifest.version) {
                return Err(ProtocolToolError::new(format!(
                    "protocol artifact is assigned to both v{previous} and v{}: {artifact}",
                    manifest.version
                )));
            }
        }
    }

    for artifact in collect_owned_artifact_paths(root)? {
        if !selected.contains_key(&artifact) {
            return Err(ProtocolToolError::new(format!(
                "unfrozen protocol artifact addition: {artifact}; assign it to a new versioned baseline"
            )));
        }
    }
    Ok(())
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

fn validate_manifest_version(
    manifest: &BaselineManifest,
    expected: u16,
) -> Result<(), ProtocolToolError> {
    if manifest.version == expected {
        Ok(())
    } else {
        Err(ProtocolToolError::new(format!(
            "baseline version must be {expected}"
        )))
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
    version: u16,
    baseline: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
) -> Result<(), ProtocolToolError> {
    let label = baseline_version_label(version);
    for (name, expected) in baseline {
        let Some(actual) = current.get(name) else {
            return Err(ProtocolToolError::new(format!(
                "frozen {kind} was removed: {name}; {label} is immutable, create a new versioned contract"
            )));
        };
        if actual != expected {
            return Err(ProtocolToolError::new(format!(
                "frozen {kind} changed: {name}; {label} is immutable, create a new versioned contract"
            )));
        }
    }
    Ok(())
}

fn compare_exact_entries(
    kind: &str,
    version: u16,
    baseline: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
) -> Result<(), ProtocolToolError> {
    compare_frozen_entries(kind, version, baseline, current)?;
    let label = baseline_version_label(version);
    for name in current.keys() {
        if !baseline.contains_key(name) {
            return Err(ProtocolToolError::new(format!(
                "unfrozen {kind} addition: {name}; {label} is immutable, create a new versioned contract"
            )));
        }
    }
    Ok(())
}

fn baseline_version_label(version: u16) -> String {
    if version == 1 {
        "v1.0".to_owned()
    } else {
        format!("v{version}")
    }
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
    fn exact_check_rejects_an_unfrozen_addition_in_its_version() {
        let baseline = entries(&[("existing", "sha256:1")]);
        let current = entries(&[("existing", "sha256:1"), ("new", "sha256:2")]);
        let error = compare_exact_entries("artifact", 2, &baseline, &current).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unfrozen artifact addition: new; v2 is immutable, create a new versioned contract"
        );
    }

    #[test]
    fn immutable_v1_check_preserves_existing_diagnostics() {
        let baseline = entries(&[("existing", "sha256:1")]);
        let additive = entries(&[("existing", "sha256:1"), ("new", "sha256:2")]);
        assert!(compare_exact_entries("event", 1, &baseline, &additive).is_err());

        let changed = entries(&[("existing", "sha256:changed")]);
        let error = compare_exact_entries("event", 1, &baseline, &changed).unwrap_err();
        assert_eq!(
            error.to_string(),
            "frozen event changed: existing; v1.0 is immutable, create a new versioned contract"
        );
    }

    #[test]
    fn versioned_selectors_are_disjoint() {
        let v1 = V1_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v2 = V2_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v3 = V3_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v4 = V4_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v5 = V5_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v6 = V6_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v7 = V7_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v8 = V8_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v9 = V9_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v10 = V10_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v11 = V11_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v12 = V12_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v13 = V13_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        let v14 = V14_ARTIFACT_PATHS.iter().copied().collect::<BTreeSet<_>>();
        assert!(v1.is_disjoint(&v2));
        assert!(v1.is_disjoint(&v3));
        assert!(v1.is_disjoint(&v4));
        assert!(v1.is_disjoint(&v5));
        assert!(v1.is_disjoint(&v6));
        assert!(v1.is_disjoint(&v7));
        assert!(v1.is_disjoint(&v8));
        assert!(v2.is_disjoint(&v3));
        assert!(v2.is_disjoint(&v4));
        assert!(v2.is_disjoint(&v5));
        assert!(v2.is_disjoint(&v6));
        assert!(v2.is_disjoint(&v7));
        assert!(v2.is_disjoint(&v8));
        assert!(v3.is_disjoint(&v4));
        assert!(v3.is_disjoint(&v5));
        assert!(v3.is_disjoint(&v6));
        assert!(v3.is_disjoint(&v7));
        assert!(v3.is_disjoint(&v8));
        assert!(v4.is_disjoint(&v5));
        assert!(v4.is_disjoint(&v6));
        assert!(v4.is_disjoint(&v7));
        assert!(v4.is_disjoint(&v8));
        assert!(v5.is_disjoint(&v6));
        assert!(v5.is_disjoint(&v7));
        assert!(v5.is_disjoint(&v8));
        assert!(v6.is_disjoint(&v7));
        assert!(v6.is_disjoint(&v8));
        assert!(v7.is_disjoint(&v8));
        assert!(v1.is_disjoint(&v9));
        assert!(v2.is_disjoint(&v9));
        assert!(v3.is_disjoint(&v9));
        assert!(v4.is_disjoint(&v9));
        assert!(v5.is_disjoint(&v9));
        assert!(v6.is_disjoint(&v9));
        assert!(v7.is_disjoint(&v9));
        assert!(v8.is_disjoint(&v9));
        assert!(v1.is_disjoint(&v10));
        assert!(v2.is_disjoint(&v10));
        assert!(v3.is_disjoint(&v10));
        assert!(v4.is_disjoint(&v10));
        assert!(v5.is_disjoint(&v10));
        assert!(v6.is_disjoint(&v10));
        assert!(v7.is_disjoint(&v10));
        assert!(v8.is_disjoint(&v10));
        assert!(v9.is_disjoint(&v10));
        assert!(v1.is_disjoint(&v11));
        assert!(v2.is_disjoint(&v11));
        assert!(v3.is_disjoint(&v11));
        assert!(v4.is_disjoint(&v11));
        assert!(v5.is_disjoint(&v11));
        assert!(v6.is_disjoint(&v11));
        assert!(v7.is_disjoint(&v11));
        assert!(v8.is_disjoint(&v11));
        assert!(v9.is_disjoint(&v11));
        assert!(v10.is_disjoint(&v11));
        assert!(v1.is_disjoint(&v12));
        assert!(v2.is_disjoint(&v12));
        assert!(v3.is_disjoint(&v12));
        assert!(v4.is_disjoint(&v12));
        assert!(v5.is_disjoint(&v12));
        assert!(v6.is_disjoint(&v12));
        assert!(v7.is_disjoint(&v12));
        assert!(v8.is_disjoint(&v12));
        assert!(v9.is_disjoint(&v12));
        assert!(v10.is_disjoint(&v12));
        assert!(v11.is_disjoint(&v12));
        for prior in [
            &v1, &v2, &v3, &v4, &v5, &v6, &v7, &v8, &v9, &v10, &v11, &v12,
        ] {
            assert!(prior.is_disjoint(&v13));
        }
        for prior in [
            &v1, &v2, &v3, &v4, &v5, &v6, &v7, &v8, &v9, &v10, &v11, &v12, &v13,
        ] {
            assert!(prior.is_disjoint(&v14));
        }
        assert!(!V1_ARTIFACT_PATHS.contains(&"protocol/proto"));
    }
}
