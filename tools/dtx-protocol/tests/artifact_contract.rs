use std::{
    fmt::Write as _,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use dtx_protocol::{check_breaking, freeze_baseline, validate_artifacts};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn committed_versioned_baselines_accept_the_current_contracts() {
    check_breaking(&repository_root())
        .expect("current contracts match every frozen versioned baseline");
}

#[test]
fn cddl_openapi_protobuf_and_golden_vectors_validate_together() {
    validate_artifacts(&repository_root()).expect("all server-owned protocol artifacts agree");
}

#[test]
fn private_application_event_v1_is_part_of_the_validated_frozen_contract() {
    let root = repository_root();
    assert!(
        root.join("protocol/cddl/private-event/v1/private-event-v1.cddl")
            .is_file()
    );
    assert!(
        root.join("protocol/test-vectors/private-event/v1/private-event-v1.json")
            .is_file()
    );
    validate_artifacts(&root).expect("private application event vectors must be byte exact");
}

#[test]
fn private_agent_approval_v6_v7_is_a_disjoint_validated_v34_contract() {
    let root = repository_root();
    let artifact_paths = [
        "protocol/cddl/private-event/v6_v7/private-agent-approval-v6-v7.cddl",
        "protocol/test-vectors/private-event/v6_v7/private-agent-approval-v6-v7.json",
    ];
    let manifest: Value = serde_json::from_slice(
        &fs::read(root.join("protocol/baseline/v34/manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["version"].as_u64(), Some(34));
    assert_eq!(manifest["events"].as_object().unwrap().len(), 0);
    assert_eq!(manifest["errors"].as_object().unwrap().len(), 0);
    let artifacts = manifest["artifacts"].as_object().unwrap();
    assert_eq!(artifacts.len(), artifact_paths.len());
    for path in artifact_paths {
        let mut digest = String::from("sha256:");
        for byte in Sha256::digest(fs::read(root.join(path)).unwrap()) {
            write!(&mut digest, "{byte:02x}").unwrap();
        }
        assert_eq!(
            artifacts.get(path).and_then(Value::as_str),
            Some(digest.as_str())
        );
    }

    let v20 = fs::read(root.join("protocol/baseline/v20/manifest.json")).unwrap();
    validate_artifacts(&root).expect("private approval V6/V7 vectors must be byte exact");
    assert_eq!(
        fs::read(root.join("protocol/baseline/v20/manifest.json")).unwrap(),
        v20,
        "validating approvals must not mutate the private-event V1/V20 baseline",
    );
}

#[test]
fn restored_v23_and_additive_v35_are_disjoint_and_frozen() {
    let root = repository_root();
    let v23_path = root.join("protocol/baseline/v23/manifest.json");
    let v35_path = root.join("protocol/baseline/v35/manifest.json");
    let v23_before = fs::read(&v23_path).expect("V23 manifest is present");
    let v35_before = fs::read(&v35_path).expect("V35 manifest is present");
    let v23: Value = serde_json::from_slice(&v23_before).expect("V23 manifest is valid JSON");
    let v35: Value = serde_json::from_slice(&v35_before).expect("V35 manifest is valid JSON");

    assert_eq!(v23["version"].as_u64(), Some(23));
    assert_eq!(
        v23["artifacts"]["protocol/proto/dirextalk/agent_control/v1_3/agent_control.proto"]
            .as_str(),
        Some("sha256:6395d9d80f249c1197758c5168bf7aa05498031baacd47db1d929754a503eb60")
    );
    assert_eq!(v35["version"].as_u64(), Some(35));
    let v35_artifacts = v35["artifacts"].as_object().expect("V35 artifacts");
    assert_eq!(v35_artifacts.len(), 1);
    let v1_4_path = "protocol/proto/dirextalk/agent_control/v1_4/agent_control.proto";
    let mut digest = String::from("sha256:");
    for byte in Sha256::digest(fs::read(root.join(v1_4_path)).expect("V1.4 source")) {
        write!(&mut digest, "{byte:02x}").unwrap();
    }
    assert_eq!(
        v35_artifacts.get(v1_4_path).and_then(Value::as_str),
        Some(digest.as_str())
    );
    assert!(
        v23["artifacts"]
            .as_object()
            .expect("V23 artifacts")
            .keys()
            .all(|path| !v35_artifacts.contains_key(path))
    );

    freeze_baseline(&root).expect("published baselines verify without refreezing");
    assert_eq!(fs::read(v23_path).unwrap(), v23_before);
    assert_eq!(fs::read(v35_path).unwrap(), v35_before);
}

#[test]
fn additive_v36_is_disjoint_and_preserves_v24_and_every_older_manifest_byte_exact() {
    let root = repository_root();
    let older = (1..=35)
        .map(|version| {
            let path = root.join(format!("protocol/baseline/v{version}/manifest.json"));
            let bytes = fs::read(&path).unwrap_or_else(|error| {
                panic!(
                    "read published V{version} manifest {}: {error}",
                    path.display()
                )
            });
            (path, bytes)
        })
        .collect::<Vec<_>>();
    let v24_before = older
        .iter()
        .find(|(path, _)| path.ends_with("protocol/baseline/v24/manifest.json"))
        .map(|(_, bytes)| bytes.clone())
        .expect("V24 manifest snapshot");
    let v36_path = root.join("protocol/baseline/v36/manifest.json");
    let v36_before = fs::read(&v36_path).expect("V36 manifest is present");
    let v36: Value = serde_json::from_slice(&v36_before).expect("V36 manifest is valid JSON");
    assert_eq!(v36["version"].as_u64(), Some(36));
    assert_eq!(v36["events"].as_object().unwrap().len(), 0);
    assert_eq!(v36["errors"].as_object().unwrap().len(), 0);
    let artifacts = v36["artifacts"].as_object().expect("V36 artifacts");
    assert_eq!(artifacts.len(), 8);
    assert_eq!(
        artifacts
            .get("protocol/test-vectors/private-event/v8/private-group-reaction-v8.json")
            .and_then(Value::as_str),
        Some("sha256:519f24a89a91d7ee7098a1d0881c9f035e587e7d96d0649bd76123edb5ba5420"),
    );
    let v24: Value = serde_json::from_slice(&v24_before).expect("V24 manifest JSON");
    assert!(
        v24["artifacts"]
            .as_object()
            .expect("V24 artifacts")
            .keys()
            .all(|path| !artifacts.contains_key(path)),
    );

    freeze_baseline(&root).expect("V36 and every published baseline remain byte exact");
    for (path, expected) in older {
        assert_eq!(
            fs::read(&path).unwrap(),
            expected,
            "{} changed",
            path.display()
        );
    }
    assert_eq!(fs::read(v36_path).unwrap(), v36_before);
}

#[test]
fn freezing_a_new_version_preserves_the_published_v1_manifest() {
    let root = isolated_protocol_tree();
    let v1 = root.join("protocol/baseline/v1/manifest.json");
    let v2 = root.join("protocol/baseline/v2/manifest.json");
    let published_v1 = fs::read(&v1).unwrap();
    fs::remove_file(&v2).unwrap();

    freeze_baseline(&root).expect("the explicitly assigned v2 artifact set freezes");
    assert_eq!(fs::read(&v1).unwrap(), published_v1);
    assert!(v2.is_file());
    check_breaking(&root).expect("the newly frozen disjoint baseline verifies");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn freezing_v3_preserves_both_older_manifests() {
    let root = isolated_protocol_tree();
    let v1 = root.join("protocol/baseline/v1/manifest.json");
    let v2 = root.join("protocol/baseline/v2/manifest.json");
    let v3 = root.join("protocol/baseline/v3/manifest.json");
    let published_v1 = fs::read(&v1).unwrap();
    let published_v2 = fs::read(&v2).unwrap();
    fs::remove_file(&v3).unwrap();

    freeze_baseline(&root).expect("the disjoint v1.1 artifact set freezes as v3");
    assert_eq!(fs::read(&v1).unwrap(), published_v1);
    assert_eq!(fs::read(&v2).unwrap(), published_v2);
    assert!(v3.is_file());
    check_breaking(&root).expect("all three disjoint baselines verify");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn freezing_v4_preserves_every_older_manifest() {
    let root = isolated_protocol_tree();
    let older = [
        root.join("protocol/baseline/v1/manifest.json"),
        root.join("protocol/baseline/v2/manifest.json"),
        root.join("protocol/baseline/v3/manifest.json"),
    ];
    let published = older
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect::<Vec<_>>();
    let v4 = root.join("protocol/baseline/v4/manifest.json");
    fs::remove_file(&v4).unwrap();

    freeze_baseline(&root).expect("the disjoint Gateway ingress artifact freezes as v4");
    for (path, expected) in older.iter().zip(published) {
        assert_eq!(fs::read(path).unwrap(), expected);
    }
    assert!(v4.is_file());
    check_breaking(&root).expect("all four disjoint baselines verify");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn freeze_never_regenerates_a_missing_published_v1_manifest() {
    let root = isolated_protocol_tree();
    fs::remove_file(root.join("protocol/baseline/v1/manifest.json")).unwrap();

    let error = freeze_baseline(&root).unwrap_err();
    assert_eq!(
        error.to_string(),
        "published v1 baseline is missing and cannot be regenerated"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn every_new_protocol_artifact_must_belong_to_a_frozen_version() {
    let root = isolated_protocol_tree();
    let unassigned = root.join("protocol/proto/dirextalk/unreviewed/v1/escape.proto");
    fs::create_dir_all(unassigned.parent().unwrap()).unwrap();
    fs::write(
        &unassigned,
        "syntax = \"proto3\"; package dirextalk.unreviewed.v1;",
    )
    .unwrap();

    let error = check_breaking(&root).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unfrozen protocol artifact addition")
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_new_file_inside_a_frozen_version_is_rejected() {
    let root = isolated_protocol_tree();
    fs::write(
        root.join("protocol/proto/dirextalk/agent_control/v1/unreviewed.proto"),
        "syntax = \"proto3\"; package dirextalk.agent_control.v1;",
    )
    .unwrap();

    let error = check_breaking(&root).unwrap_err();
    assert!(error.to_string().contains("unfrozen artifact addition"));
    assert!(error.to_string().contains("v2 is immutable"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_new_file_inside_the_published_v1_is_still_rejected() {
    let root = isolated_protocol_tree();
    fs::write(
        root.join("protocol/proto/dirextalk/v1/unreviewed.proto"),
        "syntax = \"proto3\"; package dirextalk.v1;",
    )
    .unwrap();

    let error = check_breaking(&root).unwrap_err();
    assert!(error.to_string().contains("unfrozen artifact addition"));
    assert!(error.to_string().contains("v1.0 is immutable"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn freezing_never_rewrites_an_existing_v2_manifest() {
    let root = isolated_protocol_tree();
    let v2 = root.join("protocol/baseline/v2/manifest.json");
    let frozen_v2 = fs::read(&v2).unwrap();
    fs::write(
        root.join("protocol/proto/dirextalk/agent_control/v1/agent_control.proto"),
        "syntax = \"proto3\"; package dirextalk.agent_control.v1;",
    )
    .unwrap();

    let error = freeze_baseline(&root).unwrap_err();
    assert!(error.to_string().contains("frozen artifact changed"));
    assert!(error.to_string().contains("v2 is immutable"));
    assert_eq!(fs::read(&v2).unwrap(), frozen_v2);

    fs::remove_dir_all(root).unwrap();
}

fn isolated_protocol_tree() -> PathBuf {
    static NEXT_TREE_ID: AtomicU64 = AtomicU64::new(0);
    let root = loop {
        let candidate = std::env::temp_dir().join(format!(
            "dtx-versioned-baseline-{}-{}",
            std::process::id(),
            NEXT_TREE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create isolated protocol root: {error}"),
        }
    };
    copy_tree(&repository_root().join("protocol"), &root.join("protocol"));
    root
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}
