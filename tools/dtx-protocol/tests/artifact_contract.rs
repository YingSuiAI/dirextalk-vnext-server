use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use dtx_protocol::{check_breaking, freeze_baseline, validate_artifacts};

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
