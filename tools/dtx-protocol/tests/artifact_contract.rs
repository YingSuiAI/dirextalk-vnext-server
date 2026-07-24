use std::{fs, path::PathBuf};

use dtx_protocol::{check_alpha, validate_artifacts};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn committed_alpha_inventory_accepts_current_contracts() {
    check_alpha(&repository_root()).expect("Alpha inventory is current");
}

#[test]
fn alpha_validation_accepts_current_product_core_artifacts() {
    validate_artifacts(&repository_root()).expect("Alpha artifacts validate");
}

#[test]
fn deferred_agent_and_public_sources_are_not_in_alpha_manifest() {
    let root = repository_root();
    let manifest = fs::read_to_string(root.join("protocol/alpha/manifest.json")).unwrap();
    assert!(!manifest.contains("protocol/proto/dirextalk/agent_control/"));
    assert!(!manifest.contains("protocol/test-vectors/public-feed/"));
}
