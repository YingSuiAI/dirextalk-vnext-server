use std::path::PathBuf;

use dtx_protocol::{check_breaking, validate_artifacts};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn committed_v1_baseline_accepts_the_current_contracts() {
    check_breaking(&repository_root()).expect("current contracts match the frozen v1 baseline");
}

#[test]
fn cddl_openapi_protobuf_and_golden_vectors_validate_together() {
    validate_artifacts(&repository_root()).expect("all server-owned protocol artifacts agree");
}
