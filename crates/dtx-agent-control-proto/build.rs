use std::{env, error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let repository_root = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or("CARGO_MANIFEST_DIR is required to locate the reviewed protocol source")?,
    )
    .join("../..");
    let proto_root = repository_root.join("protocol/proto");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is required")?);

    // Watch the include root as well as the entrypoint so a future imported
    // reviewed schema cannot leave generated Rust or descriptors stale.
    println!("cargo:rerun-if-changed={}", proto_root.display());

    compile_contract(
        proto_root.join("dirextalk/agent_control/v1_6/agent_control.proto"),
        out_dir.join("agent_control_descriptor.bin"),
        &proto_root,
    )?;
    compile_contract(
        proto_root.join("dirextalk/agent_gateway/v1/agent_gateway.proto"),
        out_dir.join("agent_gateway_descriptor.bin"),
        &proto_root,
    )?;

    Ok(())
}

fn compile_contract(
    contract: PathBuf,
    descriptor: PathBuf,
    proto_root: &std::path::Path,
) -> Result<(), Box<dyn Error>> {
    let mut prost = tonic_prost_build::Config::new();
    prost.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path(descriptor)
        .compile_with_config(prost, &[contract], &[proto_root.to_path_buf()])?;
    Ok(())
}
