#![forbid(unsafe_code)]

use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dtx-protocol: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), dtx_protocol::ProtocolToolError> {
    let mut arguments = env::args().skip(1);
    let command = arguments
        .next()
        .unwrap_or_else(|| "check-generated".to_owned());
    let root = arguments
        .next()
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    if arguments.next().is_some() {
        return Err(dtx_protocol::ProtocolToolError::new(
            "usage: dtx-protocol [generate|check-generated|validate|check-breaking|freeze-baseline] [repository-root]",
        ));
    }
    match command.as_str() {
        "generate" => dtx_protocol::generate(&root),
        "check-generated" => dtx_protocol::check_generated(&root),
        "validate" => dtx_protocol::validate_artifacts(&root),
        "check-breaking" => dtx_protocol::check_breaking(&root),
        "freeze-baseline" => dtx_protocol::freeze_baseline(&root),
        _ => Err(dtx_protocol::ProtocolToolError::new(
            "usage: dtx-protocol [generate|check-generated|validate|check-breaking|freeze-baseline] [repository-root]",
        )),
    }
}
