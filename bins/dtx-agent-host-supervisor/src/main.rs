#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod catalog;
#[cfg(target_os = "linux")]
mod production;
mod wire;

use std::{env, io, process::ExitCode};

use wire::{OperatorFailure, OperatorResponse, encode_response, read_frame};

fn main() -> ExitCode {
    let response = run();
    let succeeded = response.succeeded();
    if encode_response(io::stdout().lock(), &response).is_err() {
        return ExitCode::FAILURE;
    }
    if succeeded {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run() -> OperatorResponse {
    if env::args_os().len() != 1 {
        return OperatorResponse::rejected(OperatorFailure::new("INVALID_ARGUMENTS"));
    }
    let frame = match read_frame(io::stdin().lock()) {
        Ok(frame) => frame,
        Err(error) => return OperatorResponse::rejected(error),
    };
    #[cfg(target_os = "linux")]
    {
        production::handle(frame)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = frame;
        OperatorResponse::rejected(OperatorFailure::new("UNSUPPORTED_PLATFORM"))
    }
}
