#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod catalog;
#[cfg(target_os = "linux")]
mod production;
mod production_v2;
mod wire;
mod wire_v2;

use std::{
    env,
    io::{self, Read as _},
    process::ExitCode,
};

use wire::{OperatorFailure, OperatorResponse, decode_frame, encode_response};
use zeroize::Zeroizing;

fn main() -> ExitCode {
    let response = run();
    let succeeded = response.succeeded();
    if response.encode(io::stdout().lock()).is_err() {
        return ExitCode::FAILURE;
    }
    if succeeded {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

enum DispatchResponse {
    V1(OperatorResponse),
    V2(wire_v2::V2Response),
}

impl DispatchResponse {
    const fn succeeded(&self) -> bool {
        match self {
            Self::V1(response) => response.succeeded(),
            Self::V2(response) => response.succeeded_status(),
        }
    }

    fn encode(&self, writer: impl io::Write) -> io::Result<()> {
        match self {
            Self::V1(response) => encode_response(writer, response),
            Self::V2(response) => wire_v2::encode_response_v2(writer, response),
        }
    }
}

fn run() -> DispatchResponse {
    if env::args_os().len() != 1 {
        return DispatchResponse::V1(OperatorResponse::rejected(OperatorFailure::new(
            "INVALID_ARGUMENTS",
        )));
    }
    let mut input = Zeroizing::new(Vec::new());
    if io::stdin()
        .lock()
        .take(u64::try_from(wire_v2::MAX_FRAME_BYTES_V2 + 1).expect("frame limit fits u64"))
        .read_to_end(&mut input)
        .is_err()
    {
        return DispatchResponse::V1(OperatorResponse::rejected(OperatorFailure::new(
            "REQUEST_UNAVAILABLE",
        )));
    }
    if input.starts_with(wire::MAGIC) {
        let frame = match decode_frame(&input) {
            Ok(frame) => frame,
            Err(error) => return DispatchResponse::V1(OperatorResponse::rejected(error)),
        };
        #[cfg(target_os = "linux")]
        return DispatchResponse::V1(production::handle(frame));
        #[cfg(not(target_os = "linux"))]
        {
            let _ = frame;
            return DispatchResponse::V1(OperatorResponse::rejected(OperatorFailure::new(
                "UNSUPPORTED_PLATFORM",
            )));
        }
    }
    if input.starts_with(wire_v2::MAGIC_V2) {
        // Decoding occurs before any host boundary, journal, process, or
        // filesystem action. The Linux adapter then owns the bounded material
        // through fixed staging, Connector receipt binding, and journal close.
        return match wire_v2::read_frame_v2(&input) {
            Ok(frame) => DispatchResponse::V2(production::handle_v2(frame)),
            Err(_) => DispatchResponse::V2(wire_v2::V2Response::rejected("INVALID_V2_FRAME")),
        };
    }
    DispatchResponse::V1(OperatorResponse::rejected(OperatorFailure::new(
        "INVALID_FRAME",
    )))
}
