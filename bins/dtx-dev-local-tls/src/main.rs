#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match dtx_dev_local_tls::bootstrap_from_environment() {
        Ok(dtx_dev_local_tls::BootstrapOutcome::Created) => {
            println!("dtx-dev-local-tls: local TLS material generated");
            ExitCode::SUCCESS
        }
        Ok(dtx_dev_local_tls::BootstrapOutcome::AlreadyPresent) => {
            println!("dtx-dev-local-tls: local TLS material already present");
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("dtx-dev-local-tls: local TLS bootstrap failed");
            ExitCode::FAILURE
        }
    }
}
