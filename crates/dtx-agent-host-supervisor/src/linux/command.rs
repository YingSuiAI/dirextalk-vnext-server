use std::{
    ffi::OsString,
    process::{Command, Stdio},
};

use crate::{PortError, PortErrorKind};

const MAX_STDOUT_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FixedCommand {
    pub(super) program: &'static str,
    pub(super) arguments: Vec<OsString>,
}

impl FixedCommand {
    pub(super) fn new(program: &'static str, arguments: Vec<OsString>) -> Self {
        Self { program, arguments }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FixedCommandOutput {
    pub(super) success: bool,
    pub(super) stdout: Vec<u8>,
}

pub(super) trait FixedCommandRunner {
    fn run(&mut self, command: &FixedCommand) -> Result<FixedCommandOutput, PortError>;
}

#[derive(Default)]
pub(super) struct StdCommandRunner;

impl FixedCommandRunner for StdCommandRunner {
    fn run(&mut self, command: &FixedCommand) -> Result<FixedCommandOutput, PortError> {
        let output = Command::new(command.program)
            .args(&command.arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
        if output.stdout.len() > MAX_STDOUT_BYTES {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        Ok(FixedCommandOutput {
            success: output.status.success(),
            stdout: output.stdout,
        })
    }
}
