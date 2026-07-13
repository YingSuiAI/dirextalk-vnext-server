use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use crate::{PortError, PortErrorKind};

use super::{
    command::{FixedCommand, FixedCommandRunner, StdCommandRunner},
    layout::{NFT, SYSTEMCTL},
};

const SUPERVISOR_UNIT: &str = "dirextalk-host-supervisor.service";
const SUPERVISOR_CGROUP: &str = "/system.slice/dirextalk-host-supervisor.service";
const SUPERVISOR_SLICE: &str = "system.slice";
const IMDS_V4: &str = "169.254.169.254/32";
const IMDS_V6: &str = "fd00:ec2::254/128";
const POLICY_TABLE: &str = "dtx_host_supervisor";
const POLICY_PATH: &str = "/run/dirextalk/host-supervisor/imds-policy.nft";
const MAX_NFT_OUTPUT: usize = 16 * 1024;

/// Installs the root Host Supervisor's own fixed cgroup-scoped IMDS deny.
///
/// The networked process must run in the exact production systemd unit. No
/// caller-controlled unit, cgroup, path, address, table, or nft expression is
/// accepted.
pub struct LinuxHostNetworkBoundary;

impl LinuxHostNetworkBoundary {
    /// Installs and reads back the current Supervisor service's IPv4/IPv6 deny.
    ///
    /// # Errors
    ///
    /// Fails closed outside the fixed systemd service, without unified cgroup
    /// v2, or when the root-owned policy cannot be atomically installed and
    /// read back exactly.
    pub fn install() -> Result<(), PortError> {
        let cgroup = fs::read_to_string("/proc/self/cgroup").map_err(|_| invalid())?;
        if cgroup != format!("0::{SUPERVISOR_CGROUP}\n") {
            return Err(invalid());
        }
        let cgroup_path = PathBuf::from("/sys/fs/cgroup")
            .join(SUPERVISOR_CGROUP.strip_prefix('/').ok_or_else(invalid)?);
        let metadata = fs::symlink_metadata(&cgroup_path).map_err(|_| invalid())?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid());
        }
        let mut runner = StdCommandRunner;
        validate_unit(&mut runner)?;
        ensure_policy_directory()?;
        let policy = policy_file();
        atomic_policy_write(policy.as_bytes())?;
        apply_policy(&mut runner)
    }

    #[must_use]
    pub const fn unit_name() -> &'static str {
        SUPERVISOR_UNIT
    }
}

fn unit_command() -> FixedCommand {
    FixedCommand::new(
        SYSTEMCTL,
        vec![
            "show".into(),
            "--no-pager".into(),
            "--property=ControlGroup,Slice,IPAddressDeny".into(),
            "--".into(),
            SUPERVISOR_UNIT.into(),
        ],
    )
}

fn validate_unit(runner: &mut impl FixedCommandRunner) -> Result<(), PortError> {
    let read_back = runner.run(&unit_command())?;
    if !read_back.success {
        return Err(unavailable());
    }
    validate_unit_properties(&read_back.stdout)
}

fn validate_unit_properties(value: &[u8]) -> Result<(), PortError> {
    if value.len() > MAX_NFT_OUTPUT {
        return Err(invalid());
    }
    let value = std::str::from_utf8(value).map_err(|_| invalid())?;
    if value.contains(['\0', '\r']) {
        return Err(invalid());
    }
    let mut control_group = None;
    let mut slice = None;
    let mut address_denies = None;
    for line in value.lines() {
        let (name, value) = line.split_once('=').ok_or_else(invalid)?;
        let destination = match name {
            "ControlGroup" => &mut control_group,
            "Slice" => &mut slice,
            "IPAddressDeny" => &mut address_denies,
            _ => return Err(invalid()),
        };
        if destination.replace(value).is_some() {
            return Err(invalid());
        }
    }
    if control_group != Some(SUPERVISOR_CGROUP) || slice != Some(SUPERVISOR_SLICE) {
        return Err(invalid());
    }
    let mut denies = address_denies
        .ok_or_else(invalid)?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    denies.sort_unstable();
    if denies != [IMDS_V4, IMDS_V6] {
        return Err(invalid());
    }
    Ok(())
}

fn list_command() -> FixedCommand {
    // nft otherwise renders -146 as the symbolic `mangle + 4`. Request only a
    // numeric chain priority: fully numeric output may hide the cgroupv2 path
    // behind its kernel ID, which this boundary must read back exactly.
    FixedCommand::new(
        NFT,
        vec![
            "--numeric-priority".into(),
            "list".into(),
            "table".into(),
            "inet".into(),
            POLICY_TABLE.into(),
        ],
    )
}

fn policy_command() -> FixedCommand {
    FixedCommand::new(NFT, vec!["--file".into(), POLICY_PATH.into()])
}

fn apply_policy(runner: &mut impl FixedCommandRunner) -> Result<(), PortError> {
    required(runner, &policy_command())?;
    let read_back = runner.run(&list_command())?;
    if !read_back.success || normalize_listing(&read_back.stdout)? != policy_listing() {
        return Err(invalid());
    }
    Ok(())
}

fn required(runner: &mut impl FixedCommandRunner, command: &FixedCommand) -> Result<(), PortError> {
    if runner.run(command)?.success {
        Ok(())
    } else {
        Err(unavailable())
    }
}

fn policy_file() -> String {
    // One nft batch is one kernel transaction. `destroy` is idempotent when the
    // table is absent, and a rejected replacement leaves the old table intact.
    format!(
        concat!(
            "destroy table inet {POLICY_TABLE}\n",
            "add table inet {POLICY_TABLE}\n",
            "add chain inet {POLICY_TABLE} output {{ type filter hook output priority -146; policy accept; }}\n",
            "add rule inet {POLICY_TABLE} output socket cgroupv2 level 2 \"{CGROUP}\" ip daddr 169.254.169.254 drop\n",
            "add rule inet {POLICY_TABLE} output socket cgroupv2 level 2 \"{CGROUP}\" ip6 daddr fd00:ec2::254 drop\n"
        ),
        POLICY_TABLE = POLICY_TABLE,
        CGROUP = "system.slice/dirextalk-host-supervisor.service",
    )
}

fn policy_listing() -> String {
    format!(
        concat!(
            "table inet {POLICY_TABLE} {{\n",
            "chain output {{\n",
            "type filter hook output priority -146; policy accept;\n",
            "socket cgroupv2 level 2 \"{CGROUP}\" ip daddr 169.254.169.254 drop\n",
            "socket cgroupv2 level 2 \"{CGROUP}\" ip6 daddr fd00:ec2::254 drop\n",
            "}}\n",
            "}}"
        ),
        POLICY_TABLE = POLICY_TABLE,
        CGROUP = "system.slice/dirextalk-host-supervisor.service",
    )
}

fn normalize_listing(value: &[u8]) -> Result<String, PortError> {
    if value.len() > MAX_NFT_OUTPUT {
        return Err(invalid());
    }
    let value = std::str::from_utf8(value).map_err(|_| invalid())?;
    if value.contains(['\0', '\r']) {
        return Err(invalid());
    }
    Ok(value
        .lines()
        .map(|line| line.split_ascii_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n"))
}

fn ensure_policy_directory() -> Result<(), PortError> {
    for path in [
        Path::new("/run"),
        Path::new("/run/dirextalk"),
        Path::new("/run/dirextalk/host-supervisor"),
    ] {
        match fs::symlink_metadata(path) {
            Ok(metadata) => validate_root_directory(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|_| unavailable())?;
                validate_root_directory(&fs::symlink_metadata(path).map_err(|_| unavailable())?)?;
            }
            Err(_) => return Err(unavailable()),
        }
    }
    Ok(())
}

fn validate_root_directory(metadata: &fs::Metadata) -> Result<(), PortError> {
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid());
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(invalid());
        }
    }
    Ok(())
}

fn atomic_policy_write(bytes: &[u8]) -> Result<(), PortError> {
    let target = Path::new(POLICY_PATH);
    let temporary = target.with_extension("tmp");
    for path in [target, temporary.as_path()] {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => return Err(invalid()),
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|_| unavailable())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| unavailable())?;
    fs::rename(&temporary, target).map_err(|_| unavailable())?;
    File::open(target.parent().ok_or_else(invalid)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| unavailable())
}

const fn invalid() -> PortError {
    PortError::new(PortErrorKind::InvalidArtifact)
}

const fn unavailable() -> PortError {
    PortError::new(PortErrorKind::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::linux::command::FixedCommandOutput;

    #[test]
    fn policy_uses_documented_cgroupv2_path_in_one_transaction() {
        let policy = policy_file();

        assert!(policy.starts_with("destroy table inet dtx_host_supervisor\n"));
        assert!(policy.contains(
            "socket cgroupv2 level 2 \"system.slice/dirextalk-host-supervisor.service\""
        ));
        assert!(!policy.contains("meta cgroup"));
    }

    #[test]
    fn unit_properties_require_the_exact_production_boundary() {
        let exact = concat!(
            "ControlGroup=/system.slice/dirextalk-host-supervisor.service\n",
            "Slice=system.slice\n",
            "IPAddressDeny=169.254.169.254/32 fd00:ec2::254/128\n",
        );
        validate_unit_properties(exact.as_bytes()).unwrap();

        for invalid in [
            exact.replace("system.slice\n", "other.slice\n"),
            exact.replace("169.254.169.254/32 ", ""),
            exact.replace("fd00:ec2::254/128", "fd00:ec2::254/64"),
            format!("{exact}IPAddressDeny=169.254.169.254/32\n"),
        ] {
            assert_eq!(
                validate_unit_properties(invalid.as_bytes())
                    .unwrap_err()
                    .kind(),
                PortErrorKind::InvalidArtifact,
            );
        }
    }

    #[test]
    fn unit_validation_reads_only_the_fixed_systemd_unit() {
        let mut runner = ScriptedRunner::new([FixedCommandOutput {
            success: true,
            stdout: concat!(
                "ControlGroup=/system.slice/dirextalk-host-supervisor.service\n",
                "Slice=system.slice\n",
                "IPAddressDeny=fd00:ec2::254/128 169.254.169.254/32\n",
            )
            .as_bytes()
            .to_vec(),
        }]);

        validate_unit(&mut runner).unwrap();

        assert_eq!(runner.commands, vec![unit_command()]);
        assert_eq!(
            runner.commands[0].arguments,
            [
                "show",
                "--no-pager",
                "--property=ControlGroup,Slice,IPAddressDeny",
                "--",
                "dirextalk-host-supervisor.service",
            ]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn policy_read_back_requests_numeric_priority_without_hiding_the_cgroup_path() {
        assert_eq!(
            list_command().arguments,
            [
                "--numeric-priority",
                "list",
                "table",
                "inet",
                "dtx_host_supervisor",
            ]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn policy_replacement_is_one_checked_batch_followed_by_read_back() {
        let mut runner = ScriptedRunner::new([
            FixedCommandOutput {
                success: true,
                stdout: Vec::new(),
            },
            FixedCommandOutput {
                success: true,
                stdout: policy_listing().into_bytes(),
            },
        ]);

        apply_policy(&mut runner).unwrap();

        assert_eq!(runner.commands, vec![policy_command(), list_command()]);
    }

    #[test]
    fn failed_policy_batch_does_not_issue_another_mutation() {
        let mut runner = ScriptedRunner::new([FixedCommandOutput {
            success: false,
            stdout: Vec::new(),
        }]);

        assert_eq!(
            apply_policy(&mut runner).unwrap_err().kind(),
            PortErrorKind::Unavailable,
        );
        assert_eq!(runner.commands, vec![policy_command()]);
    }

    struct ScriptedRunner {
        commands: Vec<FixedCommand>,
        outputs: VecDeque<FixedCommandOutput>,
    }

    impl ScriptedRunner {
        fn new(outputs: impl IntoIterator<Item = FixedCommandOutput>) -> Self {
            Self {
                commands: Vec::new(),
                outputs: outputs.into_iter().collect(),
            }
        }
    }

    impl FixedCommandRunner for ScriptedRunner {
        fn run(&mut self, command: &FixedCommand) -> Result<FixedCommandOutput, PortError> {
            self.commands.push(command.clone());
            self.outputs.pop_front().ok_or_else(unavailable)
        }
    }
}
