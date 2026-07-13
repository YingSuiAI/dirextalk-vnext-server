#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::BTreeMap,
        fs, io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
        os::unix::net::UnixStream,
        path::{Path, PathBuf},
        process, thread,
        time::Duration,
    };

    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const CONNECT_TIMEOUT: Duration = Duration::from_millis(150);
    const CONTROL_SOCKET: &str = "/run/dirextalk/host-supervisor/control.sock";
    const INSTANCES_ROOT: &str = "/var/lib/dirextalk/connect/instances";

    pub fn run() -> Result<(), FixtureError> {
        let arguments = Arguments::parse(std::env::args().skip(1))?;
        loop {
            if arguments.workspace_dir.join("crash-loop").exists() {
                return Err(FixtureError);
            }
            let state = Observation::collect(&arguments)?;
            state.persist(&arguments.runtime_dir)?;
            thread::sleep(POLL_INTERVAL);
        }
    }

    struct Arguments {
        instance_id: String,
        workspace_dir: PathBuf,
        runtime_dir: PathBuf,
        credential_file: PathBuf,
    }

    impl Arguments {
        fn parse(values: impl Iterator<Item = String>) -> Result<Self, FixtureError> {
            let values = values.collect::<Vec<_>>();
            let Some((mode, tail)) = values.split_first() else {
                return Err(FixtureError);
            };
            if mode != "supervisor" || tail.len() != 16 {
                return Err(FixtureError);
            }
            let mut fields = BTreeMap::new();
            for pair in tail.chunks_exact(2) {
                if !pair[0].starts_with("--") || fields.insert(pair[0].as_str(), &pair[1]).is_some()
                {
                    return Err(FixtureError);
                }
            }
            for required in [
                "--instance-id",
                "--tenant-id",
                "--host-id",
                "--config-dir",
                "--data-dir",
                "--workspace-dir",
                "--runtime-dir",
                "--credential-file",
            ] {
                if !fields.contains_key(required) {
                    return Err(FixtureError);
                }
            }
            // Eight key/value pairs are required. The fixed supervisor adapter
            // deliberately supplies no arbitrary environment or command input.
            if fields.len() != 8 || tail.len() != 16 {
                return Err(FixtureError);
            }
            let instance_id = fields["--instance-id"].clone();
            if !is_uuid(&instance_id)
                || !is_uuid(fields["--tenant-id"])
                || !is_uuid(fields["--host-id"])
            {
                return Err(FixtureError);
            }
            let runtime_dir = PathBuf::from(fields["--runtime-dir"]);
            let credential_file = PathBuf::from(fields["--credential-file"]);
            let config_dir = PathBuf::from(fields["--config-dir"]);
            let data_dir = PathBuf::from(fields["--data-dir"]);
            let workspace_dir = PathBuf::from(fields["--workspace-dir"]);
            if config_dir != format!("/etc/dirextalk/connect/instances/{instance_id}")
                || data_dir != format!("/var/lib/dirextalk/connect/instances/{instance_id}/data")
                || workspace_dir
                    != format!("/var/lib/dirextalk/connect/instances/{instance_id}/workspace")
                || runtime_dir != format!("/run/dirextalk/connect/{instance_id}/worker")
                || credential_file
                    != format!(
                        "/run/dirextalk/connect/{instance_id}/credentials/control.credential"
                    )
            {
                return Err(FixtureError);
            }
            Ok(Self {
                instance_id,
                workspace_dir,
                runtime_dir,
                credential_file,
            })
        }
    }

    struct Observation {
        pid: u32,
        uid: u32,
        credential_generation: u64,
        cgroup: String,
        isolation: [bool; 4],
    }

    impl Observation {
        fn collect(arguments: &Arguments) -> Result<Self, FixtureError> {
            Ok(Self {
                pid: process::id(),
                uid: current_uid()?,
                credential_generation: credential_generation(&arguments.credential_file)?,
                cgroup: current_cgroup()?,
                isolation: [
                    sibling_data_inaccessible(&arguments.instance_id)?,
                    is_policy_denied(UnixStream::connect(CONTROL_SOCKET)),
                    is_policy_denied(TcpStream::connect_timeout(
                        &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80),
                        CONNECT_TIMEOUT,
                    )),
                    is_policy_denied(TcpStream::connect_timeout(
                        &SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)),
                            80,
                        ),
                        CONNECT_TIMEOUT,
                    )),
                ],
            })
        }

        fn persist(&self, runtime_dir: &Path) -> Result<(), FixtureError> {
            let cgroup = self
                .cgroup
                .chars()
                .map(|character| {
                    if matches!(character, '\n' | '\r' | '=') {
                        '_'
                    } else {
                        character
                    }
                })
                .collect::<String>();
            let body = format!(
                concat!(
                    "schema=1\n",
                    "pid={}\n",
                    "uid={}\n",
                    "credential_generation={}\n",
                    "cgroup={}\n",
                    "sibling_data_inaccessible={}\n",
                    "control_socket_inaccessible={}\n",
                    "imds_v4_inaccessible={}\n",
                    "imds_v6_inaccessible={}\n"
                ),
                self.pid,
                self.uid,
                self.credential_generation,
                cgroup,
                self.isolation[0],
                self.isolation[1],
                self.isolation[2],
                self.isolation[3],
            );
            let temporary = runtime_dir.join("fixture.state.tmp");
            let target = runtime_dir.join("fixture.state");
            fs::write(&temporary, body).map_err(|_| FixtureError)?;
            fs::rename(temporary, target).map_err(|_| FixtureError)
        }
    }

    fn current_uid() -> Result<u32, FixtureError> {
        let status = fs::read_to_string("/proc/self/status").map_err(|_| FixtureError)?;
        let line = status
            .lines()
            .find(|line| line.starts_with("Uid:\t"))
            .ok_or(FixtureError)?;
        let mut values = line[5..].split_ascii_whitespace();
        let real = values
            .next()
            .ok_or(FixtureError)?
            .parse::<u32>()
            .map_err(|_| FixtureError)?;
        let effective = values
            .next()
            .ok_or(FixtureError)?
            .parse::<u32>()
            .map_err(|_| FixtureError)?;
        if real == 0 || real != effective {
            return Err(FixtureError);
        }
        Ok(real)
    }

    fn current_cgroup() -> Result<String, FixtureError> {
        let value = fs::read_to_string("/proc/self/cgroup").map_err(|_| FixtureError)?;
        let line = value.lines().find(|line| line.starts_with("0::/"));
        line.map(str::to_owned).ok_or(FixtureError)
    }

    fn credential_generation(path: &Path) -> Result<u64, FixtureError> {
        let value = fs::read_to_string(path).map_err(|_| FixtureError)?;
        let generation = value
            .lines()
            .find_map(|line| line.strip_prefix("generation="))
            .ok_or(FixtureError)?;
        generation.parse::<u64>().map_err(|_| FixtureError)
    }

    fn sibling_data_inaccessible(instance_id: &str) -> Result<bool, FixtureError> {
        let entries = match fs::read_dir(INSTANCES_ROOT) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
            Err(_) => return Err(FixtureError),
        };
        for entry in entries {
            let entry = entry.map_err(|_| FixtureError)?;
            if entry.file_name() == instance_id {
                continue;
            }
            if fs::read_dir(entry.path().join("data")).is_ok()
                || fs::read_dir(entry.path().join("workspace")).is_ok()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn is_policy_denied<T>(result: io::Result<T>) -> bool {
        // The VM gate keeps a root-reachable listener on both IMDS addresses.
        // systemd cgroup-BPF reports EPERM/EACCES. The fixed UID nft fallback
        // uses DROP, which reaches the bounded connect timeout while the root
        // namespace's listener remains immediately reachable.
        result.is_err_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::TimedOut
            ) || matches!(error.raw_os_error(), Some(1 | 13 | 110 | 111))
        })
    }

    fn is_uuid(value: &str) -> bool {
        value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
            })
    }

    #[derive(Clone, Copy, Debug)]
    pub struct FixtureError;

    impl std::fmt::Display for FixtureError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("connector VM fixture failed")
        }
    }

    impl std::error::Error for FixtureError {}

    #[cfg(test)]
    mod tests {
        use super::*;

        fn valid_arguments() -> Vec<String> {
            let instance_id = "01890f00-0000-7000-8000-000000000001";
            vec![
                "supervisor",
                "--instance-id",
                instance_id,
                "--tenant-id",
                "01890f00-0000-7000-8000-000000000002",
                "--host-id",
                "01890f00-0000-7000-8000-000000000003",
                "--config-dir",
                "/etc/dirextalk/connect/instances/01890f00-0000-7000-8000-000000000001",
                "--data-dir",
                "/var/lib/dirextalk/connect/instances/01890f00-0000-7000-8000-000000000001/data",
                "--workspace-dir",
                "/var/lib/dirextalk/connect/instances/01890f00-0000-7000-8000-000000000001/workspace",
                "--runtime-dir",
                "/run/dirextalk/connect/01890f00-0000-7000-8000-000000000001/worker",
                "--credential-file",
                "/run/dirextalk/connect/01890f00-0000-7000-8000-000000000001/credentials/control.credential",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        }

        #[test]
        fn accepts_only_the_fixed_supervisor_argument_shape() {
            let parsed = Arguments::parse(valid_arguments().into_iter()).expect("fixed shape");
            assert_eq!(parsed.instance_id, "01890f00-0000-7000-8000-000000000001");

            let mut arbitrary = valid_arguments();
            arbitrary.extend(["--command".to_owned(), "/bin/sh".to_owned()]);
            assert!(Arguments::parse(arbitrary.into_iter()).is_err());

            let mut wrong_path = valid_arguments();
            let credential = wrong_path
                .iter()
                .position(|value| value == "--credential-file")
                .expect("fixture key");
            wrong_path[credential + 1] = "/tmp/credential".to_owned();
            assert!(Arguments::parse(wrong_path.into_iter()).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), linux::FixtureError> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("connector VM fixture is Linux-only");
    std::process::exit(2);
}
