#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        fs::{self, File, OpenOptions},
        io::Write as _,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
        os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
        path::Path,
        thread,
        time::Duration,
    };

    use dtx_agent_host_supervisor::LinuxHostNetworkBoundary;

    const STATE: &str = "/run/dirextalk/host-supervisor/network-boundary.state";
    const PROBE_TRIGGER: &str = "/run/dirextalk/host-supervisor/probe-nft-alone.trigger";
    const TIMEOUT: Duration = Duration::from_millis(150);
    const POLL_INTERVAL: Duration = Duration::from_millis(50);

    LinuxHostNetworkBoundary::install()?;
    let probe = || {
        let addresses = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)),
                80,
            ),
        ];
        addresses.map(|address| {
            TcpStream::connect_timeout(&address, TIMEOUT).is_err_and(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::TimedOut
                ) || matches!(error.raw_os_error(), Some(1 | 13 | 110 | 111))
            })
        })
    };
    let write_state = |generation: u64, denied: [bool; 2]| -> std::io::Result<()> {
        let target = Path::new(STATE);
        let temporary = target.with_extension("tmp");
        let body = format!(
            "schema=1\nunit={}\nprobe_generation={generation}\nimds_v4_inaccessible={}\nimds_v6_inaccessible={}\n",
            LinuxHostNetworkBoundary::unit_name(),
            denied[0],
            denied[1],
        );
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, target)?;
        File::open(target.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "state path has no parent")
        })?)?
        .sync_all()
    };
    let record_result = |generation| -> Result<(), Box<dyn std::error::Error>> {
        let denied = probe();
        write_state(generation, denied)?;
        if denied.into_iter().all(|value| value) {
            Ok(())
        } else {
            Err("Host Supervisor IMDS boundary is not active".into())
        }
    };

    let mut generation = 1_u64;
    record_result(generation)?;
    loop {
        match fs::symlink_metadata(PROBE_TRIGGER) {
            Ok(metadata)
                if metadata.file_type().is_file() && !metadata.file_type().is_symlink() =>
            {
                fs::remove_file(PROBE_TRIGGER)?;
                generation = generation
                    .checked_add(1)
                    .ok_or("probe generation overflow")?;
                record_result(generation)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err("Host Supervisor probe trigger is not a regular file".into()),
            Err(error) => return Err(error.into()),
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {}
