#!/usr/bin/env bash
set -euo pipefail

if [[ "${DTX_DISPOSABLE_VM_ACCEPTANCE:-}" != '1' ]]; then
  echo 'Refusing destructive Host Supervisor acceptance outside an explicitly disposable VM.' >&2
  echo 'Set DTX_DISPOSABLE_VM_ACCEPTANCE=1 only inside an isolated disposable Linux VM.' >&2
  exit 2
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo 'Host Supervisor VM acceptance must run as root.' >&2
  exit 2
fi

if [[ "$(ps -p 1 -o comm= | tr -d '[:space:]')" != 'systemd' ]]; then
  echo 'Host Supervisor VM acceptance requires systemd as PID 1.' >&2
  exit 2
fi

if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
  echo 'Host Supervisor VM acceptance requires cgroup v2.' >&2
  exit 2
fi

for capability in \
  /usr/bin/chown \
  /usr/bin/getent \
  /usr/bin/install \
  /usr/bin/rm \
  /usr/bin/rmdir \
  /usr/bin/sha256sum \
  /usr/bin/systemctl \
  /usr/bin/systemd-run \
  /usr/sbin/ip \
  /usr/sbin/nft \
  /usr/sbin/useradd \
  /usr/sbin/userdel; do
  if [[ ! -x "$capability" ]]; then
    echo "Host Supervisor VM acceptance requires $capability." >&2
    exit 2
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  cargo_home="${DTX_TEST_CARGO_HOME:-}"
  rustup_home="${DTX_TEST_RUSTUP_HOME:-}"
  if [[ -z "$cargo_home" && -n "${SUDO_USER:-}" && "$SUDO_USER" != 'root' ]]; then
    invoking_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    cargo_home="$invoking_home/.cargo"
    rustup_home="$invoking_home/.rustup"
  fi
  if [[ -x "$cargo_home/bin/cargo" && -d "$rustup_home" ]]; then
    export CARGO_HOME="$cargo_home"
    export RUSTUP_HOME="$rustup_home"
    export PATH="$CARGO_HOME/bin:$PATH"
    export CARGO_NET_OFFLINE=true
  else
    echo 'Cargo is not available to the root VM test user.' >&2
    exit 2
  fi
fi

for user in dtx01k07g0000e008000000000083 dtx01k07g0000e008000000000084; do
  if /usr/bin/getent passwd "$user" >/dev/null; then
    echo "Disposable VM resource collision: user $user already exists." >&2
    exit 2
  fi
done

for unit in \
  dirextalk-host-supervisor.service \
  dirextalk-connect@01980f00-0000-7000-8000-000000000103.service \
  dirextalk-connect@01980f00-0000-7000-8000-000000000104.service; do
  if [[ "$(/usr/bin/systemctl show --property=LoadState --value -- "$unit")" != 'not-found' ]]; then
    echo "Disposable VM resource collision: unit $unit already exists." >&2
    exit 2
  fi
done

for path in \
  /etc/dirextalk/connect/instances/01980f00-0000-7000-8000-000000000103 \
  /etc/dirextalk/connect/instances/01980f00-0000-7000-8000-000000000104 \
  /run/dirextalk/connect/01980f00-0000-7000-8000-000000000103 \
  /run/dirextalk/connect/01980f00-0000-7000-8000-000000000104 \
  /run/dirextalk/host-supervisor \
  /opt/dirextalk/host-supervisor-vm-acceptance \
  /var/lib/dirextalk/connect/instances/01980f00-0000-7000-8000-000000000103 \
  /var/lib/dirextalk/connect/instances/01980f00-0000-7000-8000-000000000104 \
  /var/lib/dirextalk/host-supervisor/journals/01980f00-0000-7000-8000-000000000102; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "Disposable VM resource collision: $path already exists." >&2
    exit 2
  fi
done


if /usr/sbin/nft list tables 2>/dev/null | grep -Eq 'dtx_hs_|dtx_host_supervisor'; then
  echo 'Disposable VM resource collision: Dirextalk nft table already exists.' >&2
  exit 2
fi

if /usr/sbin/ip address show dev lo | grep -Eq '169\.254\.169\.254|fd00:ec2::254'; then
  echo 'Disposable VM resource collision: IMDS probe address already exists on loopback.' >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/dtx-vnext-host-supervisor-vm-target}"
cd "$repo_root"

cargo build --locked -p dtx-agent-host-supervisor --example connector_fixture
cargo build --locked -p dtx-agent-host-supervisor --example host_supervisor_boundary_fixture
export DTX_CONNECT_FIXTURE_BINARY="$CARGO_TARGET_DIR/debug/examples/connector_fixture"
host_boundary_source="$CARGO_TARGET_DIR/debug/examples/host_supervisor_boundary_fixture"
host_boundary_dir='/opt/dirextalk/host-supervisor-vm-acceptance'
export DTX_HOST_BOUNDARY_FIXTURE_BINARY="$host_boundary_dir/host_supervisor_boundary_fixture"
cleanup_host_boundary_fixture() {
  /usr/bin/rm --force -- "$DTX_HOST_BOUNDARY_FIXTURE_BINARY"
  /usr/bin/rmdir -- "$host_boundary_dir" 2>/dev/null || true
}
trap cleanup_host_boundary_fixture EXIT
/usr/bin/install -d -m 0700 -o root -g root -- "$host_boundary_dir"
/usr/bin/install -m 0755 -o root -g root -- \
  "$host_boundary_source" "$DTX_HOST_BOUNDARY_FIXTURE_BINARY"
release_digest="$(/usr/bin/sha256sum "$DTX_CONNECT_FIXTURE_BINARY" | cut -d' ' -f1)"
release_path="/opt/dirextalk/connect/versions/$release_digest"
if [[ -e "$release_path" || -L "$release_path" ]]; then
  echo "Disposable VM resource collision: $release_path already exists." >&2
  exit 2
fi
cargo test --locked -p dtx-agent-host-supervisor --test linux_vm_acceptance \
  two_connectors_are_isolated_and_recover_an_intent_after_supervisor_crash -- \
  --ignored --exact --nocapture

cleanup_host_boundary_fixture
trap - EXIT

for user in dtx01k07g0000e008000000000083 dtx01k07g0000e008000000000084; do
  if /usr/bin/getent passwd "$user" >/dev/null; then
    echo "Host Supervisor VM acceptance leaked user $user." >&2
    exit 1
  fi
done

for unit in \
  dirextalk-host-supervisor.service \
  dirextalk-connect@01980f00-0000-7000-8000-000000000103.service \
  dirextalk-connect@01980f00-0000-7000-8000-000000000104.service; do
  if [[ "$(/usr/bin/systemctl show --property=LoadState --value -- "$unit")" != 'not-found' ]]; then
    echo "Host Supervisor VM acceptance leaked unit $unit." >&2
    exit 1
  fi
done

for path in \
  /etc/dirextalk/connect/instances/01980f00-0000-7000-8000-000000000103 \
  /etc/dirextalk/connect/instances/01980f00-0000-7000-8000-000000000104 \
  /run/dirextalk/connect/01980f00-0000-7000-8000-000000000103 \
  /run/dirextalk/connect/01980f00-0000-7000-8000-000000000104 \
  /run/dirextalk/host-supervisor \
  /opt/dirextalk/host-supervisor-vm-acceptance \
  /var/lib/dirextalk/connect/instances/01980f00-0000-7000-8000-000000000103 \
  /var/lib/dirextalk/connect/instances/01980f00-0000-7000-8000-000000000104 \
  /var/lib/dirextalk/host-supervisor/journals/01980f00-0000-7000-8000-000000000102 \
  "$release_path"; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "Host Supervisor VM acceptance leaked path $path." >&2
    exit 1
  fi
done

if /usr/sbin/nft list tables 2>/dev/null | grep -Eq 'dtx_hs_|dtx_host_supervisor'; then
  echo 'Host Supervisor VM acceptance leaked a Dirextalk nft table.' >&2
  exit 1
fi

if /usr/sbin/ip address show dev lo | grep -Eq '169\.254\.169\.254|fd00:ec2::254'; then
  echo 'Host Supervisor VM acceptance leaked an IMDS loopback probe address.' >&2
  exit 1
fi
