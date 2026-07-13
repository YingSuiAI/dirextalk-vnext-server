# Host Control Operator v1

This is the bootstrap/operator ingress for the Linux Host Supervisor. It is a
root-only, one-shot adapter used until the outbound Host mTLS control stream is
assembled. It does not replace that long-term transport; both must terminate in
the same `HostSupervisor` core and durable journal.

## Fixed boundary

- Executable: `/usr/local/libexec/dirextalk/dtx-agent-host-supervisor` with no
  command-line arguments.
- Host identity: `/etc/dirextalk/host-supervisor/host.json` (`0600`, root-owned).
- Release allowlist: `/etc/dirextalk/host-supervisor/releases.json` (`0600`,
  root-owned). The installer writes it only after signature and artifact-digest
  verification.
- Journal and Connector process layout remain owned by
  `dtx-agent-host-supervisor`; the operator never accepts a command, path,
  service, image, environment map, Unix user, or release URL.
- The caller sends one bounded binary frame on stdin and receives one sanitized
  JSON response on stdout. Secrets are accepted only as the optional credential
  payload of `rotate_credential`, never in the JSON header or response.

## Frame

```text
8 bytes  magic "DTXHC01\0"
4 bytes  big-endian JSON header length (1..16384)
N bytes  UTF-8 JSON request header
4 bytes  big-endian payload length (0..65536)
M bytes  opaque credential payload
```

The header protocol is `dirextalk.host-control.operator.v1`. Requests are bound
to the exact tenant and Host. Closed actions are `snapshot`, `observe`, and
`execute`; closed execute commands are `ensure`, `start`, `stop`, `restart`,
`rotate_credential`, and retain-data `remove`. Mutations carry a UUIDv7
operation ID and exact desired/observed Host revision fence. A credential
payload is valid only for `rotate_credential`, and its SHA-256 must equal the
opaque credential reference in the header.

`ensure` requires an immutable SHA-256 already present in the root-owned release
allowlist and at the fixed release path. Config delivery is separate and must
install the schema-v2 Connector config as root-owned `0440` at the fixed
instance path before start. The Go worker revalidates the invocation identity,
all fixed paths, process user, ownership, and permissions before opening its
outbound control stream.

## Crash and replay

The Rust core persists intent before credential materialization or process
mutation. The operator supplies the caller's operation ID unchanged. Retrying
the exact frame returns the durable result; reusing an operation ID for another
envelope fails closed. A different mutation cannot pass an unresolved intent.
The deployer persists its pending projection before invoking this adapter and
replays the same envelope after a local crash.
