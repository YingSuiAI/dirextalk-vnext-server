# Command Map

Run commands from this repository root.

| Task | Command |
| --- | --- |
| format | `cargo fmt --all` |
| verify (Windows) | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify.ps1` |
| test | `cargo test --workspace --locked` |
| persistence migrations | `cargo test -p dtx-storage --test migrations --locked` |
| persistence contracts | `cargo test -p dtx-storage --test persistence_contract --locked` |
| Host Supervisor VM acceptance (destructive; isolated disposable Linux VM only) | `sudo DTX_DISPOSABLE_VM_ACCEPTANCE=1 bash scripts/test-host-supervisor-vm.sh` |
| SQLx migration/prepare gate | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sqlx-prepare.ps1` |
| testkit dependency boundary | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\check-testkit-boundary.ps1` |
| build | `cargo build --workspace --locked` |
| release-build | `cargo build --workspace --locked --release` |
| regenerate contracts | `cargo run -p dtx-protocol --locked -- generate .` |
| check generated contracts | `cargo run -p dtx-protocol --locked -- check-generated .` |
| validate schema and vectors | `cargo run -p dtx-protocol --locked -- validate .` |
| check frozen v1 contracts | `cargo run -p dtx-protocol --locked -- check-breaking .` |
| initialize a new baseline | `cargo run -p dtx-protocol --locked -- freeze-baseline .` |

The full verification gate checks generated Rust/Dart sources before and after
idempotent regeneration, validates CDDL/OpenAPI/Protobuf and golden vectors,
enforces the frozen v1 baseline, runs Dart VM and compiled-JavaScript
conformance, then runs fmt/clippy/test/deny/audit and `git diff --check`. CI pins
the latest stable Dart SDK selected for S0.3 (`3.12.2`). `freeze-baseline` is an
initialization command for a new versioned contract; once its manifest exists it
accepts only an exact no-op. New events, errors, or artifacts require a new
versioned schema/manifest and cannot be appended to the published v1.0 baseline.

On Windows, a normal Rust MSVC installation also requires the Visual C++ Build Tools. When they are unavailable but the user-scoped LLVM-MinGW toolchain is installed, use the checked-in wrapper:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cargo.ps1 fmt --all -- --check
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cargo.ps1 clippy --workspace --locked --all-targets --all-features -- -D warnings
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cargo.ps1 test --workspace --locked
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cargo.ps1 deny check
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cargo.ps1 audit
```

The wrapper preserves an existing Visual Studio Developer Prompt and otherwise selects the pinned `1.97.0-x86_64-pc-windows-gnu` toolchain plus a local linker. CI and Linux use normal `cargo` commands.

### Opt-in local PostgreSQL integration tests

Integration tests use Testcontainers by default. To avoid container startup during
local development, set `DTX_TEST_LOCAL_POSTGRES=1` together with literal-loopback
`DTX_TEST_LOCAL_POSTGRES_HOST`, `DTX_TEST_LOCAL_POSTGRES_PORT`,
`DTX_TEST_LOCAL_POSTGRES_USER`, `DTX_TEST_LOCAL_POSTGRES_PASSWORD`, and
`DTX_TEST_LOCAL_POSTGRES_MAINTENANCE_DATABASE`. The harness creates only a unique
`dtx_test_<uuid>` database and removes it with `DROP DATABASE ... WITH (FORCE)`
after the test; it rejects DNS and non-loopback hosts. Keep credentials ephemeral
in the invoking shell and never save them in tracked files.

The SQLx gate uses exact PostgreSQL `18.4-alpine3.24` in an ephemeral Docker
container. Install its pinned user-scoped CLI once when it is not already
available:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cargo.ps1 install sqlx-cli --version 0.9.0 --force --no-default-features --features 'rustls,postgres' --root "$env:LOCALAPPDATA\Dirextalk\tools\sqlx-cli-0.9.0"
```
