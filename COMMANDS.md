# Command Map

The active cross-repository contract is
[`docs/internal-test-alpha.md`](docs/internal-test-alpha.md). Run commands from
this repository root. Focused checks come first; production and release checks
below are optional hardening and cannot block Internal Test Alpha.

## Focused server checks

| Task | Command |
| --- | --- |
| Android harness self-check | `bash scripts/test-android-acceptance.sh` |
| Android setup/trust run (not Direct/Group acceptance) | `bash scripts/android-acceptance.sh --run` |
| focused server tests | `cargo test --locked` |
| persistence baseline | `cargo test -p dtx-storage --test migrations --locked` |
| persistence contracts | `cargo test -p dtx-storage --test persistence_contract --locked` |
| generated contracts | `cargo run -p dtx-protocol --locked -- check-generated .` |
| schema and vectors | `cargo run -p dtx-protocol --locked -- validate .` |
| exact Alpha inventory | `cargo run -p dtx-protocol --locked -- check-alpha .` |
| format | `cargo fmt` |
| build | `cargo build --locked` |
| verify (Ubuntu/WSL) | `bash scripts/verify.sh` |
| verify (Windows) | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify.ps1` |

## Optional production hardening

| Task | Command |
| --- | --- |
| production stack contract | `bash scripts/check-production-stack.sh` |
| production PostgreSQL gate | `bash scripts/test-production-postgres.sh` |
| release image contract | `bash scripts/check-release-image.sh` |
| publish production image | `bash scripts/publish-production-release.sh` |
| clean interrupted release builder | `bash scripts/cleanup-production-release.sh` |

The focused commands establish implementation evidence only. Internal Test
Alpha passes only with the executable server/client/Connector/Deployer bundle
and three-device record described in the active spec; no local command alone
is a completion claim. The current Android script provides setup and shell
checks only and terminates before Direct/Group. A three-device Direct/Group
runner is a missing target capability, not an executable command in this map.
