# Command Map

Run commands from this repository root.

| Task | Command |
| --- | --- |
| format | `cargo fmt --all` |
| verify | `cargo fmt --all -- --check`; `cargo clippy --workspace --locked --all-targets --all-features -- -D warnings`; `cargo test --workspace --locked`; `cargo deny check`; `cargo audit`; `git diff --check` |
| test | `cargo test --workspace --locked` |
| build | `cargo build --workspace --locked` |
| release-build | `cargo build --workspace --locked --release` |

On Windows, a normal Rust MSVC installation also requires the Visual C++ Build Tools. When they are unavailable but the user-scoped LLVM-MinGW toolchain is installed, use the checked-in wrapper:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cargo.ps1 fmt --all -- --check
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cargo.ps1 clippy --workspace --locked --all-targets --all-features -- -D warnings
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cargo.ps1 test --workspace --locked
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cargo.ps1 deny check
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cargo.ps1 audit
```

The wrapper preserves an existing Visual Studio Developer Prompt and otherwise selects the pinned `1.97.0-x86_64-pc-windows-gnu` toolchain plus a local linker. CI and Linux use normal `cargo` commands.
