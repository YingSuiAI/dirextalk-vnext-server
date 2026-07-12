# Dirextalk vNext Server

This repository owns the Matrix-independent Dirextalk vNext server protocol and control plane.

## Start

1. Read `../docs/dirextalk-vnext-development.md` and implement only a claimed task ID whose dependencies are complete.
2. Read `COMMANDS.md`, then run `git status --short --branch` before editing.
3. Treat `protocol/`, public Rust types, migrations, state machines, authorization, leases, job/resource transitions, and error codes as contracts.
4. Preserve unrelated work and keep each commit limited to one verified task ID.

## Engineering rules

- Keep the workspace on the pinned Rust toolchain and Rust 2024 Edition.
- Workspace code forbids unsafe Rust. A future exception requires an isolated crate, an ADR, and an independent security review.
- Use test-first slices for protocol contracts, identity, authorization, persistence, concurrency, cloud mutations, and state machines. Keep low-risk scaffolding lightweight.
- Domain and wire crates must not depend on Axum, SQLx, AWS SDKs, agent frameworks, or concrete storage.
- Never expose a generic cloud SDK request, shell command, secret value, raw private key, decrypted MLS content, or unredacted provider response through public APIs.
- Persist an intent before every external side effect; use idempotency, fencing, reconciliation, and durable outbox patterns from the development specification.
- Use `apply_patch` for ordinary edits. Do not commit build output, `.codegraph/`, local databases, logs, credentials, or generated cloud state.

## Finish

Run the focused test while developing, then the repository `verify` commands. Review the full diff against the claimed task and its acceptance criteria. Update the task checkbox only after production code and required verification pass, then create one focused commit.
