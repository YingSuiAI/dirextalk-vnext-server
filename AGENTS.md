# Dirextalk vNext Server

This repository owns the Matrix-independent Dirextalk vNext server protocol and control plane.

## Start

1. At a project/session boundary read `../docs/dirextalk-vnext-development.md`; during an active stage reread only its task, direct dependencies, and contract sections. Implement only a claimed task ID whose dependencies are complete.
2. Read `COMMANDS.md`, then run `git status --short --branch` before editing.
3. Treat `protocol/`, public Rust types, migrations, state machines, authorization, leases, job/resource transitions, and error codes as contracts.
4. Preserve unrelated work and keep each commit limited to one verified task ID.

## Engineering rules

- Keep the workspace on the pinned Rust toolchain and Rust 2024 Edition.
- Workspace code forbids unsafe Rust. A future exception requires an isolated crate, an ADR, and an independent security review.
- Use test-first slices for protocol contracts, identity, authorization, persistence, concurrency, cloud mutations, and state machines. Keep low-risk scaffolding lightweight.
- For one active high-risk stage, start with the smallest boundary test that proves the critical invariant, then batch implementation. Use compile feedback or a directly relevant test only when it resolves an active uncertainty; do not create a test/verification/review cycle for each internal module.
- Domain and wire crates must not depend on Axum, SQLx, AWS SDKs, agent frameworks, or concrete storage.
- Never expose a generic cloud SDK request, shell command, secret value, raw private key, decrypted MLS content, or unredacted provider response through public APIs.
- Persist an intent before every external side effect; use idempotency, fencing, reconciliation, and durable outbox patterns from the development specification.
- Use `apply_patch` for ordinary edits. Do not commit build output, `.codegraph/`, local databases, logs, credentials, or generated cloud state.

## Finish

At one real stage boundary, run the affected focused tests and documented fast checks, then review the accumulated diff against the claimed task and its acceptance criteria. Run broad repository `verify` commands only when `COMMANDS.md` makes them a stage requirement, focused evidence is insufficient, or release/deployment is in scope. Do not repeat slow database/integration targets after unrelated edits. Update a task checkbox only after its full production contract is complete; a foundation commit may remain under an unchecked task.
