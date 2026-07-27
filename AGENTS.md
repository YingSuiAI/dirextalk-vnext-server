# Dirextalk vNext Server

This repository owns the Matrix-independent Dirextalk vNext server protocol and control plane.

## Start

1. At a project/session boundary read [`docs/internal-test-alpha.md`](docs/internal-test-alpha.md); during an active stage reread only its task, direct dependencies, and contract sections. Implement only work within the current Internal Test Alpha scope.
2. Read `COMMANDS.md`, then run `git status --short --branch` before editing.
3. Treat `protocol/`, public Rust types, migrations, state machines, authorization, leases, job/resource transitions, and error codes as contracts.
4. Preserve unrelated work and keep each commit limited to one verified task ID.

## Engineering rules

- This vNext repository is being built from zero. Feature and logic changes
  must adopt the best target-product contract directly. Do not retain
  historical-version compatibility code.
- Do not add dual paths, version negotiation, compatibility shims, or fallback
  branches for superseded designs. Replace the old contract and migrate test or
  development data directly; a frozen external boundary requires an explicit
  product decision, not a second production path.
- Prioritize core product behavior and real device/node evidence. Do not add
  anti-counterfeit or exhaustive adversarial-observer machinery beyond the
  minimal commit/image/config/APK/device evidence required by Internal Test
  Alpha unless a concrete product threat or gate needs it.
- Review the active Internal Test Alpha business path strictly; model and fixture tests do not
  substitute for executable integration evidence.
- The primary worktree is the default. Create an extra worktree only for a
  concurrent, non-overlapping writer in this repository.
- One owner handles locate, implementation, focused test, self-review, and
  commit for one coherent change. At stage close, perform one accumulated
  review; ordinary fixes do not trigger another full review unless they change
  a high-risk public, persistence, or deployment contract.
- During Internal Test Alpha, ordinary single-owner work does not auto-load or
  use `$govern-agent-system` and does not delegate. The primary-worktree owner
  performs the full workflow directly. Use governance delegation only when the
  user explicitly requests it for this task or when two genuinely independent,
  non-overlapping writer surfaces exist.
- Keep the workspace on the pinned Rust toolchain and Rust 2024 Edition.
- Workspace code forbids unsafe Rust. A future exception requires an isolated crate, an ADR, and an independent security review.
- Use test-first slices for protocol contracts, identity, authorization, persistence, concurrency, cloud mutations, and state machines. Keep low-risk scaffolding lightweight.
- For one active high-risk stage, start with the smallest boundary test that proves the critical invariant, then batch implementation. Use compile feedback or a directly relevant test only when it resolves an active uncertainty; do not create a test/verification/review cycle for each internal module.
- Domain and wire crates must not depend on Axum, SQLx, AWS SDKs, agent frameworks, or concrete storage.
- Never expose a generic cloud SDK request, shell command, secret value, raw private key, decrypted MLS content, or unredacted provider response through public APIs.
- Persist an intent before every external side effect; use idempotency, fencing, reconciliation, and durable outbox patterns from the Internal Test Alpha contracts.
- Use `apply_patch` for ordinary edits. Do not commit build output, `.codegraph/`, local databases, logs, credentials, or generated cloud state.

## Finish

At one real stage boundary, run the affected focused tests and documented fast checks, then review the accumulated diff against the current Internal Test Alpha acceptance criteria. Run broad repository `verify` commands only when `COMMANDS.md` makes them a stage requirement or focused evidence is insufficient. Do not repeat slow database/integration targets after unrelated edits. Do not treat optional production or release hardening as Internal Test Alpha evidence.
