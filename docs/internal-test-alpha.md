# Internal Test Alpha

This is the single active cross-repository contract for
`dirextalk-vnext-server`, `dirextalk-vnext-client`,
`dirextalk-agent-connector`, and `dirextalk-vnext-deployer`. It is fresh-only:
use an empty schema and fresh client/device state, with no legacy import,
dual-write, or compatibility path. This document defines the target and the
evidence required; it does not claim that existing code or tests have passed.
The primary worktree is the default; an extra worktree is only for a concurrent
non-overlapping writer. One owner carries each change from locate through
implementation, focused test, self-review, and commit, followed by one
accumulated stage-close review. Ordinary fixes do not require a second full
review unless they alter a high-risk public, persistence, or deployment
contract.
During Internal Test Alpha, ordinary single-owner work does not auto-load or use
`$govern-agent-system` and does not delegate: the primary-worktree owner carries
the full workflow directly. Governance delegation is allowed only when the user
explicitly requests it for this task or when two genuinely independent,
non-overlapping writer surfaces exist.

## 1. Current business goal

Prove one complete, real-device IM and Agent path across three independent
origins, in this exact priority order:

`A/B/C origins; three clients provision/contact/Direct Pull+ACK; Group invite/join/owner approval/B+C ACK; WSS highwater→Pull→atomic ACK; Connector lease flow; Sidecar encrypted plane; schema3 Host/Deployer AcceptanceObserved+rollback; exact commit/image/config/APK hash internal bundle.`

1. A/B/C origins; three clients provision and establish contacts, then deliver
   a Direct message through Pull and ACK.
2. Group invite, join, owner approval, and B+C message ACK.
3. WSS highwater notification → Pull → atomic ACK, including reconnect and
   replay after a lost response.
4. Connector lease flow: offer is not authority; only the exact matching
   `RunLeaseGranted` may start the runtime, and every event carries both
   Connector and Run lease fences.
5. Sidecar encrypted plane: conversation and runtime input remain opaque to
   Agent Control and the server.
6. Schema3 Host/Deployer `AcceptanceObserved` evidence and rollback behavior.
7. An internal bundle containing exact commit, image, configuration, and APK
   hashes.

## 2. Inputs and outputs

Inputs are the pinned server/client/Connector/Deployer commits, fresh schema
baseline, disposable A/B/C origins, three enrolled Android devices, the
Connector credential and lease configuration, the Sidecar endpoint, schema3
Host/Deployer plan, and immutable image/config/APK files. Prompt and message
content enters only as encrypted conversation events or opaque artifacts.

The output is an owner-recorded Internal Test Alpha bundle: origin and device
identities, contact and group receipts, WSS highwater/Pull/atomic-ACK traces,
lease-fenced Connector receipts, Sidecar ciphertext references,
`AcceptanceObserved` and rollback records, exact commit/image/config/APK
SHA-256 values, and a pass/fail decision. Logs contain IDs, digests, and
bounded error codes—not plaintext, secrets, or private keys.

## 3. Dependencies

- Server: fresh PostgreSQL schema, A/B/C node origins, Identity, Group,
  Mailbox, Realtime/WSS, and opaque Push wake-up paths.
- Client: native Rust runtime plus Android/Flutter UI, platform trust for the
  disposable CA, and the three-device acceptance actions.
- Connector: one outbound identity, Agent Control session, exact lease fence,
  and the opaque Sidecar encrypted data plane.
- Deployer/Host: schema3 plan, fixed host supervisor boundary,
  `AcceptanceObserved` readback, and explicit rollback record.
- Tooling: Docker/Compose, PostgreSQL, Android SDK/JDK, three reachable
  Android devices, and the commands in [`COMMANDS.md`](../COMMANDS.md).

All dependencies are disposable and pinned for this run. Production release
hardening is outside the critical path and cannot turn an incomplete real
workflow into a pass.

## 4. One happy path

1. Reset server databases and all three clients. Start origins A, B, and C and
   provision one client on each; record the exact identities and commits.
2. Establish contacts A↔B, B↔C, and C↔A with origin-bound authorization.
   Send Direct messages on those contacts; each recipient observes the wake-up,
   Pulls at the durable highwater, commits client state/MLS/dedup/cursor and
   Mailbox ACK atomically, and records its ACK outcome.
3. A creates the Group and invites B and C. B and C join; A performs owner
   approval/MLS commit; deliver a Group message and require both B+C to Pull,
   commit, and ACK.
4. Drop and restore WSS, replay the same highwater, and prove that Pull before
   atomic ACK is the recovery authority with no duplicate side effect.
5. Run Connector offer → exact `RunLeaseGranted` → runtime checkpoint/output →
   completion or failure → release. Inject a stale lease/fence and require a
   fail-closed rejection.
6. Verify all conversation and runtime input travels through the Sidecar as
   encrypted opaque data; no server or Agent Control log contains plaintext.
7. Execute the schema3 Host/Deployer plan, capture `AcceptanceObserved`, force
   the reviewed rollback path, and capture its terminal evidence.
8. Seal the internal bundle and compare every recorded hash to the exact
   source commit, image digest, configuration digest, and APK SHA-256.

## 5. Executable acceptance

The run owner must execute and retain output for the focused server command
sequence in [`COMMANDS.md`](../COMMANDS.md), the client and Connector focused
commands in their repositories, and the Deployer plan/evidence validation.
The current Android script can be invoked for its disposable setup and shell
checks:

```bash
bash scripts/android-acceptance.sh --run
```

It does not execute Direct/Group and terminates before that scenario. The
three-device Direct/Group runner, including its device and client wiring, is a
missing target capability; no current command may be presented as executing
that acceptance path.

Acceptance is pass only when the bundle contains positive evidence for every
step in the happy path, exact hashes, and a clean fresh reset. A green unit,
fixture, model, or deterministic self-check is useful evidence but never
substitutes for the real three-device run. Any missing receipt, stale-fence
acceptance, plaintext observation, changed hash, or incomplete rollback is a
fail.

## 6. Deferred items

The following may be hardened only after Internal Test Alpha passes: production
image publication and host installation, long-lived release retention,
cross-environment operations, observability expansion, and non-critical
operator ergonomics. They must not add a second active workflow or block the
fresh internal test.

See [`docs/deferred-production/`](deferred-production/) for tagged production
and release narratives.
