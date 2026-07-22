# ADR-0004: One Connector, One Process, One Lease

- Status: Accepted for MC2
- Date: 2026-07-13
- Owners: `dtx-agent-host`, `dtx-agent-host-supervisor`, `dtx-connect-registry`

## Context

Dirextalk must run Codex, OpenClaw, Eino, Rig, and future runtimes concurrently without sharing process identity, credentials, workspaces, crypto state, failure domains, or routing authority. The legacy multi-project Connect process cannot provide that isolation. A disconnected worker also cannot be trusted to restart or remove itself.

## Decision

Each Connector Instance has exactly one adapter, one OS process, one control certificate, one boot identity, and at most one active lease. Every instance receives a distinct Unix identity, fixed service identity, config/data/workspace/runtime/log namespace, and cgroup-v2 resource boundary. A restart or removal targets one derived Connector identity and must not mutate a sibling.

The Rust Host Supervisor is the only local process-control authority. Its public capability is closed to:

- ensure an allowlisted adapter at an immutable release digest;
- start, stop, or restart one known Connector;
- rotate one opaque credential artifact reference;
- remove runtime state while retaining user data by default;
- observe one Connector without mutating desired state.

Host Control v2 adds one separately framed install lifecycle without changing
those v1 operations: prepare exact Connector bootstrap material and finalize
its exact prepared receipt after an independent Running observation. The two
IDs remain distinct: a Host operation fences journal/process effects, while a
Connector lifecycle operation binds the redacted plan, secret handoff, and
Connector-owned receipts. The operator accepts bounded bytes and typed
IDs/digests only; all executable, config, trust, credential, bearer, unit, and
receipt paths are fixed derivatives. See `docs/host-control-operator-v2.md`.

No public type accepts a shell command, argument vector, environment map, artifact URL, filesystem path, image name, Unix user, or service name. A trusted release catalog exposes two distinct views: immutable known history for replay/recovery/removal, and the current runnable allowlist for new effects. A release revoked after a durable Start/Restart intent is stopped and completed with a durable `PolicyBlocked` receipt; cold reconciliation never revives it. Linux layout, users, units, and paths are derived internally from validated IDs.

Host-local mutations use a host-global desired revision. A command is bound to tenant, host, operation ID, exact predecessor revision, and a domain-separated command digest. The Supervisor durably records a resolved intent before any credential, filesystem, or process side effect. Process-controller idempotency uses the strongly typed pair of the original durable operation ID and a closed phase: `requested-effect` or deterministic `policy-compensation`; a compensation stop can therefore never collide with the start/restart it reverses. Only a verified OS postcondition advances the observed revision. Exact retries return the durable receipt; a different body reusing an operation ID conflicts. A pending operation blocks a different successor until reconciliation completes.

The versioned journal retains enough intent, receipt, disposition, and non-secret Supervisor snapshot state to recover every crash window. Version 4 gives every record an immutable sequence and previous-record digest, binds the first record to a Host-specific genesis anchor, and stores the current chain tip; a Pending-to-Completed replacement preserves its sequence and advances the tip. Install lifecycle receipts add an optional non-secret proof. Its absent encoding remains byte-identical to pre-install-proof v4 records, while present proofs bind lifecycle facts, prepared/finalized receipt digests, opaque credential/bearer references, and the required process observation. Validation recomputes the complete snapshot and record chains, including every historical lifecycle transition, so stale or incomplete truncation metadata, reordering, renumbering, and partial rewrites fail closed. The production journal and its ancestors are root-owned: the unkeyed SHA-256 chain detects corruption and incomplete rewrites, but without an external monotonic anchor it cannot distinguish a self-consistent rollback to an earlier valid whole-file image. Such rollback, and an active root attacker that can rewrite the file and recompute the complete chain, are explicitly outside this integrity boundary; either requires an anchor or key held outside the Host root boundary. Recovery observes the actual OS state and reconciles by operation ID; it does not blindly repeat restart, rotation, removal, or bootstrap. Process adapters must make each operation idempotent by host and operation ID. A release-bound durable crash-loop marker survives systemd state reset and ordinary cold reconciliation; only an explicit Ensure, Stop, Restart, or Remove clears it.

A credential artifact reference is an opaque control-plane handle, never a content digest. The trusted provider separately proves the staged file's bounded content (currently 64 KiB maximum), stable inode/length, single-link status, owner, and mode. Activation copies into a root-only operation path, verifies the internal SHA-256 proof, changes ownership to `root:<connector-group>` with mode `0440`, atomically renames the file, and then records the opaque reference plus non-secret proof. Workers cannot rewrite the active credential or read a sibling's credential.

The production Host workload identity uses the canonical URI namespace:

```text
spiffe://dirextalk.internal/v1/tenants/<tenant-id>/hosts/<host-id>
```

The namespace is not a DNS discovery mechanism. Trust comes from the deployment-specific CA roots plus the current `HostCredentialId`, certificate fingerprint, validity, EKU, revocation, and exact URI-SAN binding. The authorization image has a compare-and-swap revision and durable irreversible history of retired credential IDs and fingerprints, so restart or stale configuration cannot roll a revoked/rotated credential back into service. Connector and Host identities are distinct and cannot impersonate one another.

Linux uses fixed `dirextalk-connect@<connector-id>.service` identities during migration. Each service is pinned to `system.slice` and has `NoNewPrivileges`, a read-only system view, private temporary storage, SUID/SGID restrictions, control-group kill semantics, allowlisted CPU/memory/PID/IO limits, journal output, a persistent per-instance log directory under `/var/lib`, and an explicit IMDS network deny. PID 1, unified cgroup v2 controllers, the exact unit argv/properties, process UID, executable digest, and cgroup membership are read back before success. The deny is enforced twice: systemd cgroup-BPF `IPAddressDeny` properties and a root-owned, exact-read-back nftables policy derived only from the Connector UUID and its allocated UID. The nftables policy uses fixed IPv4/IPv6 `drop` rules, is loaded as one atomic batch before process start, removed with the Connector runtime, and cannot accept an arbitrary table, rule, file, address, or action from control input. The Host Supervisor has a separate fixed cgroup-scoped nftables deny and exact read-back. Workers cannot read sibling state or the Supervisor management boundary.

The existing Go `dirextalk-connect` remains the runtime adapter and gains a single-instance Supervisor mode. This ADR does not require rewriting working Go runtime adapters in Rust. Connector outbound enrollment/control streaming is MC2b; routing and Run leases remain owned by Agent Control.

## Alternatives considered

- One Connect process with multiple projects was rejected because a crash, credential leak, runtime-global state, or upgrade crosses Agent boundaries.
- Containers alone were rejected as the contract because the first supported host also needs a systemd/cgroup implementation; either adapter must satisfy the same typed capability and isolation tests.
- Allowing arbitrary root commands, paths, service names, or manifests was rejected because it turns Agent input into a remote root shell.
- Letting each Connector self-manage restart/removal was rejected because an offline or compromised process cannot be the recovery authority.
- Advancing state before durable intent or trusting process exit status without read-back was rejected because crash recovery would duplicate or falsely complete side effects.

## Security and privacy consequences

Compromise of one Connector is bounded to its credential, authorized conversations, UID, files, cgroup, and lease. Short leases, boot fencing, credential revocation, and exact Host identity prevent an old process from silently returning. The Supervisor can see only fixed process metadata and opaque credential references; it cannot read chats, Agent workspace content, model tokens, cloud credentials, or arbitrary files.

The Supervisor is privileged enough to manage fixed Connector identities, so its adapter and VM tests are a security boundary. Shared hosts must not expose IMDS to the Supervisor or workers. The first Linux adapter therefore requires systemd, unified cgroup v2, and nftables; unsupported hosts fail closed instead of starting an unisolated worker. Diagnostic errors remain typed and must not include command output, paths, environment values, certificate material, or secret bytes.

## Migration

Legacy scalar/multi-project configuration is converted to a collection of stable Connector IDs. Each legacy project becomes one single-instance worker with independent storage and a generated service identity. Migration installs the immutable release first, writes the new per-instance state, verifies the new process and control identity, then drains the legacy authority. Rollback keeps the legacy data read-only until the new instance is verified; it never merges two instance stores.

## Reversal cost

Changing directory or unit templates requires a host migration that preserves Connector IDs, data ownership, and credential fences. Relaxing one-process isolation would invalidate the threat model and is not an in-place configuration change. Replacing systemd with a rootless container or another init adapter is comparatively cheap if it preserves the closed capability, durable journal, independent identity/storage/cgroup, and VM acceptance suite.

## Consequences

- More processes and service identities increase operational overhead.
- Instance failures, upgrades, credentials, limits, and leases become independently observable and recoverable.
- A fixed capability catalog slows arbitrary custom runtime installation, but prevents the control plane from becoming a generic root execution surface.
- Multi-Agent collaboration remains an explicit routing/Run decision instead of an accidental property of a shared worker process.
