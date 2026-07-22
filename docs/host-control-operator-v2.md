# Host Control Operator v2

Host Control Operator v2 is the production-dispatched, closed install
lifecycle for one Connector instance. It is selected only by the `DTXHC02\0`
magic. The existing `DTXHC01\0` v1 frame, commands, payload rules, response,
and journal records remain accepted unchanged.

## Frame and header

The one-shot operator reads stdin once into bounded zeroizing storage and then
dispatches by magic. A v2 frame contains the magic, a big-endian `u32` JSON
header length, at most 16 KiB of strict JSON, a big-endian `u32` material
length, and exactly that many material bytes, at most 384 KiB. Truncated,
trailing, duplicate-key, unknown-field, noncanonical, and oversized input is
rejected before a host, journal, process, or filesystem effect.

The protocol string is `dirextalk.host-control.operator.v2`. Tenant, host,
Connector, Host operation, and Connector lifecycle operation identifiers are
canonical UUIDv7 values. Host and Connector operation IDs are distinct:
the Host ID fences the local journal and mutations, while the lifecycle ID
binds the Connector plan, handoff, and receipts.

Revisions are exact, positive, JSON-safe integers. The optional observed
revision cannot exceed desired. Expiry is positive and JSON-safe. Platform is
closed to `linux-amd64` and `linux-arm64` and must match the executing binary.
Every digest is exactly lowercase hexadecimal SHA-256.

Only two v2 operations exist:

- `prepare_connector_material`
- `finalize_connector_material`

Both carry the approved release, original prepare-material, plan, handoff,
config, and three trust-component digests. Prepare forbids a receipt digest.
Finalize requires the exact prepared-receipt digest. Finalize carries no
config or trust bytes; their digests bind the fixed files staged by prepare.
Neither operation accepts a path, argv, environment, service name, shell,
caller readiness assertion, finalized receipt, credential, bearer, or URL as
an operator-controlled execution parameter.

## Bootstrap material

Material uses the `DTXBMT01` envelope with six big-endian `u32` lengths and
six fields in this order:

1. config TOML, at most 64 KiB;
2. enrollment root CA PEM, at most 64 KiB;
3. control server root CA PEM, at most 64 KiB;
4. Connector issuer root CA PEM, at most 64 KiB;
5. redacted Connector plan JSON, at most 65,536 bytes;
6. secret handoff JSON, at most 64 KiB.

Prepare requires all six fields. Finalize requires only the exact plan and
handoff; the first four lengths are zero. The aggregate envelope is bounded to
384 KiB. Each field is digest-bound before an intent or subprocess. Plan and
handoff JSON are strict, duplicate-free, and bound field-by-field to the
Connector v1 plan/handoff contract. Secret values stay in zeroizing storage
and are never printable or journaled.

An empty material payload is accepted only as a completed-operation replay
seam. New or pending operations return `MATERIAL_REQUIRED` before an intent,
provider call, or process effect.

## Durable lifecycle

Prepare validates the host boundary and release catalog, then persists the
resolved Host intent before any ensure, staging, Connector invocation, or
artifact adoption. The Linux adapter derives every path internally. It stages
fixed config, trust, and plan files; opens the catalog-selected immutable
release with no-follow metadata checks; hashes that same descriptor; and
executes it through `/proc/self/fd` with fixed bootstrap argv, an empty
environment, bounded stdin/stdout, and a 45-second kill-and-reap deadline.

The Connector is the sole durable credential and bearer generator. The Host
binds the exact prepared receipt, validates the two fixed root-owned `0600`
durable files, requires the bearer to be canonical 43-byte base64url, and
atomically adopts both into the Host runtime. The completed prepare record
stores only non-secret facts and opaque digests and leaves the process stopped.

Start and restart remain ordinary v1 Host mutations. For an installed
Connector they first prove the stored tenant, host, Connector, adapter,
release, credential, and bearer facts, then restore the fixed runtime files if
needed. Ordinary v1 credential rotation and release drift are rejected while
an install lifecycle exists; durable reissue is a separate future contract.

Finalize is accepted only for the exact prepared facts and receipt after the
core independently observes the fixed process as Running. It re-verifies and
executes the immutable Connector release, binds the finalized receipt, and
persists the finalized non-secret proof before returning success.

## Replay, expiry, and output

Exact completed operations replay their stored result without material or a
provider. An exact pending operation may reconcile only through its original
facts and material. A different envelope under the same Host operation ID,
another pending Host operation, stale fence, mismatched receipt, release,
identity, or metadata fails closed.

For an expired pending prepare, the adapter first observes the exact fixed
systemd unit and performs a read-only scan of every fixed filesystem footprint.
`ExpiredUnclaimed` is returned only when the unit and all paths are absent and
the missing paths have safe existing ancestors; this neither requires nor
creates the service user. A present unit or securely typed and permissioned
footprint proceeds to exact Connector-claim recovery. Any symlink, special
file, unsafe ancestor, owner/group/mode/link mismatch, partial ambiguous state,
or lookup failure is rejected. Expiry never authorizes a new claim or inferred
reinstall.

The v2 response is a separate sanitized projection: protocol, success/reject
status, operation, application (`applied` or `replayed`), disposition,
revisions, Connector ID, lifecycle state, and prepared/finalized receipt
digests. Rejections use a fixed allowlisted code. Material, credentials,
bearers, paths, commands, URLs, raw receipts, subprocess output, and diagnostic
text never cross the response boundary.

## Root-only issuance boundary

The server-side issuer is the one-shot root-only command:

```text
dtx-agent-provision bootstrap-issue \
  --database-url-file <0600-file> \
  --request-file <root-owned-0600-json> \
  --handoff-file <root-owned-0600-json> \
  [--plan-file <redacted-json>]
```

`dirextalk.connector-bootstrap-issuance-request` v1 is strict and contains
all non-secret plan facts. The operator generates independent enrollment and
MCP bearer secrets, stages them in a fixed operation-scoped `0600` handoff,
then commits the Host, Connector, enrollment intent, and issuance fence in one
tenant transaction. The durable row stores only redacted JSON and digests. A
post-commit atomic rewrite publishes the `ready` handoff and canonical
`dirextalk.connector-bootstrap-plan` v1 accepted by this Host V2 boundary.
The plan's `host.owner_id` is the stable `IdentityId` text form (`dtxi1` plus
52 lowercase RFC 4648 Base32 characters); tenant, host, credential, Connector,
and operation identifiers remain UUIDv7 values.
Missing or changed handoff material after a durable row exists returns
`HANDOFF_UNAVAILABLE`/conflict and never remints secrets.
