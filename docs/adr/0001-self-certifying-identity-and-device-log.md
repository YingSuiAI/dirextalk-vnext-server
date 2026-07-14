# ADR-0001: Self-certifying identity and device log

- Status: Accepted for IM1a
- Date: 2026-07-14
- Owners: `dtx-domain`, `dtx-identity-log`, and `protocol/cddl/identity-log/{v1,v1_1}`

## Context

Dirextalk identities must survive relay replacement and must not depend on a
homeserver account, a tenant UUID, or a mutable directory record. Devices need
independent signing and encryption keys, an auditable revoke path, and an
offline recovery path. These facts will later cross QR enrollment, HTTP,
PostgreSQL, client synchronization, MLS, mailbox, and public directory
boundaries; accepting implementation-defined bytes here would make key control
ambiguous.

This ADR covers the IM1a canonical identity-log core only. It does not add the
HTTP endpoints, PostgreSQL persistence, handle registration/search, recovery
UI, QR transport, MLS state, mailbox storage, or relay network fetches.

## Decision

### Permanent identity and exact wire

`identity_id` is the existing self-certifying value from ADR-0003:

```text
dtxi1 + base32lower(
  SHA-256("dirextalk.identity.v1\0" || genesis_root_ed25519_public_key)
)
```

The genesis root key is immutable for this derivation. Root rotation changes
authority, not the public identity ID. The identity log has separate,
non-tenant CDDL artifacts and baselines; it must not reuse `EventEnvelopeV1`,
tenant IDs, server sequence values, or the frozen S0.3 v1 artifact set.

The original exact `identity-log/v1` wire `1.0` is frozen under baseline v5
and remains replayable only. The current writer is the disjoint
`identity-log/v1_1` wire `1.1`, frozen under baseline v6. A log establishes one
exact wire line at genesis and rejects mixed-line append or embedded
certificate/descriptor data. New identities write `1.1`; readers retain `1.0`
only through a read-only historical import projection. The current
`IdentityLogV1` bootstrap and append entry points reject `1.0`, so callers
cannot obtain an append-capable legacy log. Both lines use RFC 8949
deterministic CBOR, with positive integer map keys, closed typed shapes, no
unknown fields, and no permissive future-version path. The signed event fields
are:

1. wire version;
2. identity ID;
3. positive contiguous sequence;
4. prior complete-event hash, or null only at genesis;
5. occurrence timestamp;
6. transition kind;
7. transition payload;
8. signer public key;
9. Ed25519 signature.

The v1 domains, including the trailing NUL, are frozen:

```text
unsigned event digest = SHA-256(
  "dirextalk.identity-log-event.v1\0" || deterministic_cbor(fields 1..8)
)
event signing input =
  "dirextalk.identity-log-signature.v1\0" || unsigned_event_digest
entry hash = SHA-256(
  "dirextalk.identity-log-entry.v1\0" || deterministic_cbor(fields 1..9)
)

certificate digest = SHA-256(
  "dirextalk.device-certificate.v1\0" || deterministic_cbor(certificate fields 1..7)
)
certificate signing input =
  "dirextalk.device-certificate-signature.v1\0" || certificate_digest
```

Genesis recovery and successor-key acceptance each use distinct, documented
domain-separated canonical proof inputs. Successor acceptance includes the
identity, exact sequence, predecessor hash, successor key, and one of root
rotate, recovery rotate, recovery-restore-root, or recovery-restore-recovery;
it cannot be replayed across transition meanings. Verification is strict
Ed25519. A signer is not authorized merely because its signature is valid.

The exact canonical acceptance bodies are frozen as follows. Genesis recovery
uses `{1: identity_id, 2: root_key, 3: recovery_key}`, hashes it with
`dirextalk.identity-log-genesis-recovery-acceptance.v1\0`, and signs
`dirextalk.identity-log-genesis-recovery-acceptance-signature.v1\0 || digest`.
Successor acceptance uses `{1: identity_id, 2: sequence, 3: predecessor_or_null,
4: purpose, 5: successor_key}`, hashes it with
`dirextalk.identity-log-key-acceptance.v1\0`, and signs
`dirextalk.identity-log-key-acceptance-signature.v1\0 || digest`. Purpose is
`1 = root_rotate`, `2 = recovery_rotate`, `3 = recovery_restore_root`, and
`4 = recovery_restore_recovery`.

Wire `1.1` strengthens `RecoveryRotate`: the current root signs the event, the
current recovery key co-signs the exact transition, and the successor recovery
key supplies its separate possession proof. The recovery co-sign body is
`{1: wire_version, 2: identity_id, 3: sequence, 4: predecessor_or_null,
5: occurred_at, 6: root_signer, 7: successor_recovery_key,
8: successor_acceptance_signature}`. It is hashed with
`dirextalk.identity-log-recovery-rotation-authorization.v1\0` and signed as
`dirextalk.identity-log-recovery-rotation-authorization-signature.v1\0 ||
digest`. This binds both current authorities and all successor evidence;
neither a root-only event nor a signature made by a breached former recovery
key can rotate the recovery authority.

### Authority matrix

The projection admits only the next sequence with the exact current entry hash
as predecessor. It retains every accepted entry hash, so replay, forks,
reordering, and stale-head retries fail before any state mutation. Unknown
kinds, fields, versions, malformed canonical CBOR, invalid signatures, and
ambiguous role transitions fail closed.

| Transition | Event signer | Additional proof / effect |
| --- | --- | --- |
| Genesis | genesis root | Identity ID derives from root; independent recovery key signs a possession proof. |
| Device add | current root or current active device | Certificate is signed by the current root, names this identity, and binds a fresh device ID plus distinct signing/encryption keys. |
| Device revoke | current root | Existing active device becomes permanently revoked. |
| Root rotate | current root | New root signs a transition-, sequence-, and parent-bound possession proof. |
| Recovery rotate | current root | Current recovery co-signs the exact transition, and the successor recovery key signs a transition-, sequence-, and parent-bound possession proof. |
| Recovery restore | current recovery | Both new root and new recovery keys sign transition-, sequence-, and parent-bound proofs; all prior devices are revoked. |
| Relay descriptor update | current root | Bounded, ordered, unique literal HTTPS relay descriptor has not expired at the event time. |

Root and recovery keys must always be distinct. Device signing keys cannot be a
current authority key or reused by another device; device encryption public
keys cannot be all-zero or reused. A root rotation invalidates the ability to
issue new certificates under the old root, while existing active devices remain
usable only to co-authorize a certificate issued by the current root. Recovery
restore rotates both authority keys and fences every old device, so recovering a
lost identity never silently revives a compromised device.

Device encryption keys are opaque X25519-compatible 32-byte public encodings
at this boundary. IM2/IM3 choose their concrete use; private encryption keys,
MLS secrets, message bodies, and backup material never enter this log.

### Relay descriptors and visibility

The log stores literal ASCII `https://` endpoints only: one to eight entries,
strictly bytewise increasing, unique, bounded to 512 bytes, with no userinfo,
query, fragment, control character, or backslash. The protocol deliberately
does not invent cross-runtime URL normalization; the signed literal strings are
the authority. Publishing or indexing a descriptor is a later opt-in policy;
there is no implicit global directory or human-readable handle in IM1a.

The projection retains the latest signed descriptor for replay and audit even
after it expires. A caller that needs a usable route must query the active
descriptor with a trusted `now`; it is active only when `expires_at > now`.
The event timestamp merely rejects a descriptor that was already expired when
the signer created that event. It is signer-provided historical metadata and
must never stand in for the trusted current clock.

## Alternatives considered

- A centrally mutable account record was rejected because relay migration and
  account recovery would remain dependent on one server operator.
- Reusing the tenant `EventEnvelopeV1` was rejected because a self-certifying
  identity has no tenant owner and needs an independently replayable chain.
- Server-generated device bearer tokens were rejected because they do not
  provide an auditable device certificate or an independent recovery boundary.
- A blockchain/DID ledger was rejected for v1 because external consensus,
  transaction fees, metadata disclosure, and chain availability are not needed
  to verify a signed append-only identity history.

## Security and privacy consequences

The relay can retain, relay, and serve exact public log bytes but cannot forge
a root, recovery, or device proof. The expected-head check is mandatory in the
future storage transaction; a unique `(identity_id, sequence)`, unique entry
hash, and compare-and-swap on `(head_sequence, head_hash)` are required to
prevent concurrent forks. Exact bytes, not a re-serialized object, are the
durable audit record.

An identity ID, public keys, certificate timestamps, revocation history, and
any published relay descriptor are correlatable public metadata. The system
therefore exposes no automatic handle lookup, contact graph, mailbox content,
private key, recovery seed, provider credential, or decrypted MLS state from
this contract. Error variants are intentionally non-secret and do not reveal
whether another identity or hidden device exists beyond an already authorized
log projection.

## Migration

The legacy Matrix identity is not reinterpreted as a v1 identity log. A
migration creates a new verified genesis and imports user-approved devices by
issuing fresh root certificates. A contact migration can carry both old and
new verification material until explicit confirmation; it must not silently
map `@user:server` to a new `identity_id`.

The later `/v1/identity/*` and `/v1/devices/*` APIs persist the exact canonical
event and update the authorization head in one transaction. They must expose
expected-head conflicts as an idempotent retry boundary, not choose a winning
fork in application memory. QR enrollment supplies transport and user consent
around the same root certificate and active-device event authorization; it does
not define a second device trust model.

The published v1.0 CDDL/vector and baseline v5 are never rewritten. The
recovery co-sign requirement is published only as the current v1.1 CDDL/vector
and baseline v6. A migration reader can validate and import a complete v1.0
line only into a read-only historical projection; it cannot append either v1.0
or v1.1 events. Only a v1.1 genesis can create the current writable
projection, and a historical v1.0 recovery rotation must never be reinterpreted
as if it had a co-signature.

## Reversal cost

Changing identity derivation, event fields, map keys, canonical CBOR profile,
signature preimages, certificate structure, or role matrix invalidates stored
proofs and contact verification. Reversal requires a new protocol major,
dual-reader migration, a new signed identity mapping or contact confirmation,
and an auditable cutover. Changing HTTP routing, PostgreSQL implementation,
or relay availability policy is cheaper as long as it preserves the frozen v1
bytes and authorization semantics.
