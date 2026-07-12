# ADR-0003: v1 Wire Contracts

- Status: Accepted for S0.3
- Date: 2026-07-13
- Owners: `dtx-domain`, `dtx-wire`, and `protocol/`

## Context

Dirextalk vNext needs byte-stable identifiers, hashes, signatures, errors, and durable events that can be verified independently by Rust and Dart. These values cross storage, HTTP, control-stream, and client projection boundaries. A permissive decoder or an implementation-defined serializer would make approvals and signatures ambiguous.

## Decision

### Version and evolution

The first public wire line is protocol `1.0`. The pre-S0.3 Rust compatibility types were not a public serialization. Every durable message carries its writer version and minimum reader version. A reader rejects a different major, a minimum reader newer than itself, and an internally invalid version range.

Versioned signed or hashed types reject unknown fields. Extensible events do not weaken that rule: a future version of a locally known optional event family is retained as its original validated canonical bytes and may skip only a non-critical projection when its type suffix, schema version, aggregate, local policy, and wire capability all agree. A required family, a wire capability, or an entirely unknown family stops cursor advancement. A known typed payload is never decoded and re-encoded while silently dropping fields.

### Identifiers

Internal lifecycle identifiers use UUIDv7. Their text form is the RFC 9562 lowercase hyphenated form only; alternate UUID spellings and non-v7 values are rejected.

Public identities use an Ed25519 compressed verification key and the existing domain-separated formulas:

```text
identity_id = "dtxi1" + base32lower(SHA-256("dirextalk.identity.v1\0" || key))
channel_id  = "dtxc1" + base32lower(SHA-256("dirextalk.channel.v1\0" || key))
agent_id    = "dtxa1" + base32lower(SHA-256("dirextalk.agent.v1\0" || key))
```

Base32 is RFC 4648 lowercase without padding. The 32-byte digest encodes to exactly 52 characters, so every public ID is exactly 57 ASCII characters. Parsing rejects uppercase, mixed case, padding, invalid alphabet characters, non-zero trailing bits, and the wrong prefix or length. Binding an ID to a subject additionally validates that the Ed25519 key decompresses, round-trips to the same compressed bytes, is not weak, and derives the supplied ID.

### Canonical primitives

- `UtcMillis` is a signed UTC Unix epoch-millisecond integer in the inclusive Gregorian range `0001-01-01T00:00:00Z` through `9999-12-31T23:59:59.999Z`.
- `Sha256Digest` is `sha256:<64 lowercase hex>` in JSON and exactly 32 bytes in CBOR/Protobuf.
- `Ed25519PublicKey` is `ed25519:<base64url without padding>` in JSON and exactly 32 bytes in CBOR/Protobuf.
- `Ed25519Signature` is `ed25519:<base64url without padding>` in JSON and exactly 64 bytes in CBOR/Protobuf.
- Protocol versions are strict `<major>.<minor>` decimal strings in JSON and a two-field integer map in CBOR.
- Unsigned counters, revisions, sequences, and money minor units exposed to JSON use `SafeUint`, the inclusive range `0..9007199254740991`. Public signed error-detail integers use the corresponding inclusive range `-9007199254740991..9007199254740991`. This keeps Rust, Dart VM, Flutter Web, JSON, CBOR, and Protobuf consumers exact without transport-specific rounding.
- Unicode strings are valid UTF-8 and are not normalized. NFC and NFD inputs therefore remain distinct.

### Deterministic CBOR profile

Signed and hashed Dirextalk values use the RFC 8949 section 4.2.1 core deterministic encoding requirements:

- preferred shortest serialization for integers and lengths;
- definite-length strings, arrays, and maps only;
- map keys sorted by the bytewise lexicographic order of their deterministic encodings;
- duplicate map keys, tags, floating-point values, undefined, unsupported simple values, trailing bytes, invalid UTF-8, and integers outside the declared field type are rejected;
- typed maps use positive integer keys fixed by their v1 CDDL schema;
- encoding and validation are bounded symmetrically to 1 MiB, nesting depth 32,
  4096 entries per container, and 65,536 total data items (including map keys).
- map-key sorting charges both nested items and pending encoded key bytes before
  retaining them; the 1 MiB budget includes sorting workspace derived from keys.

The protocol implements and tests this restricted profile directly. A generic CBOR library is not trusted to canonicalize security-sensitive input implicitly.

### Hashes and signatures

Domain separators include their trailing NUL byte.

```text
plan_hash = SHA-256(
  "dirextalk.job-plan.v1\0" || deterministic_cbor(JobPlanBodyV1)
)

event_digest = SHA-256(
  "dirextalk.event.v1\0" || deterministic_cbor(UnsignedEventEnvelopeV1)
)

event_signature_input =
  "dirextalk.event-signature.v1\0" || event_digest_bytes
```

S0.3 freezes the plan-hash function and a representative cross-language fixture. The complete production `JobPlanBodyV1` resource and step schema remains owned by JOB2; S0.3 does not publish an incomplete substitute. `plan_hash` is never encoded inside the body it hashes.

Ed25519 verification uses strict verification. Private keys are outside `dtx-wire`; callers provide a public key and signature. Decoding an envelope does not imply integrity. Verification returns a distinct verified wrapper, and semantic getters for event metadata and typed payload exist only on that wrapper so an unverified deserialized envelope cannot be projected accidentally.

### Durable event envelope

`UnsignedEventEnvelopeV1<T>` contains, in order of numeric CBOR key:

1. protocol version;
2. minimum reader version;
3. event ID;
4. tenant ID;
5. aggregate type;
6. aggregate ID;
7. aggregate revision;
8. stream sequence;
9. occurrence time;
10. payload schema version;
11. registered event type;
12. required reader capability or null;
13. typed payload.

`EventEnvelopeV1<T>` adds key 14, `EventIntegrityV1`. Integrity is either hash-only (`sha256` plus the event digest) or signed (`ed25519`, event digest, signer public key, and signature). Hash-only detects corruption but does not authenticate an origin. Signed verification proves possession of the included key; authorization of that key remains an outer trust-policy decision.

Known type/schema pairs pass through the generated typed canonical dispatcher,
which verifies envelope integrity and then requires an exact typed payload map
whose re-encoding is byte-equivalent. Extensible cursor sync uses the CBOR event
page, where every item is the exact canonical envelope byte string; its JSON
projection is only for event schemas enumerated by the current OpenAPI union.
The complete encoded CBOR page, including outer framing, is capped at 1 MiB.
Writers paginate on accumulated encoded bytes before the structural 1000-event
limit, so a standalone 1 MiB envelope cannot be embedded in a single page.

### Errors and safe details

`protocol/errors/registry.yaml` is the only source of server-constructible error codes, their default public message, HTTP status, and default retryability. Decoders preserve a syntactically valid unknown future code for forward-compatible display, but server constructors accept only registered codes.

Error details are bounded public scalars or non-empty short scalar arrays. Empty arrays are rejected because JSON cannot distinguish their intended text or integer item type. Nested objects, binary values, arbitrary provider responses, and unbounded strings are not representable. This structural boundary supplements, but cannot replace, review of public messages for secret or infrastructure leakage.

### Source artifacts and breaking checks

`protocol/events/registry.yaml` generates committed Rust and Dart payload types. CDDL, OpenAPI 3.1, Protobuf, registries, and golden vectors are validated in CI. The complete v1.0 registry and artifact set is frozen by a committed baseline. That baseline is closed: additions, deletions, and mutations all fail the breaking checker and cannot be repaired by re-freezing. A reviewed optional event or error addition is published through a new protocol-minor registry/schema/baseline (for example v1.1), leaving v1.0 byte-for-byte available to older readers.

## Alternatives considered

- JSON canonicalization was rejected for signed state because number handling,
  Unicode escaping, object ordering, and Web integer precision create a larger
  cross-runtime ambiguity surface.
- A general-purpose CBOR value/serializer was rejected as the trust boundary.
  Libraries may still parse schema fixtures, but security-sensitive encoding and
  admission use this bounded profile and its independent vectors.
- Protobuf was not selected as the durable signed representation. It remains a
  control-stream wrapper because unknown-field retention and implementation
  re-encoding are not an adequate byte-identity contract for signatures.
- Permissively skipping every unknown event was rejected because a new event can
  carry state required for authorization, resource lifecycle, or user-visible
  correctness.

## Security and privacy consequences

Canonical admission is a security boundary: size, depth, total-item, container,
integer, text, map-order, duplicate-key, version, registry metadata, digest, and
signature checks happen before projection or cursor advancement. Unknown event
metadata is derived from authenticated envelope bytes and generated local event-
family policy; callers cannot declare an event optional. Only a future version
of a known optional family can preserve-and-skip, and an entirely unknown event
family stops the cursor conservatively.

Error bodies permit only reviewed public messages and bounded scalar details.
They cannot carry nested provider responses, binary secrets, raw credentials,
or arbitrary debug context. Public IDs reveal a stable subject identifier but
not a private key; correlation and directory publication remain explicit policy
decisions outside this ADR.

## Migration

The pre-S0.3 Rust types were never a public serialization, so v1 begins without
an on-wire compatibility migration. Legacy Matrix/Go data crosses into vNext
through a migration adapter that emits validated v1 commands/events; it is not
reinterpreted as canonical bytes. Readers retain exact bytes only for an
admissible future version of a known optional family, while a required or
entirely unknown family stops before cursor advancement and requires a reader
upgrade or a signed snapshot path.

Every reviewed additive entry or artifact creates a new versioned contract
set; it is never appended into an already published manifest. Published bytes
and hashes are immutable. The new set declares its minimum reader and keeps the
older set available during rollout. A non-additive change uses a new protocol
major and an explicit reader/writer migration policy.

## Reversal cost

Changing canonical encoding, ID derivation, hash domains, signature preimages,
or an existing event field after publication invalidates stored signatures,
approval receipts, cursors, and cross-language fixtures. Reversal therefore
requires a new protocol major, dual readers during migration, re-signed
snapshots, and an auditable cutover; it is intentionally expensive. Replacing a
schema parser, code generator, or transport wrapper is comparatively cheap as
long as it reproduces the frozen bytes and passes the same conformance suite.

## Consequences

- Encoders have less freedom, but hashes and signatures are reproducible across languages.
- Unknown optional event forwarding requires retaining original canonical bytes.
- New required fields require a new schema version instead of permissive in-place evolution.
- The server remains all Rust at runtime; Dart exists only as an independent conformance consumer.
