# Protocol Artifacts

This directory owns the versioned Dirextalk vNext wire contract. The Rust
implementation lives in `dtx-domain` and `dtx-wire`; this tree contains the
language-neutral schemas, registries, generated consumers, and independent
vectors that prevent those implementations from becoming an implicit source of
truth.

Layout:

- `events/registry.yaml` is the event name, payload-field, capability, retention,
  redaction, and unknown-version registry.
- `errors/registry.yaml` is the stable public error registry.
- `cddl/v1`, `openapi/v1`, and `proto` describe deterministic CBOR, HTTPS JSON,
  and control-stream transports. The reviewed `dirextalk.agent_control.v1`
  enrollment and control services are generated into
  `dtx-agent-control-proto` with a vendored `protoc`; separate services keep
  ordinary TLS enrollment off the mandatory-mTLS control listener.
  Durable commands retain their exact nested Protobuf bytes inside a bounded
  raw frame so reconnect replay does not depend on decode/re-encode behavior.
  The disjoint full `agent_control/v1_1` source artifact retains the existing
  `dirextalk.agent_control.v1` package and single stream while adding only the
  MC3 offer/lease handshake: `RunClaim` acknowledges `RunAvailable`, and only
  `RunLeaseGranted` authorizes execution. `RunRelease` echoes both fences;
  checkpoint, output, completion, and failure frames remain deferred to AR3.
  The independent `dirextalk.agent_gateway.v1` package exposes only the
  internal-mTLS `AgentRunIngress/CreateAgentRun` method. Its request carries
  opaque vNext UUIDs and digests, never a tenant selector, prompt, or raw
  Matrix room/event identifier; result and completion remain separate work.
- `test-vectors/v1` contains byte-exact public ID, plan hash, API error, and
  event-envelope fixtures.
- `generated/dart` is an independent Dart conformance consumer. Its registry-
  generated `.g.dart` files and `crates/dtx-wire/src/generated` must not be
  edited manually.
- `baseline/v1/manifest.json` freezes the published registry and original v1
  artifacts by SHA-256. `baseline/v2/manifest.json` is a disjoint artifact set
  that freezes Agent Control 1.0 without changing any v1 entry.
  `baseline/v3/manifest.json` independently freezes the additive Agent Control
  1.1 source without changing the v1 or v2 artifact sets.
  `baseline/v4/manifest.json` independently freezes the Legacy Matrix Gateway
  run-ingress source without changing any older artifact set.
  `baseline/v5/manifest.json` freezes the original identity-log wire 1.0
  source for read-only historical validation/import only.
  `baseline/v6/manifest.json` freezes the disjoint current identity-log wire
  1.1 source, including the recovery-rotation co-sign requirement; neither
  baseline rewrites the other. `baseline/v7/manifest.json` freezes the original
  public descriptor 1.0 wire for explicit historical reads only. Its endpoint
  field allowed an arbitrary path and it must never enter the current writer,
  reducer, registration, or Indexer path. `baseline/v8/manifest.json`
  independently freezes the superseded public descriptor 1.1 wire for explicit
  historical reads only. `baseline/v9/manifest.json` freezes the current public
  descriptor 1.2 wire: self-certifying `dtxc1`/`dtxa1` subject IDs, publisher
  identity binding, canonical signed sequence heads, canonical lower-case DNS
  HTTPS `feed_origin` values, artifact digests, expiry, and permanent
  tombstones. V1.2 excludes IP literals and URL-parser-ambiguous numeric host
  forms, and its Channel and Agent tombstones both use the empty payload map.
  Clients and PD2 derive the fixed public document path
  `/.well-known/dirextalk/public/v1/{subject_id}` from that origin; a
  capability, token, userinfo, query, fragment, or custom path is not
  representable in a current descriptor. V1.0 and V1.1 never enter a current
  writer, decoder, reducer, registration, or Indexer path. No version
  introduces an Indexer, public feed transport, delegation, or a control-plane
  UUID alias for a public subject.
  `baseline/v19/manifest.json` assigns the previously published Agent Control
  1.2 execution-report and cancellation source to its disjoint frozen set.
  `baseline/v20/manifest.json` freezes the private application event carried
  only inside MLS ciphertext. Its vector stores body bytes as hex solely for
  byte-exact cross-implementation conformance; no server storage, reducer, or
  logging path may decode or retain that field. Consumers must reject an event
  larger than the exact V1 maximum of 66,383 canonical CBOR bytes. The same
  vector freezes the 32-byte MLS group identifier as
  `SHA-256("dirextalk.mls-group-id.conversation.v1\0" || conversation UUID raw16)`.
  It also freezes the Agent Control MLS-authenticated private event digest as
  `SHA-256("dirextalk.private-event-mls-ciphertext.v1\0" || event UUID raw16 || u64-be(ciphertext length) || exact MLS wire ciphertext)`.
  Implementations must never hash the plaintext body or canonical private event
  for that field; only the non-empty, mailbox-bounded MLS ciphertext is safe.
  `baseline/v21/manifest.json` freezes the single-node MLS Commit Sequencer:
  opaque commit CAS, signed response-loss-safe receipts, one-time Owner
  bootstrap, GM1-approved identity admission, same-identity active-controller
  consent for additional devices, and candidate confirmation before routing.
  `baseline/v22/manifest.json` is the production HTTP revision. It replaces
  the under-specified V1 device proof with a server-recomputed canonical
  transcript and distinct candidate/controller signature domains, fixes
  `group-scope` to the CDDL integer enum, and publishes the stable receipt
  verification-key descriptor. V21 remains immutable and has no production
  route.

Run `dtx-protocol check-generated`, `validate`, and `check-breaking` through the
commands in `../COMMANDS.md`. Ordinary generation never updates the frozen
baseline. Adding a reviewed event/error or versioned artifact requires an
explicitly assigned next versioned registry/schema set and its own baseline;
the published v1.0 manifest is an exact closed set and is never regenerated.
Every CDDL, OpenAPI, Protobuf, and test-vector artifact must belong to exactly
one frozen set. Adding, changing, or deleting an entry in an existing set is a
breaking change rather than an operation that re-freezing can repair.

The v1 deterministic profile is defined by ADR-0003. In particular, exact
canonical bytes—not a generic serializer's defaults—are hashed, signed, stored,
and forwarded. Private keys and decrypted message content never belong in this
tree or its fixtures.
