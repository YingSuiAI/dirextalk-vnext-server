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
