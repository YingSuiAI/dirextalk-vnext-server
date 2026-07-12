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
  and control-stream transports.
- `test-vectors/v1` contains byte-exact public ID, plan hash, API error, and
  event-envelope fixtures.
- `generated/dart` is an independent Dart conformance consumer. Its registry-
  generated `.g.dart` files and `crates/dtx-wire/src/generated` must not be
  edited manually.
- `baseline/v1/manifest.json` freezes reviewed registry entries and versioned
  artifacts by SHA-256.

Run `dtx-protocol check-generated`, `validate`, and `check-breaking` through the
commands in `../COMMANDS.md`. Ordinary generation never updates the frozen
baseline. Adding a reviewed event/error or versioned artifact requires the
next versioned registry/schema and its own baseline; the published v1.0 manifest
is an exact closed set. Adding, changing, or deleting an entry in that set is a
breaking change rather than an operation that re-freezing can repair.

The v1 deterministic profile is defined by ADR-0003. In particular, exact
canonical bytes—not a generic serializer's defaults—are hashed, signed, stored,
and forwarded. Private keys and decrypted message content never belong in this
tree or its fixtures.
