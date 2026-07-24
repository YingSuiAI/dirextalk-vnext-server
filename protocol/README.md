# Protocol Artifacts

This directory is the language-neutral source of truth for the current
Product Core Alpha wire contract. Rust and Dart consumers are generated from
the two registries; CDDL, OpenAPI, Protobuf, and byte-exact vectors remain
reviewed source artifacts.

The Alpha release inventory is [alpha/manifest.json](alpha/manifest.json).
It hashes the current registries and Product Core artifact set. `check-alpha`
accepts only that exact inventory; it does not compare against prior releases
and there is no cross-version compatibility gate.

Agent execution, Connector, and Public Channel/Feed artifacts are retained for
their independent frozen-source consumers, but are explicitly excluded from
the Product Core Alpha release gate. Historical artifacts are removed only
when no runtime, test, or generated consumer depends on them.

Use the repository commands from `../COMMANDS.md`:

```text
cargo run -p dtx-protocol --locked -- generate .
cargo run -p dtx-protocol --locked -- check-generated .
cargo run -p dtx-protocol --locked -- validate .
cargo run -p dtx-protocol --locked -- check-alpha .
```

Private keys and decrypted message content never belong in this tree or its
fixtures. Exact canonical bytes, not serializer defaults, are the wire and
hashing contract.
