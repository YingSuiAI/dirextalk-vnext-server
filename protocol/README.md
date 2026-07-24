# Protocol Artifacts

This directory is the language-neutral source of truth for the current
Product Core Alpha wire contract. Rust and Dart consumers are generated from
the two registries; CDDL, OpenAPI, Protobuf, and byte-exact vectors remain
reviewed source artifacts.

The Alpha release inventory is [alpha/manifest.json](alpha/manifest.json).
It hashes the current registries and Product Core artifact set. `check-alpha`
accepts only that exact inventory; it does not compare against prior releases
and there is no cross-version compatibility gate.

Agent execution, Connector, and Public Channel/Feed artifacts are frozen source
for the next version and are explicitly excluded from the Product Core Alpha
release gate. There is no historical baseline directory or compatibility
validator.

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
