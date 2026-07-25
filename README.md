# Dirextalk vNext Server

The identity node's Completion V2 authority is opt-in and fail-closed. When
enabled, provision all of `DTX_IDENTITY_COMPLETION_KEY_FILE` (an absolute
owner-only 32-byte seed path), `DTX_IDENTITY_COMPLETION_KEY_ID` (UUIDv7),
`DTX_IDENTITY_COMPLETION_EPOCH`, `DTX_IDENTITY_COMPLETION_ROLLBACK_FLOOR`,
`DTX_IDENTITY_COMPLETION_ISSUED_AT_MS`, and
`DTX_IDENTITY_COMPLETION_EXPIRES_AT_MS`. Rotation additionally requires
`DTX_IDENTITY_COMPLETION_PREVIOUS_DIGEST` (lower-case hex); no ephemeral key
or default signer is generated.

Rust workspace for the Matrix-independent Dirextalk Product Core Alpha server.

The current server contract is [`docs/product-core-alpha.md`](docs/product-core-alpha.md).
The workspace is intentionally built in verified vertical slices; the presence
of a crate, binary, or protocol artifact does not imply complete product
acceptance.

## Product Core Alpha

Product Core Alpha is the current release boundary for the `dirextalk-vnext-server`
and `dirextalk-vnext-client` IM product. The server currently provides the
durable protocol and service foundations used by that product, including:

- self-authenticated identity, device enrollment/session, and recovery
  protocol surfaces;
- private conversation/group membership and MLS sequencing boundaries;
- opaque mailbox delivery, pull/ack, account read state, and realtime sync
  recovery boundaries;
- PostgreSQL-backed persistence, migrations, authorization, fencing, and
  idempotent replay contracts;
- the unified `dtx-node` composition and the protocol schemas, vectors, and
  generated consumers that guard these contracts.

This is a fresh-only product boundary: use a fresh schema and fresh client
state. There is no compatibility path for the obsolete workspace monolith or
legacy Matrix state. Agent/Connector execution and public-content expansion are
frozen outside this release; `dirextalk-vnext-deployer` and
`dirextalk-agent-connector` are deferred to Platform Integration Alpha.

Product Core Alpha is not a claim of complete end-to-end acceptance. X3, X4,
and X5 are resettable acceptance environments, and the remaining live workflow
checks are tracked separately from the server's unit, contract, and persistence
evidence. Runtime recovery, durable intent ordering, leases/fencing, and
idempotency remain required behavior in every slice.

See [`COMMANDS.md`](COMMANDS.md) for local verification.
