# Product Core Alpha Security Boundary

This is the active security contract for Product Core Alpha. Historical ADRs
and version-specific operator notes are not security authorities.

## Trust boundary

Client devices own:

- identity root and device private keys;
- HPKE opening keys and MLS group state;
- plaintext private events and local conversation history;
- attachment content keys and private read capabilities;
- the encrypted `client.redb` database key, wrapped by the platform Keystore.

Product Core servers own:

- identity/device public facts and signed log ordering;
- group membership authorization and MLS commit sequencing;
- opaque Mailbox ciphertext, blinded capability digests, receipts, and cursors;
- opaque attachment chunks and their integrity metadata;
- durable realtime invalidations and opaque Push registrations.

The server may validate signatures, canonical encodings, digests,
authorization, ordering, idempotency, leases, and fences. It must not decrypt
or log private-event bodies, attachment plaintext, MLS secrets, private keys,
raw capabilities, or client database keys.

## Metadata that remains visible

Product Core does not claim SimpleX-style relationship anonymity. Depending on
the service role, an operator may observe stable identity/device identifiers,
service origins, Mailbox ownership, group membership authorization, request
timing, IP addresses, and ciphertext sizes. Logs and metrics must minimize
these values and never combine them with plaintext or secrets.

Push payloads are wake-up hints. They must not contain identity,
conversation/group, Mailbox, MLS, contact-name, message-body, or attachment
identifiers. After a wake-up, the authenticated client reconciles from the
durable server high-water mark.

## Required fail-closed behavior

- A schema epoch or aggregate baseline digest mismatch refuses startup.
- Revoked devices cannot obtain new sessions, Pull new Mailbox data, or send
  new authorized operations.
- A changed retry under the same idempotency key is rejected.
- Stale leases, generations, epochs, revisions, and fences are rejected.
- Mailbox ACK occurs only after ciphertext validation, deduplication, MLS
  advancement, message persistence, and cursor persistence commit atomically.
- Missing keys, invalid signatures/descriptors, corrupt ciphertext, cursor
  gaps, and incomplete local state enter an explicit degraded/reset-required
  state; they never silently accept partial state.
- Agent Control and Public services are optional profiles and have no database
  or runtime path that bypasses Product Core message authorization.

## Logging and diagnostics

Production logs may include bounded error codes, service role, operation ID,
state revision, coarse latency, and redacted digests where needed for
correlation. They must not include:

- message or filename plaintext;
- identity/device private keys, MLS secrets, or database keys;
- bearer material, raw Mailbox/attachment capabilities, or Push credentials;
- HPKE plaintext, decrypted events, or decrypted attachment content.

Tests and fixtures use synthetic credentials only. X3/X4/X5 acceptance resets
may remove vNext state, but must preserve host TLS/CA/domain material and every
non-vNext service, directory, container, and database.
