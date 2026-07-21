# Recovery Scope Catalog V1

V41 adds an identity-origin catalog for recovery discovery without adding a
plaintext, key, or authorization truth source. Catalogs and provider responses
are opaque deterministic-CBOR envelopes. The identity node verifies their
signed metadata and current identity-log authority, stores the exact bytes, and
returns only signed heads or a minimal candidate-authorized status.

## HTTP surfaces

- `PUT /v1/recovery-scope-catalogs/{generation}` accepts only
  `application/vnd.dirextalk.recovery-scope-catalog.v1+cbor`. It requires an
  active device session and an idempotency key. Generation numbers are positive
  canonical safe integers, contiguous per identity, and immutable. Success
  returns the exact signed head as
  `application/vnd.dirextalk.recovery-scope-catalog-head.v1+cbor` (`201` for
  creation and `200` for an exact replay).
- `POST /v2/devices/enroll/catalog-preparations` accepts only
  `application/vnd.dirextalk.recovery-scope-catalog-preparation.v1+cbor`. It
  requires both the ordinary protocol-version-1
  `DTX-Enrollment-Capability` for the referenced enrollment challenge and the
  candidate-held `DTX-Recovery-Response-Capability`, plus an idempotency key.
  It freezes the current catalog generation and identity head before ordinary
  enrollment approval.
- `GET /v2/devices/enroll/catalog-preparations/{request_id}` accepts no request
  body or authentication substitute and requires the exact recovery response
  capability. It returns
  `application/vnd.dirextalk.recovery-scope-catalog-status.v1+cbor` with only
  the protocol's redacted status projection.
- `PUT /v2/devices/enroll/catalog-preparations/{request_id}/provider-response`
  accepts only
  `application/vnd.dirextalk.recovery-scope-catalog-provider-response.v1+cbor`.
  It requires an active provider device session and an idempotency key. The
  provider must be the current history provider or current history authority at
  the frozen head, or the exact candidate device added at the direct successor
  head. No broader same-identity-device substitution is permitted.

All four surfaces reject content encoding, enforce exact media types and
canonical CBOR, and emit `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff`. Catalog ciphertext is limited to 1,048,576
bytes, signed preparation metadata to 16,384 bytes, and catalog/provider command
envelopes to 1,065,984 bytes. Bearer capabilities, device session secrets,
opaque ciphertext, signatures, and exact envelopes are not log fields.

## State and failure rules

A preparation begins `pending`, becomes `ready` only after a valid provider
response, and is terminally `invalidated` when its frozen catalog/head no
longer represents the current catalog or enrollment predecessor. Expiry is
reported as `expired`. Status reads use `200` for pending/ready, `410` for
expired, and `412` for invalidated; even terminal responses contain only the
minimal redacted status object.

Every operation revalidates current device, provider, authority, catalog, and
enrollment facts while holding the relevant database locks. Changed bytes under
an existing idempotency identity are conflicts. A stale head, catalog rotation,
revocation, wrong capability, non-direct candidate addition, signature failure,
or storage error fails closed before a catalog, preparation, or provider
response is written. Exact concurrent retries converge on the original durable
result. A later exact preparation replay performs no write and returns the same
current redacted ready, invalidated, or expired projection as the status read;
it never resurrects the original pending view. The POST replay remains the
declared `200 PreparationStatus` for every one of those states. The dedicated
GET uses `200`, `412`, or `410` for ready/pending, invalidated, or expired,
respectively. POST `412 HeadChanged` is reserved for a new preparation that
cannot be created against its proposed frozen bindings.

## Runtime readiness

Migration 52 creates the two identity-owned tables with forced row-level
security. `dtx_identity_runtime` has only `SELECT` and `INSERT` on both tables,
plus `UPDATE` on the eight provider-response columns of preparations. It has no
table-wide `UPDATE`, `DELETE`, `TRUNCATE`, ownership, or policy-bypass authority.
Startup readiness validates these exact grants and must fail when they drift.

An empty rollback must apply migration 52 down before migration 51. Migration
52 refuses the downgrade before any DDL when either catalog table contains
facts; otherwise it revokes only the catalog-specific runtime grants and drops
only the catalog trigger, function, and tables. It does not own or rewrite the
federated MLS authorization objects created by migration 51.

The byte-exact schemas, domains, status fields, and public error vocabulary are
frozen in protocol baseline V41. Operators must retain migration 52 and its
least-privilege grants when deploying the V41 identity-node routes.

Protocol baseline V42 is a separate additive contract freeze for Recovery Scope
Catalog V2, History Recovery V3, KeyPackage V4, and MLS Sequencer V7. It neither
rewrites V41 nor activates V2 catalog runtime routes, and it does not replace
migration 52. Operators and clients must not infer V2 runtime availability from
the presence of the V42 schemas and validators alone.
