# Opaque Push Registration V1 (V43)

V43 publishes a device-scoped FCM preference at the canonical HTTPS endpoint
`/v1/devices/push-registrations/fcm` for both `PUT` and `DELETE`. The
authenticated device identity comes solely from the `DTX-Device-Session`
header. Requests use canonical CBOR and require `Idempotency-Key` plus
`If-Match` (revision `0` creates the first registration).

The PUT body is exactly `{version: 1, token: bstr}` with a 1..4096-byte token.
Receipts are exactly `{version: 1, provider: fcm, revision: uint>=1,
state: active|suspended|revoked}` and never expose token, digest, KMS, delivery,
or identity data. Exact bound retries return byte-identical receipts, including
after session revocation; changed bindings return 409. First PUT is 201,
replace/replay is 200, and DELETE terminal/replay is 200. Authentication and
error/status/header/media rules are frozen in the OpenAPI artifact.

FCM is the only V43 provider. The internal provider payload is exact UTF-8 JSON
`{"version":1,"wake_delivery_id":"<canonical UUIDv7>"}`; transport TTL 60
seconds is metadata, not payload. Registration is only a wake preference:
durable Mailbox Pull/ACK and the account read cursor remain delivery truth.

The production runtime is the standalone `dtx-opaque-push-broker` process. It
owns the public registration routes and a single cancellation-aware delivery
loop, and uses three separately authenticated PostgreSQL pools for identity
authentication, registration mutation, and broker delivery. Database URLs are
accepted only from root-owned file references. The local root key, FCM service
account, TLS material, and database URL files are loaded before the process
clears supplementary groups and drops to its configured non-root UID/GID;
Tokio, database pools, provider HTTP, and listeners start only after the drop is
verified. The readiness listener is loopback-only and reports ready only after
the pools, broker, and bound listeners are initialized.

V43 code completion does not imply live activation. Container/release service
wiring, Firebase project material, client platform token/cold-start handling,
and device acceptance remain separate deployment and client stages.
