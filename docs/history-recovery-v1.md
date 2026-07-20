# History Recovery V1

V40 adds candidate-authorized history recovery without changing the existing
durable mailbox, identity log, or MLS truth sources. The server never receives
history plaintext, MLS epoch secrets, private keys, or an active UI scope.

## Contract flow

1. A candidate device creates and signs a canonical enrollment V2 recovery
   request. It binds the candidate-generated request ID, identity and device,
   candidate signing and recipient-encryption keys, the observed identity-log
   head, `all_current_memberships`, and a bounded validity window. The bearer
   capability is an HTTP carrier field and is not part of the signed request.
2. Existing enrollment approval appends the exact `DeviceAdd` only while the
   observed head is still the direct identity-log predecessor. Persistence keeps
   the exact request bytes and digest immutable.
3. The candidate publishes and a same-identity active controller claims a V2
   `history_recovery` KeyPackage. Both operations bind the recovery request and
   exact scope digests; a general-purpose package cannot satisfy this contract.
4. An active provider encrypts an opaque snapshot to the registered recipient
   key and submits a V2 history grant. The provider and a distinct authority
   sign the same canonical transcript. The authority is another active device,
   the current root key, or the current recovery key. Active-device authority
   IDs are device UUIDs; root/recovery authority IDs use the existing
   `dirextalk.device-history-authority-id.v1` public-key hash convention.
5. The grant transaction locks identity delivery highwater `H`, persists the
   exact grant and opaque offer, enqueues the mailbox envelope, and appends the
   durable delivery and realtime journal facts at `H + 1`. Any mismatch at `H`
   is a conflict, not a best-effort retry.
6. MLS Sequencer V5 admits each recovered device with a same-identity active
   controller signature over the request, scope, claimed KeyPackage, parent,
   Commit, and Welcome. The candidate does not sign a final recovery transcript;
   its earlier request is the candidate authorization. Welcome remains pending
   until candidate confirmation.
7. A federated Group Node never reads the identity origin's tables. For every
   V5 submit, exact replay, and receipt readback it first reduces the current
   self-verifying identity log, then performs a hardened origin GET for the
   exact candidate, controller, current head, KeyPackage, request, and scope.
   The origin returns only current redacted digests and the earliest expiry.

The candidate first applies the opaque snapshot locally and then resumes the
ordinary per-device mailbox/WSS stream from `H + 1`. Delivery remains
at-least-once and every device retains an independent cursor and ACK. An ACK by
one device never consumes another device's delivery.

## Revocation and failure rules

- The provider must still be active and hold usable snapshot key material. A
  stale provider fails with `KeyMaterialUnavailable`; the server does not
  substitute or reconstruct keys.
- Approval, grant, and MLS authorization re-check current identity-log facts.
  Exact retries return the original receipt only after those remote facts are
  revalidated; changed bytes under an existing idempotency identity are
  conflicts. A stale request/head, mismatched package/scope/controller, expired
  grant, or unavailable origin fails before a Group intent is written.
- MLS V5 removal requires the current identity-log revoke head and removes only
  the revoked device leaf. Federated removal reduces the fresh identity log and
  requires that exact `DeviceRevoke` target to be the terminal current-head
  event. It never deletes the account or group membership.
- Expired offers no longer authorize history pulls. Device delivery state is a
  cursor only and cannot become an alternate authorization source.

## HTTP surfaces

- `POST /v1/devices/enroll/challenges` with
  `application/vnd.dirextalk.history-recovery-request.v1+cbor`
- Existing enrollment approval route for the resulting challenge
- Existing KeyPackage routes with
  `application/vnd.dirextalk.key-package-publish.v2+cbor` and
  `application/vnd.dirextalk.key-package-claim.v2+cbor`
- `POST /v3/devices/history-grants` with
  `application/vnd.dirextalk.device-history-grant.v2+cbor`
- `GET /v1/identities/{identity_id}/history-recovery-requests/{request_id}/mls-v5-authorization`
  with the canonical ordered query
  `candidate_device_id`, `controller_device_id`, `identity_head_digest`,
  `key_package_digest`, `recovery_request_digest`, and
  `recovery_scope_digest`, accepting only
  `application/vnd.dirextalk.mls-v5-recovery-authorization.v1+cbor`
- Existing identity mailbox V2/V3 pull and per-device ACK routes
- Existing MLS commit route with
  `application/vnd.dirextalk.mls-commit.v5+cbor`

The authorization GET is origin-authenticated, `no-store`, redirect-free, DNS
pinned, proxy-free, content-type exact, and bounded to 4096 bytes. Its unsigned
16-field projection is deliberately non-portable: it contains IDs, current
head/package/request/scope/grant/attachment/claim-receipt digests, authority
kind/ID, and expiry, but never the opaque offer, bearer capability, session,
snapshot, KeyPackage bytes, private key, MLS private state, or epoch secret.

The byte-exact CDDL and public invariants are frozen in protocol baseline V40.
Operational logs and diagnostics must expose only IDs, digests, cursors, and
typed outcomes; opaque offers and bearer capabilities are not logging fields.
