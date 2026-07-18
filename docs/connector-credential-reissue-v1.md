# Connector credential reissue v1

`ReissueConnectorCredential` is an emergency, certificate-only recovery path for an expired
Connector control certificate. It is an additive unary RPC on `ConnectorEnrollment`, protected by
ordinary server-authenticated TLS. It is not an Owner HTTP API and does not alter the normal live
`RotateCredential` command.

The operator prepares one tenant-scoped operation against the exact Connector, current credential
ID/fingerprint, generation and spec revision. The protected handoff contains the sole raw 32-byte
token; server persistence contains only `SHA-256(token)`. A retry must reuse the same handoff.
Creating a new token after a handoff is lost is intentionally refused.

The RPC proves possession of both the expired current control key and the new control key over the
exact reissue transcript. It rejects a current/not-yet-valid/revoked/non-current credential,
mismatched fence, pending normal rotation/reissue, expired first consumption window, or changed
replay. Exact consumed requests replay their original public credential result after the handoff
TTL; no certificate/private key/token/signature is logged or returned.

The replacement certificate has a fresh ID, control key and leaf fingerprint, but retains the
Connector generation, spec revision, offline refresh key and command cursor. It remains pending
until its first valid `Hello`; that one transaction promotes it, retires the old certificate
immediately and keeps normal boot/lease fencing. Pending credentials are not accepted for any
other control frame. Abort is permitted only before consumption/promotion.
