# Connector credential reissue v1

`ReissueConnectorCredential` is an emergency, certificate-only recovery path for an expired
Connector control certificate. It is an additive unary RPC on `ConnectorEnrollment`, protected by
ordinary server-authenticated TLS. It is not an Owner HTTP API and does not alter the normal live
`RotateCredential` command.

The operator prepares one tenant-scoped operation against the exact Connector, current credential
ID/fingerprint, generation and spec revision. The protected handoff contains the sole raw 32-byte
token; server persistence contains only `SHA-256(token)`. A retry must reuse the same handoff.
Creating a new token after a handoff is lost is intentionally refused. Prepare idempotency also
commits the exact Connector, plan, and requested TTL; an aborted operation never reopens.

The RPC proves possession of both the expired current control key and the new control key over the
exact reissue transcript. It rejects a current/not-yet-valid/revoked/non-current credential,
mismatched fence, pending normal rotation/reissue, expired first consumption window, or changed
replay. Exact consumed requests replay their original public credential result after the handoff
TTL and after later credentials retire that result; no certificate/private key/token/signature is
logged or returned. Reissue intent identity and fence fields are immutable, and consumed or
aborted receipts are terminal under the tenant-scoped runtime role.

The replacement certificate has a fresh ID, control key and leaf fingerprint, but retains the
Connector generation, spec revision, offline refresh key and command cursor. It remains pending
until its first valid `Hello`; that one transaction promotes it, retires the old certificate
immediately and keeps normal boot/lease fencing. Pending credentials are not accepted for any
other control frame. Abort is permitted only before consumption/promotion.

## Result commitment

The response `result_digest` is
`SHA-256(LP(domain) || LP(part-1) || ... || LP(part-n))`, where every `LP(value)` is the
eight-byte unsigned big-endian length followed by the exact value bytes. The domain is the ASCII
bytes `dirextalk.connector-credential-reissue-result.v1`. UUIDs below are their 16 network-order
bytes; counters and timestamps are unsigned eight-byte big-endian values.

The parts, in order, are:

1. operation UUID;
2. intent UUID;
3. tenant UUID;
4. host UUID;
5. Connector UUID;
6. expired/current credential UUID;
7. expired/current leaf SHA-256;
8. Connector generation;
9. spec revision;
10. issued credential UUID;
11. issued credential generation;
12. issued credential revision;
13. new control Ed25519 public key;
14. certificate-chain entry count;
15. each DER certificate as its own part, in response order (leaf first);
16. issued leaf SHA-256;
17. `valid_from_millis`;
18. `valid_until_millis`;
19. request digest.

The retained refresh key and `result_digest` itself are excluded. The issued generation and
revision are committed separately even though v1 requires them to equal the Connector generation
and spec revision.

The frozen server vector uses request digest
`182a3e68f3e341b74529644de36cac5702bfa20d3f600ab97b5eef1038406963` and produces result digest
`860c6e1904d97a574a5e453939273981904a29496cc5785ba702823900e90fed`; its complete synthetic inputs
are retained in `crates/dtx-agent-control/tests/credential_reissue_result_vector.rs`.

## Downgrade safety

Schema v43 cannot represent two credentials with the same Connector generation and spec revision,
nor the append-only reissue authorization causes. The v44 down migration therefore performs a
read-only preflight before any DDL and refuses atomically with SQLSTATE `55000` if any reissue
intent, operation, credential, or authorization revision exists. This includes active, aborted,
consumed, pending, and promoted recovery histories.

An operator must keep the server on schema v44 or later unless the downgrade is empty-data. For an
exceptional recovery, first complete or abort live recovery work, archive the tenant-scoped audit
history, obtain explicit destructive-data authority, and remove all related reissue facts through
an audited recovery procedure before retrying. The migration deliberately does not perform that
lossy purge. On an empty-data downgrade it restores all v43 uniqueness/check constraints and the
four trigger functions replaced by v44.
