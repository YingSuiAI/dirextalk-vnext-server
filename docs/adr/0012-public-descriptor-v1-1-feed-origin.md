# ADR-0012: Public descriptor V1.1 authority-only feed origins

- Status: Accepted for PD1 follow-up
- Date: 2026-07-14
- Supersedes: ADR-0011 for all new public-descriptor writes
- Owners: `dtx-public-descriptor` and `protocol/public-descriptor/v1_1`

## Context

The frozen public-descriptor V1.0 contract carried a signed `feed_endpoint`.
Although it excluded several ambiguous URL forms, it allowed a publisher to
place an arbitrary path in a publicly replicated descriptor. A path can carry a
capability, token, signed URL, or other correlatable secret-like value. An
Indexer, relay, client cache, support export, or future federation peer could
then persist and disclose it even though it never needs that path to locate the
subject's public feed.

V7 is immutable and remains useful to inspect existing exact history. It is not
a safe current registration format and cannot be repaired by rewriting its
CDDL, vector, signature, or baseline.

## Decision

V1.1 is the sole writable public-descriptor wire:

```text
writer = minimum_reader = { major: 1, minor: 1 }
feed_origin = "https://" + host + optional(":" + port) + optional("/")
fixed_feed_path(subject_id) =
  "/.well-known/dirextalk/public/v1/" + subject_id
public_feed_url = trim_trailing_root_slash(feed_origin) + fixed_feed_path(subject_id)
```

`feed_origin` is a literal ASCII HTTPS authority with either no path or exactly
one root slash. The V1.1 verifier rejects userinfo, query, fragment, backslash,
non-HTTPS schemes, custom paths, invalid ports, and malformed authorities. It
does not accept a generic URL normalization or a path-bearing endpoint.
`capability_digest` and (for Agents) `manifest_digest` remain digests only; no
token, private key, mailbox credential, raw Matrix identifier, tenant ID, or
control-plane UUID is representable in V1.1.

The stable public subject continues to be self-certifying and independent of
the origin:

```text
channel_id = dtxc1 + base32lower(
  SHA-256("dirextalk.channel.v1\0" || subject_genesis_ed25519_public_key)
)
agent_id = dtxa1 + base32lower(
  SHA-256("dirextalk.agent.v1\0" || subject_genesis_ed25519_public_key)
)
```

The V1.0 domain-separated descriptor digest, signature input, entry hash, and
publisher/subject authority binding remain unchanged within major version 1;
the exact `1.1` wire field and canonical bytes prevent cross-wire ambiguity.

### Historical V1.0 boundary

`HistoricalPublicDescriptorV1_0::decode_and_verify` is the only exposed V1.0
read path. It validates exact canonical bytes and signatures for migration or
audit inspection, but does not expose a writable constructor, current payload,
append operation, current reducer, registration, or public-feed URL.
`UnsignedPublicDescriptorV1::new`, `SignedPublicDescriptorV1::signed`,
`SignedPublicDescriptorV1::decode_and_verify`, and `DescriptorHeadV1` accept
only V1.1. This makes a V1.0 downgrade fail before a current descriptor can be
created, decoded, reduced, registered, or indexed.

## Consequences

Clients and PD2 can compute exactly one public feed URL per active descriptor,
without trusting a publisher-controlled path. PD2 may define transport and
fetch policy later, but it must use the derived path rather than concatenating
an untrusted endpoint. PD3/PD4 must revalidate V1.1 descriptors and never use
V1.0 history as a current discovery result.

The V1.0 CDDL, vectors, and V7 baseline are preserved unchanged. V1.1 has a
new CDDL, byte-exact vectors, and independent V8 baseline. A future change to
the well-known path, authority grammar, delegation, or publisher-key model
requires another versioned wire and baseline rather than an in-place edit.
