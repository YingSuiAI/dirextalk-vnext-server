# ADR-0013: Public descriptor V1.2 canonical DNS origins

- Status: Accepted for PD1 follow-up
- Date: 2026-07-14
- Supersedes: ADR-0012 for all new public-descriptor writes
- Owners: `dtx-public-descriptor` and `protocol/public-descriptor/v1_2`

## Context

V1.1 removed publisher-controlled feed paths, but its authority grammar still
accepted literals that URL implementations can interpret differently from a
plain DNS hostname. In particular, dotted numeric, octal-like, hexadecimal,
single-number IPv4 forms, and IP literals make a public descriptor less
portable and can turn origin policy into a client-specific URL-parser decision.
The V1.1 CDDL also described an Agent tombstone payload as an Agent payload,
while the signed Rust implementation correctly emits the empty tombstone map.

V8 is immutable. Neither defect can be repaired by changing V1.1 CDDL,
vectors, signatures, or its baseline.

## Decision

V1.2 is the sole writable public-descriptor wire:

```text
writer = minimum_reader = { major: 1, minor: 2 }
feed_origin = "https://" + canonical_dns_name + optional(":" + non_default_port)
              + optional("/")
fixed_feed_path(subject_id) =
  "/.well-known/dirextalk/public/v1/" + subject_id
public_feed_url = trim_trailing_root_slash(feed_origin) + fixed_feed_path(subject_id)
```

The V1.2 verifier permits only an ASCII lower-case DNS hostname. Each label is
1 through 63 bytes, contains only lower-case letters, digits, or hyphens, and
cannot begin or end with a hyphen. The full hostname is at most 253 bytes, has
no trailing dot, and contains at least one ASCII letter. These rules reject
underscores, upper-case names, raw IPv4 and IPv6 literals, dotted numeric
forms, hexadecimal forms such as `0x7f000001`, and all-numeric one-part forms
such as `2130706433` or `0177.0.0.1`.

Only HTTPS is allowed. A feed origin has no path or exactly one root slash; it
has no userinfo, query, fragment, or backslash. A port, when present, is a
non-zero decimal `u16` with no leading zero and is not the default HTTPS port
443. This gives each accepted origin one stable textual representation.

Both Channel and Agent tombstones use payload code `3` and field `12` is the
empty map `{}`. The V1.2 CDDL and byte-exact vector include both tombstone
kinds, so CDDL validation and the Rust reducer verify the same cross-boundary
shape.

### Historical boundary

`HistoricalPublicDescriptorV1_0` and
`HistoricalPublicDescriptorV1_1` are the only exposed old-wire read paths.
They verify exact canonical bytes and signatures for migration or audit, but
expose no payload, current feed URL, writable constructor, append operation,
or current reducer. `UnsignedPublicDescriptorV1::new`,
`SignedPublicDescriptorV1::signed`,
`SignedPublicDescriptorV1::decode_and_verify`, and `DescriptorHeadV1` accept
only V1.2.

### PD2 boundary

Canonical DNS syntax is intentionally not a network authorization decision.
PD2 must resolve an accepted DNS name under an explicit egress policy and
defend fetches against private/link-local/reserved destinations, DNS rebinding,
redirects, and connection-time address changes. This ADR adds no resolver,
network fetcher, SSRF policy, or deployment change.

## Consequences

Consumers have one portable authority representation and derive exactly one
public document URL for each active descriptor. V1.0 and V1.1 remain
verifiable history, but cannot be reintroduced as current discovery input.
The V1.0/V7 and V1.1/V8 artifacts remain byte-for-byte unchanged; V1.2 has its
own CDDL, vectors, and independent V9 baseline. Any future change to the
authority grammar, fixed path, DNS-resolution policy, delegation, or
publisher-key model requires another versioned wire and baseline.
