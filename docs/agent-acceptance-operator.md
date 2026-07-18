# Agent Alpha Acceptance Operator

`dtx-agent-provision` exposes a temporary, root-operated two-phase Alpha
acceptance boundary. It creates no public HTTP API and starts no runtime or
cloud process. The split keeps Connector enrollment independent from the real
Agent identities that the client authority flow creates later.

The non-secret plan contains one Host and one or two Connectors. The supported
adapter sets are exactly `{codex}` for a fresh Windows Codex Host,
`{codex, openclaw_acp}` for the existing Alpha path, or
`{codex, hermes_acp}` for future native Hermes acceptance. OpenClaw-only,
Hermes-only, duplicate, and three-adapter plans are invalid; so are approximate
values such as `openclaw` or `hermes`. The plan also contains the future
Agent/Installation/Agent Device/Binding IDs and each Agent's canonical HTTPS
`server_origin`. Immutable IDs, capacities, descriptor digests, and request IDs
are replay checked; changed durable facts fail closed.

## Prepare

Validate without PostgreSQL or token creation:

```text
dtx-agent-provision acceptance-prepare \
  --config-file /etc/dirextalk/agent-control.json \
  --database-url-file /run/credentials/dtx-agent-control.service/database-url \
  --plan-file /root/dtx-acceptance/plan.json \
  --dry-run
```

Create/reuse the Host and selected Connector(s), then issue/recover one exact
enrollment intent per Connector:

```text
install -d -m 0700 /root/dtx-acceptance
dtx-agent-provision acceptance-prepare \
  --config-file /etc/dirextalk/agent-control.json \
  --database-url-file /run/credentials/dtx-agent-control.service/database-url \
  --plan-file /root/dtx-acceptance/plan.json \
  --handoff-file /root/dtx-acceptance/handoff.json
```

The handoff parent must be owned by the operator and mode `0700`. The command
creates or atomically replaces a non-symlink `0600` handoff. Raw enrollment
tokens exist only in that file: never in arguments, environment, stdout,
errors, or logs. Stdout is a redacted prepare manifest containing the exact
Installation IDs and origins needed by the client authority tool.

## Real Agent authority facts

Run the controlled client `provision_agent_authority` flow once per
Installation against the origin from the prepare manifest. Each invocation
must write one independent non-symlink `0600` JSON file with exactly this
shape:

```json
{
  "schema_version": 1,
  "installation_id": "01900000-0000-7000-8000-000000000001",
  "server_origin": "https://x3.dirextalk.ai",
  "agent_identity_id": "dtxi1...",
  "identity_device_id": "01900000-0000-7000-8000-000000000002",
  "identity_head_sequence": 2,
  "identity_head_hash": "base64url-unpadded-32-byte-digest",
  "credential_fingerprint": "base64url-unpadded-32-byte-digest"
}
```

Unknown fields, non-canonical Base64URL, duplicate identities/devices,
zero-valued digests, an Owner identity/device reuse, an Installation/origin
mismatch, or unsafe file permissions are rejected. The credential fingerprint
must be produced from the real root-signed Agent `DeviceCertificateV1` using
the protocol's `dirextalk.agent-device-credential-fingerprint.v1\0` hash
domain. The operator never fabricates or substitutes this value; the root-only
facts file is the trust handoff from the controlled client authority tool, so
fixtures and random placeholder fingerprints are unsupported.

## Finalize

Validate the facts files without touching PostgreSQL. This existing
Codex-plus-OpenClaw example requires two:

```text
dtx-agent-provision acceptance-finalize \
  --config-file /etc/dirextalk/agent-control.json \
  --database-url-file /run/credentials/dtx-agent-control.service/database-url \
  --plan-file /root/dtx-acceptance/plan.json \
  --facts-file /root/dtx-acceptance/codex-agent-facts.json \
  --facts-file /root/dtx-acceptance/openclaw-agent-facts.json \
  --dry-run
```

Run the same command without `--dry-run` to create/reuse each verified Agent
Definition, owner-approval-pending Installation, active Agent Device, and
enabled exclusive Binding. The client's signed Owner approval remains the
only operation allowed to bind the Agent identity to its Installation.
Finalize requires exactly one facts file per selected plan entry, matched by
the exact Installation ID and canonical origin. A `{codex}` plan therefore
requires only its Codex facts file; it must not fabricate an OpenClaw or Hermes
fact from another Host. Finalize also requires the exact prepared Host and
Connectors; it never silently creates a missing foundation. Repeating the exact
command is idempotent, while changed identity, certificate, descriptor, or
routing facts fail closed.

For a `{codex, hermes_acp}` plan, keep the command shape identical and replace
only the second facts path with the independent native Hermes facts file, for
example `/root/dtx-acceptance/hermes-agent-facts.json`. The facts file does not
carry an adapter label: its exact Installation ID and origin bind it to the
corresponding `hermes_acp` plan entry. This support is future-ready operator
code and does not imply that Hermes is deployed or accepted on a particular
host.

The database URL is read only from the explicit owner-controlled `0400`,
`0440`, `0600`, or `0640` service secret. The Connector issuer is loaded from
the running service configuration, so prepare issues credentials accepted by
that Agent Control instance.

## Short-lived Agent MCP credential

After the real Agent Device, enabled Binding, and active ConversationGrant
exist, the peer operator may issue a 32-byte random bearer locally. Keep the
raw Base64URL-no-pad token only in the Connector's owner-controlled secret
handoff. Never place it in SQL, stdout, logs, or the Owner Device Session
surface.

Register only
`SHA-256("dirextalk.agent-mcp-token.v1\0" || raw_32_token_bytes)` through
`agent.register_mcp_credential_digest(...)`. The function also requires the
exact tenant, UUIDv7 credential, Installation, Binding, Agent Device,
Connector node ID, private conversation, `mcp.references.v1` capability,
creation time, and expiry. Expiry is strictly capped at 24 hours. At most two
unexpired credentials may coexist for one Binding so rotation can install the
new Connector secret before revoking the old digest.

Revoke through `agent.revoke_mcp_credential_digest(...)` with the exact
credential ID and digest. Both functions are available only to the optional
`dtx_agent_peer_admin` role and require the transaction-local tenant context.
The Agent runtime receives only the authentication function; it has no direct
table, registration, or revocation access.
