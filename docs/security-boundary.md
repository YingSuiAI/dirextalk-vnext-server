# Internal Test Alpha security boundary

This is the minimal active privacy and authorization boundary for the Internal
Test Alpha workflow.

## Privacy

- Conversation events, MLS state, attachments, prompts, and runtime input stay
  encrypted/opaque end to end through the Sidecar. The server and Agent
  Control may validate envelopes, digests, ordering, and authorization, but
  never decrypt or log content.
- Device private keys, MLS secrets, bearer material, database keys, and
  provider credentials remain on their owning device/Host and never enter
  protocol responses or logs.
- Logs and acceptance bundles contain only bounded error codes, identifiers,
  and digests needed for correlation; synthetic credentials are used in tests.

## Authorization and fencing

- Every device, contact, Group membership, Connector event, and Deployer/Host
  mutation is origin-bound and authorized by its current identity, generation,
  or operation fence.
- An offer is not execution authority. Only the exact matching
  `RunLeaseGranted` can start a runtime; stale Connector or Run lease fences
  fail closed.
- Mailbox ACK is accepted only after ciphertext validation, deduplication,
  domain/MLS state, and cursor persistence commit atomically. WSS is a wake-up
  signal; Pull at the durable highwater is the recovery authority.
- Missing keys, invalid signatures, cursor gaps, changed retries, and stale
  generations enter an explicit reset/degraded result and never silently
  accept partial state.
