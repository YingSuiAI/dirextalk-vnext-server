# Dirextalk vNext Server

Rust workspace for the Matrix-independent Dirextalk communication, multi-Agent control, durable automation, and typed cloud-resource control plane.

The implementation source of truth is [`../docs/dirextalk-vnext-development.md`](../docs/dirextalk-vnext-development.md). This repository is intentionally being built in verified vertical slices; the presence of a crate or type does not imply that the corresponding product feature is complete.

## Current slice

S0.1 provides only:

- the pinned Rust workspace and policy tooling;
- internal UUIDv7 lifecycle identifier types;
- protocol/minimum-reader compatibility validation;
- focused contract tests and CI.

It does not yet implement networking, persistence, identity cryptography, MLS, Agent routing, jobs, cloud operations, or client APIs.

See [`COMMANDS.md`](COMMANDS.md) for local verification.
