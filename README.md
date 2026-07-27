# Dirextalk vNext Server

Rust workspace for the Matrix-independent Dirextalk server and control plane.
The single active cross-repository contract is
[`docs/internal-test-alpha.md`](docs/internal-test-alpha.md).

Internal Test Alpha is a fresh-only, evidence-driven stage for the server,
client, Connector, and Deployer. A crate, binary, focused test, or local stack
is an implementation input—not proof that the real three-device workflow has
passed. Keep server state, client state, and acceptance evidence disposable;
never import legacy state or add a compatibility path.

Production-stack, release-image, and other operator hardening are optional
follow-up work. They cannot block the Internal Test Alpha workflow or be used
as a substitute for its real-device evidence.
