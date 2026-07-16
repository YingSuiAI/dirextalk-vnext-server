# Local three-node development cluster

Start the disposable local cluster from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\local-cluster.ps1 -Action up
```

It builds the current Rust node image, creates a disposable local P-256 test CA
and three node leaf certificates in a Docker named volume, starts one
PostgreSQL instance with three independent logical node databases, applies the
embedded forward migrations to each database, provisions the explicit
least-privilege runtime grant matrix, then checks Docker health and safe
malformed HTTPS requests on each published Identity, Mailbox, Group, Public
Feed, and Indexer route before returning. Each logical node is one `dtx-node`
container with one native HTTPS outlet:

| Logical node | Unified endpoint | Fixed tenant | Fixed local Indexer |
| --- | --- | --- | --- |
| A | `https://127.0.0.1:18443` | `0190f2a5-7b1c-7abc-8def-0123456789a0` | `0190f2a5-7b1c-7abc-8def-0123456789b0` |
| B | `https://127.0.0.1:18444` | `0190f2a5-7b1c-7abc-8def-0123456789a1` | `0190f2a5-7b1c-7abc-8def-0123456789b1` |
| C | `https://127.0.0.1:18445` | `0190f2a5-7b1c-7abc-8def-0123456789a2` | `0190f2a5-7b1c-7abc-8def-0123456789b2` |

The unified Rust node terminates TLS itself on container `:8443`; there is no
same-container TCP proxy. Docker publishes each outlet only on host loopback.
The generated root private key is never serialized, and node private keys stay
in the `dtx-local-tls` volume mounted read-only into the node containers. The
script copies only the public CA certificate to
`$env:TEMP\dirextalk-vnext-local-ca.pem` for host-side checks. On Windows the
check uses Schannel's `--ssl-no-revoke` only because this offline disposable CA
has no CRL endpoint; certificate-chain and hostname validation remain enabled.

Useful commands:

```powershell
scripts\local-cluster.ps1 -Action status
scripts\local-cluster.ps1 -Action logs -Follow
scripts\local-cluster.ps1 -Action down
scripts\local-cluster.ps1 -Action reset  # deletes only the local Compose volumes
```

For an isolated second local cluster, set `DTX_LOCAL_POSTGRES_PORT` before
`-Action up`; the default remains `15432`.

This is a development-only topology. PostgreSQL trust authentication and the
passwordless local runtime principals are deliberately confined to the dedicated
Compose network and loopback-published ports; never copy them to a deployed
environment. The three databases are independent logical node stores, not
hostile-node containment: their containers share the development network and
the passwordless trust setup. Use it for repeatable functional testing, never
to validate network isolation or production credential boundaries.

It exercises identity, opaque mailbox, group-command, signed public-feed, and
Indexer services on three separate node databases. The five stores use separate
least-privilege database login URLs inside each unified node process; Public
Feed and Indexer login roles are `NOINHERIT` and receive disjoint direct table
grants. Each node has a fixed, non-secret local tenant and Indexer identifier.
Local actors use that node's session projection; federated actors
send an origin-bound device proof and the Group Node fetches the actor's
self-authenticated identity log from the matching A/B/C Identity Node. The
Group Node adds this local CA to normal platform trust only for the local
three-node topology; it still validates certificate chains and hostnames and
does not use an insecure TLS bypass. Each runtime principal has only the
explicit permissions needed for its path.

The explicit ignored integration test
`three_node_compose_runs_v30_peer_admission_and_exact_recovery_over_tls`
requires a freshly reset disposable volume,
`DTX_THREE_NODE_COMPOSE_ACCEPTANCE=1`, and
`DTX_THREE_NODE_TLS_CA_FILE=$env:TEMP\dirextalk-vnext-local-ca.pem`. It proves
A Owner create/bootstrap/invite → B federated candidate join → A approval/MLS
commit → lost-response exact replay → B federated confirmation over real HTTPS;
it also checks each A/B/C descriptor from the host. Normal Compose health
checks do not substitute for this workflow acceptance.

The Group Node provides the durable policy/membership command boundary only.
MLS commit reconciliation, contact acceptance, and client integration are
still unfinished; the stack does not claim those end-to-end product paths are
available. The local CA is development-only and must never be deployed or
added to a user/system trust store.
