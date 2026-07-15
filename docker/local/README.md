# Local three-node development cluster

Start the disposable local cluster from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\local-cluster.ps1 -Action up
```

It builds the current Rust node image, starts one PostgreSQL instance with three
independent logical node databases, applies the embedded forward migrations to
each database, provisions the explicit least-privilege runtime grant matrix,
then checks Docker health and a safe malformed HTTP request (expected `422`) on
each published Identity, Mailbox, and Group Node before returning. It starts
these host-loopback-published development endpoints:

| Logical node | Identity endpoint | Mailbox endpoint | Group endpoint | Fixed group tenant |
| --- | --- | --- | --- | --- |
| A | `http://127.0.0.1:18080` | `http://127.0.0.1:14812` | `http://127.0.0.1:14814` | `0190f2a5-7b1c-7abc-8def-0123456789a0` |
| B | `http://127.0.0.1:18081` | `http://127.0.0.1:14813` | `http://127.0.0.1:14815` | `0190f2a5-7b1c-7abc-8def-0123456789a1` |
| C | `http://127.0.0.1:18082` | `http://127.0.0.1:14816` | `http://127.0.0.1:14817` | `0190f2a5-7b1c-7abc-8def-0123456789a2` |

The identity binary itself remains bound to container loopback; the local image
uses a tiny same-container TCP proxy to make it reachable through Docker's
published host-loopback port. The proxy listens on the container interface so
Docker can forward that port, but every published host port is explicitly bound
to `127.0.0.1`.

Useful commands:

```powershell
scripts\local-cluster.ps1 -Action status
scripts\local-cluster.ps1 -Action logs -Follow
scripts\local-cluster.ps1 -Action down
scripts\local-cluster.ps1 -Action reset  # deletes only the local Compose volume
```

This is a development-only topology. PostgreSQL trust authentication and the
passwordless local runtime principals are deliberately confined to the dedicated
Compose network and loopback-published ports; never copy them to a deployed
environment. The three databases are independent logical node stores, not
hostile-node containment: their containers share the development network and
the passwordless trust setup. Use it for repeatable functional testing, never
to validate network isolation or production credential boundaries.

It exercises identity, opaque mailbox, and group-command services on three
separate node databases. Each Group Node has a fixed, non-secret local tenant
identifier. Local actors use that node's session projection; federated actors
send an origin-bound device proof and the Group Node fetches the actor's
self-authenticated identity log from the matching A/B/C Identity Node. Exact
HTTP origins are allowed only by this development configuration. Each runtime
principal has only the explicit permissions needed for its path.

The explicit ignored integration test
`three_node_compose_runs_remote_owner_admin_candidate_and_receipt_recovery`
requires a freshly reset disposable volume and
`DTX_THREE_NODE_COMPOSE_ACCEPTANCE=1`. It proves A Owner → B Admin → B invite →
C join → B approval plus fresh C receipt-query recovery across the three
logical node databases. Normal Compose health checks do not substitute for
this workflow acceptance.

The Group Node provides the durable policy/membership command boundary only.
MLS commit reconciliation, public-channel discovery, contact acceptance, and
client integration are still unfinished; the stack does not claim those
end-to-end product paths are available. The client's production discovery
transport also requires HTTPS, so its QR/contact flow needs the later local
TLS/test-CA stage rather than these HTTP endpoints.
