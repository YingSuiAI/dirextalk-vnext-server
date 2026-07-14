# Local two-node development cluster

Start the disposable local cluster from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\local-cluster.ps1 -Action up
```

It builds the current Rust node image, starts one PostgreSQL instance with two
independent logical node databases, applies the embedded forward migrations to
each database, provisions the explicit least-privilege runtime grant matrix,
then waits for an HTTP response from each service before returning. It starts
these host-loopback-published development endpoints:

| Logical node | Identity endpoint | Mailbox endpoint |
| --- | --- | --- |
| A | `http://127.0.0.1:18080` | `http://127.0.0.1:14812` |
| B | `http://127.0.0.1:18081` | `http://127.0.0.1:14813` |

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
environment. The two databases are independent logical node stores, not
hostile-node containment: their containers share the development network and
the passwordless trust setup. Use it for repeatable functional testing, never
to validate network isolation or production credential boundaries.

It currently exercises the runnable identity and opaque-mailbox services on two
separate node databases. Group membership has durable server state but no HTTP
node yet, and public-channel/contact-acceptance endpoints are still unfinished;
the stack does not pretend those end-to-end product paths are available. The
client's production discovery transport also requires HTTPS, so its QR/contact
flow needs the later local TLS/test-CA stage rather than these HTTP endpoints.
