# Platform Examples

This directory contains end-to-end examples for the complete SecureEdge Platform. The examples intentionally exercise **SecurityEdge and EdgeProxy together** instead of duplicating application-specific configuration samples.

The checked-in local-development contract used throughout these examples is:

```text
Client                    http://127.0.0.1:8081
  -> SecurityEdge         gateway/WAF
  -> EdgeProxy            http://127.0.0.1:8080 (internal)
  -> origin-demo          http://127.0.0.1:9000

SecurityEdge Admin        http://127.0.0.1:9191
SecurityEdge dev token    dev-security-token
EdgeProxy Admin           http://127.0.0.1:9090
EdgeProxy dev token       dev-token
Route                     demo-app
```

These values come from [`apps/securityedge/configs/local-dev.json`](../apps/securityedge/configs/local-dev.json) and [`integration/edgeproxy-local-behind-waf.json`](../integration/edgeproxy-local-behind-waf.json). If you change those profiles, update the example variables before running the requests.

## Start the local stack

Run the following commands from the **repository root** in three terminals. `-no-env` makes the examples independent of any local `.env` files.

### Terminal 1 - Origin

```powershell
go run ./apps/edgeproxy/cmd/origin-demo `
  -no-env `
  -listen 127.0.0.1:9000 `
  -name origin-local
```

### Terminal 2 - EdgeProxy

```powershell
go run ./apps/edgeproxy/cmd/edgeproxy `
  -no-env `
  -config ./integration/edgeproxy-local-behind-waf.json `
  -pretty-logs
```

### Terminal 3 - SecurityEdge

```powershell
go run ./apps/securityedge/cmd/securityedge `
  -no-env `
  -config ./apps/securityedge/configs/local-dev.json `
  -pretty-logs
```

The dashboard is then available at `http://127.0.0.1:9191` with the local token `dev-security-token`.

## Example catalog

| Example | Demonstrates | Mutates configuration? |
| --- | --- | --- |
| [`end-to-end/`](./end-to-end/) | Full request path, response metadata, Origin identity, health and Admin visibility | No |
| [`cache/`](./cache/) | Cache purge, `MISS -> HIT`, private-response and authenticated-request bypass | Cache entries only |
| [`waf/`](./waf/) | Allowed traffic, SQL-injection blocking, XSS blocking and security-event visibility | No |
| [`load-balancing/`](./load-balancing/) | Multiple Origins, round robin, priority failover and recovery | Yes, but only on a disposable config copy |

## Running the `.http` collections

Each example includes a `requests.http` file using standard HTTP-client syntax supported by tools such as the VS Code **REST Client** extension and JetBrains HTTP Client. Execute requests individually and in the documented order.

The request files contain only the **checked-in development credentials** from the local profiles. Never replace those values with production credentials in a committed file.

If you prefer command-line execution, every README also includes equivalent PowerShell and/or `curl.exe` commands for the important verification steps.

## Safety and repeatability

- The normal examples never send traffic directly to the internal EdgeProxy data-plane listener; requests enter through SecurityEdge.
- Admin operations use the SecurityEdge Admin API, which proxies EdgeProxy Control Plane operations through the intended management boundary.
- The cache example changes only in-memory cache contents.
- The WAF examples use harmless local demonstration payloads against `origin-demo`; do not aim these requests at systems you do not own or administer.
- The load-balancing example is the only configuration-mutating scenario. Its README requires a temporary copy of the EdgeProxy profile so the repository configuration remains unchanged.
- Stop the three local services when finished. The example requests do not require elevated privileges or firewall changes.

Application-specific standalone profiles remain under [`apps/edgeproxy/configs/`](../apps/edgeproxy/configs/) and [`apps/securityedge/configs/`](../apps/securityedge/configs/). Shared deployment profiles remain under [`integration/`](../integration/).
