# End-to-End Request Path

This example verifies the complete local request path:

```text
HTTP client -> SecurityEdge -> EdgeProxy -> origin-demo
```

Start the standard local stack from the [examples index](../README.md), then run [`requests.http`](./requests.http) from top to bottom.

## What to verify

1. `GET /healthz` returns `200 OK` and is not cached.
2. `GET /api/time` reaches `origin-demo` through both platform layers and returns the Origin name.
3. The response contains SecurityEdge decision metadata such as `X-Security-Action: ALLOW`.
4. `GET /api/products` is routed through EdgeProxy and returns `X-Cache` metadata.
5. The authenticated Dashboard overview endpoint is reachable through the loopback-only SecurityEdge Admin listener.
6. The EdgeProxy dependency status exposed by SecurityEdge is healthy while EdgeProxy is running.

The exact generated timestamps and request IDs are intentionally nondeterministic.

## curl.exe equivalents

```powershell
curl.exe -i http://127.0.0.1:8081/healthz
curl.exe -i http://127.0.0.1:8081/api/time
curl.exe -i http://127.0.0.1:8081/api/products
curl.exe -sS `
  -H "Authorization: Bearer dev-security-token" `
  http://127.0.0.1:9191/api/v1/dashboard/overview
curl.exe -sS `
  -H "Authorization: Bearer dev-security-token" `
  http://127.0.0.1:9191/api/v1/edgeproxy/status
```

A direct request to `http://127.0.0.1:8080` is intentionally **not** part of this platform example because normal client traffic should enter through SecurityEdge.
