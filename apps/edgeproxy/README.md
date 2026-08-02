# EdgeProxy

EdgeProxy is the reverse-proxy and HTTP-caching component of the [SecureEdge Platform](../../README.md). It can run independently or as the internal data plane behind [SecurityEdge](../securityedge/README.md).

This README assumes commands are executed from:

```text
apps/edgeproxy
```

## Responsibilities

EdgeProxy owns the platform's upstream delivery path:

- host- and path-based route matching;
- multiple origins per route;
- round-robin origin selection;
- active origin health checks;
- route-level readiness;
- HTTP reverse proxying with trusted-proxy-aware forwarding headers;
- retries for safe replayable requests;
- connection pooling and upstream timeouts;
- in-memory HTTP caching;
- cache-stampede prevention;
- stale-if-error fallback, except when the Origin requires revalidation with `must-revalidate` or `proxy-revalidate`;
- structured access and origin-attempt logs;
- request, cache, origin, retry, byte, and latency metrics;
- an authenticated Admin API.

In the active integrated deployment, EdgeProxy does **not** expose the public listener. SecurityEdge receives public traffic first and forwards accepted requests to EdgeProxy on loopback.

## Architecture

### Integrated platform mode

```text
SecurityEdge
127.0.0.1 → EdgeProxy:8080
                    │
                    ├── route matching
                    ├── cache processing
                    ├── healthy-origin selection
                    └── upstream observability
                    ▼
                  Origin
```

### Standalone mode

```text
HTTP client → EdgeProxy → Origin
```

Standalone mode is useful for isolated development and for demonstrating the reverse-proxy and cache phases without SecurityEdge.

## Configuration profiles

| Configuration | Listener | Origin | Usage |
|---|---:|---|---|
| `configs/local-dev.json` | `127.0.0.1:8080` | `127.0.0.1:9000` | Local EdgeProxy-only development |
| `configs/edgeproxy.json` | `0.0.0.0:80` | `10.36.74.43:9000` | Standalone LAN demonstration |
| `../../integration/edgeproxy-local-behind-waf.json` | `127.0.0.1:8080` | `127.0.0.1:9000` | Local integrated platform |
| `../../integration/edgeproxy-behind-waf.json` | `127.0.0.1:8080` | `10.36.74.43:9000` | LAN integrated platform |
| `configs/compose.json` | `0.0.0.0:8080` | `origin:9000` | Standalone EdgeProxy Compose demonstration |
| `../../integration/edgeproxy-compose-behind-waf.json` | `0.0.0.0:8080` | `origin:9000` | Full-platform Compose deployment behind SecurityEdge |

The shared profiles are stored in the root-level [`integration`](../../integration/README.md) directory because they define the contract between both applications.

## Quick start: local standalone mode

### 1. Start the demo Origin

```powershell
go run ./cmd/origin-demo `
  -listen 127.0.0.1:9000 `
  -name origin-local
```

### 2. Start EdgeProxy

In another terminal, still from `apps/edgeproxy`:

```powershell
go run ./cmd/edgeproxy `
  -config ./configs/local-dev.json `
  -pretty-logs
```

### 3. Test proxying and caching

```powershell
curl.exe -i http://127.0.0.1:8080/api/products
curl.exe -i http://127.0.0.1:8080/api/products
```

Expected cache headers:

```text
first request   X-Cache: MISS
second request  X-Cache: HIT
```

Dynamic responses such as `/api/time` should bypass storage according to their origin cache policy:

```powershell
curl.exe -i http://127.0.0.1:8080/api/time
```

## Run behind SecurityEdge

Start the demo Origin as above, then run EdgeProxy with the shared local integration profile:

```powershell
go run ./cmd/edgeproxy `
  -config ../../integration/edgeproxy-local-behind-waf.json `
  -pretty-logs
```

For the LAN profile:

```powershell
go run ./cmd/edgeproxy `
  -config ../../integration/edgeproxy-behind-waf.json `
  -pretty-logs
```

In both integrated profiles, EdgeProxy binds to:

```text
Data plane   127.0.0.1:8080
Admin API    127.0.0.1:9090
```

These profiles trust forwarded client addresses only from the local SecurityEdge process. The full-platform Compose profile trusts only the fixed SecurityEdge container address `172.30.0.10`. Standalone profiles do not trust client-supplied forwarding headers.

Start SecurityEdge separately by following [`../securityedge/README.md`](../securityedge/README.md).

## Routing

Each route can define:

- exact hosts or a single leading wildcard such as `*.example.com` (without ports);
- a path prefix;
- optional prefix stripping;
- host preservation behavior;
- one or more upstream origins;
- proxy and retry settings;
- cache policy;
- active health checks.

Routing precedence favors the most specific host/path match. Request paths are canonicalized before route selection, optional prefix stripping, Origin forwarding, cache-key generation, and path-filtered cache purges. This keeps dot-segment-equivalent requests aligned across the entire data path. Example profiles are available in:

```text
configs/examples/multi-origin.json
configs/examples/multi-route.json
```

## Reverse-proxy behavior

EdgeProxy provides:

- `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` handling;
- explicit `server.trusted_proxy_cidrs` and `server.forwarded_for_header` controls so only approved upstream proxies can supply the original client address;
- `X-Request-ID` generation and propagation;
- authoritative edge response metadata: Origin-supplied `X-Request-ID`, `X-Cache`, timing, and `X-Security-*` headers are removed before responses are forwarded or cached;
- hop-by-hop header removal;
- optional incoming TLS termination;
- optional HTTPS upstreams;
- bounded response headers;
- direct Origin connections that do not inherit ambient `HTTP_PROXY` or `HTTPS_PROXY` settings;
- transport, response-header, request, and idle timeouts;
- retries for idempotent replayable requests after transport failures or configured upstream errors;
- response-stream failures recorded in metrics and structured logs even when the final HTTP status has already been sent;
- graceful shutdown.

## HTTP cache

The cache is an in-memory, thread-safe LRU with:

- entry-count, total-byte, and per-object limits;
- TTL derived from `s-maxage`, `max-age`, `Expires`, or the route default;
- `X-Cache: HIT`, `MISS`, `BYPASS`, or `STALE`;
- `Age` response headers;
- conditional `304 Not Modified` support, including `If-None-Match: *` for fresh successful cached representations without an explicit ETag;
- per-key locking to prevent cache stampedes;
- stale-if-error fallback, except when the Origin requires revalidation with `must-revalidate` or `proxy-revalidate`;
- route/host/path purge support.

Requests or responses are bypassed when caching would be unsafe, including common cases involving `Authorization`, cookies, `Set-Cookie`, `Range`, `private`, `no-store`, `no-cache`, legacy `Pragma: no-cache`, or unsupported `Vary` values. If authenticated or cookie-bearing request caching is explicitly enabled, EdgeProxy automatically partitions cache keys with SHA-256 fingerprints of those headers. Responses that are explicitly allowed to be cached despite `Set-Cookie` keep the cookie on the live Origin response but never replay it from shared cache.

When the Origin explicitly sends `s-maxage`, `max-age`, or `Expires`, malformed values cause the response to bypass storage instead of silently falling back to the route default TTL. This prevents an invalid Origin freshness policy from extending a response's shared-cache lifetime.

## Demo Origin endpoints

The included Origin server provides:

```text
GET /healthz       liveness response
GET /               basic Origin identity
GET /api/products   cacheable JSON response
GET /api/time       dynamic response
GET /api/private    private/non-cacheable response
GET /api/slow       delayed response
GET /api/error      upstream error response
GET /api/counter    request counter
```

## Admin API

The Admin API defaults to `127.0.0.1:9090` in local and integrated profiles.

Liveness and readiness:

```text
GET /healthz
GET /readyz
```

Authenticated endpoints:

```text
GET     /api/v1/status
GET     /api/v1/metrics
GET     /api/v1/logs
DELETE  /api/v1/logs
POST    /api/v1/cache/purge
```

Local-development credentials:

```powershell
$AdminUrl = "http://127.0.0.1:9090"
$Token = "dev-token"
$Auth = "Authorization: Bearer $Token"
```

Examples:

```powershell
curl.exe -i "$AdminUrl/healthz"
curl.exe -i "$AdminUrl/readyz"
curl.exe -s -H $Auth "$AdminUrl/api/v1/status"
curl.exe -s -H $Auth "$AdminUrl/api/v1/metrics"
curl.exe -s -H $Auth "$AdminUrl/api/v1/logs?limit=100"
```

Purge the cache for one route:

```powershell
curl.exe -X POST -H $Auth `
  "$AdminUrl/api/v1/cache/purge?route=demo-app"
```

Limit the purge to one authority and a canonical path prefix:

```powershell
curl.exe -X POST -H $Auth `
  "$AdminUrl/api/v1/cache/purge?route=demo-app&host=project.test&path_prefix=%2Fapi"
```

`path_prefix` matches the exact path segment and its descendants. For example, `/api` matches `/api` and `/api/products`, but not `/apix`. It must be an absolute canonical path without query text, fragments, percent-encoded path bytes, dot-segments, or repeated slashes.

`/healthz` reports process liveness. `/readyz` reports `503 Service Unavailable` when any configured route has no healthy Origin.

The in-memory Admin log ring accepts a configured capacity from `1` through `100000` entries. Request-method metrics preserve the standard HTTP methods and aggregate nonstandard or extension methods under `OTHER` to keep metric label cardinality bounded.

## Admin-token override

The environment variable takes precedence over the JSON value:

```powershell
$env:EDGEPROXY_ADMIN_TOKEN = "<strong-random-token>"

go run ./cmd/edgeproxy `
  -config ./configs/local-dev.json `
  -pretty-logs
```

Use environment-based secret injection outside demonstration environments.

## Scripts

Run from `apps/edgeproxy`:

```powershell
.\scripts\start-origin.ps1
.\scripts\start-proxy.ps1 -Config ./configs/local-dev.json
.\scripts\test-proxy.ps1 -ProxyUrl http://127.0.0.1:8080 -Token dev-token
```

`start-origin.ps1` binds to `127.0.0.1:9000` by default. For a deliberate LAN deployment, pass `-Listen 0.0.0.0:9000` and protect the Origin port with the host firewall.

For the integrated LAN profile, supply the public SecurityEdge URL to traffic-generation scripts rather than connecting clients directly to EdgeProxy.

## Build and verification

```powershell
go fmt ./...

go vet ./...
go test ./...
go test -race ./...

go build -trimpath -o ./bin/edgeproxy ./cmd/edgeproxy
go build -trimpath -o ./bin/origin-demo ./cmd/origin-demo
```

Makefile targets:

```powershell
make fmt
make vet
make test
make validate
make build
```

## Docker

### Standalone EdgeProxy Compose stack

Run from `apps/edgeproxy`:

```powershell
docker compose up --build
```

The Compose file builds two minimal non-root images from this Dockerfile:

```text
Host client → EdgeProxy container → Origin container
```

Published listeners:

```text
EdgeProxy data plane   http://127.0.0.1:8080
EdgeProxy Admin API    http://127.0.0.1:9090
```

The Origin is available only inside the Compose network. Both services use read-only root filesystems, drop Linux capabilities, and enable `no-new-privileges`.

Stop the stack:

```powershell
docker compose down
```

This Compose file intentionally demonstrates EdgeProxy and the demo Origin only.

### Complete platform Compose stack

To run SecurityEdge in front of EdgeProxy, still from `apps/edgeproxy`, use the repository-level deployment:

```powershell
docker compose `
  -f ../../deployments/docker/compose.yml `
  up --build
```

That deployment does not publish the EdgeProxy or Origin ports to the host; all public HTTP traffic enters through SecurityEdge. See [../../deployments/docker/README.md](../../deployments/docker/README.md).

### Build images directly

The final Dockerfile stage builds the EdgeProxy image:

```powershell
docker build -t edgeproxy:latest .
```

Build the demo Origin image by selecting its target:

```powershell
docker build `
  --target origin-demo `
  -t edgeproxy-origin-demo:latest `
  .
```

## Security guidance

- In integrated mode, keep ports `8080` and `9090` on loopback.
- Do not expose the Admin API to untrusted networks.
- Use `EDGEPROXY_ADMIN_TOKEN` for real credentials.
- Restrict the Origin application port to the gateway host.
- Sensitive query-parameter values are redacted from both retained request logs and process logs.
- Treat `configs/edgeproxy.json` and the checked-in tokens as demonstration values.

## Related documentation

- [SecureEdge Platform](../../README.md)
- [SecurityEdge](../securityedge/README.md)
- [Platform integration](../../integration/README.md)

## License

See [../../LICENSE](../../LICENSE).
