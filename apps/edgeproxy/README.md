# EdgeProxy

EdgeProxy is the reverse-proxy and HTTP-caching component of the [SecureEdge Platform](../../README.md). It can run independently or as the internal data plane behind [SecurityEdge](../securityedge/README.md).

This README assumes commands are executed from:

```text
apps/edgeproxy
```

## Responsibilities

EdgeProxy owns the platform's upstream delivery path:

- host- and path-based route matching;
- multiple named origins per route with independent weight and priority;
- per-route `round_robin`, `weighted_round_robin`, `least_connections`, `priority_failover`, `adaptive_latency`, and `random_weighted` scheduling;
- active origin health checks, automatic failover, and recovery to higher-priority origins;
- route-level readiness;
- HTTP reverse proxying with trusted-proxy-aware forwarding headers;
- retries for safe replayable requests;
- connection pooling and upstream timeouts;
- in-memory HTTP caching;
- cache-stampede prevention;
- stale-if-error fallback, except when the Origin requires revalidation with `must-revalidate` or `proxy-revalidate`;
- structured access and origin-attempt logs;
- request, cache, origin, retry, byte, active-request, EWMA-latency, health-transition, and scheduler metrics;
- an authenticated, transactional configuration Control Plane;
- automatic JSON and `.env` watching with hot reload or graceful generation restart.

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

## Environment configuration

EdgeProxy can run entirely from its JSON profiles, so an environment file is optional. For deployment-specific addresses and credentials, copy the committed template:

```powershell
Copy-Item ./.env.example ./.env
```

The process automatically loads `apps/edgeproxy/.env` when launched from the repository root and `.env` when launched from this directory. It does not fall back to a repository-root `.env`, so settings for another tool or application cannot become EdgeProxy configuration accidentally. An explicit file can be selected with `-env` or `EDGEPROXY_ENV_FILE`; use `-no-env` for an isolated run that must ignore dotenv files. Relative `EDGEPROXY_CONFIG` values loaded from `.env` resolve from that file, while CLI and pre-existing process-environment paths remain relative to the current working directory. Double-quoted dotenv values use JSON-compatible escapes in both the Go executable and PowerShell scripts; Go-only escapes such as `\xNN` are rejected.

Configuration precedence is:

```text
CLI flags > existing process environment > .env > JSON profile > built-in defaults
```

Important variables:

| Variable | Purpose |
|---|---|
| `EDGEPROXY_CONFIG` | JSON profile; relative paths are resolved from the loaded `.env` file |
| `EDGEPROXY_SERVER_LISTEN_ADDR` | EdgeProxy data-plane IP and port |
| `EDGEPROXY_ADMIN_LISTEN_ADDR` | Admin API IP and port |
| `EDGEPROXY_ADMIN_TOKEN` | Admin API credential shared with SecurityEdge |
| `EDGEPROXY_TRUSTED_PROXY_CIDRS` | Comma-separated trusted SecurityEdge peers |
| `EDGEPROXY_FORWARDED_FOR_HEADER` | Verified client-address header name |
| `EDGEPROXY_ROUTE_<ROUTE>_UPSTREAM_URLS` | Comma-separated Origin URLs for one route |
| `EDGEPROXY_TLS_ENABLED` | Enables the EdgeProxy TLS listener |
| `EDGEPROXY_TLS_CERT_FILE` / `EDGEPROXY_TLS_KEY_FILE` | TLS certificate and key paths |
| `ORIGIN_DEMO_LISTEN_ADDR` / `ORIGIN_DEMO_NAME` | Demo Origin listener and name |

Route names are converted to uppercase environment suffixes with non-alphanumeric characters replaced by underscores. For example, `demo-app` uses `EDGEPROXY_ROUTE_DEMO_APP_UPSTREAM_URLS`. Only Origin URLs are environment-overridable. Route names, host selectors, and path prefixes remain in the shared JSON profile because SecurityEdge reads the same route contract when selecting per-route security policies. A legacy `EDGEPROXY_ROUTE_<ROUTE>_HOSTS` value is rejected instead of being silently ignored.

Empty or missing variables do not replace JSON values. A missing auto-discovered `.env` file is therefore safe and uses the selected JSON profile unchanged. A path supplied explicitly with `-env` or `EDGEPROXY_ENV_FILE` must identify a regular UTF-8 file no larger than 1 MiB and parse successfully. Invalid files are rejected before any values are applied.

Never commit the real `.env`; the root `.gitignore` excludes it while allowing `.env.example`. EdgeProxy PowerShell verification scripts also auto-load this file, never overwrite pre-existing process variables, and allow explicit script parameters to override the effective values.

## Quick start: local standalone mode

### 1. Start the demo Origin

```powershell
go run ./cmd/origin-demo `
  -no-env `
  -listen 127.0.0.1:9000 `
  -name origin-local
```

### 2. Start EdgeProxy

In another terminal, still from `apps/edgeproxy`:

```powershell
go run ./cmd/edgeproxy `
  -no-env `
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

After copying `.env.example` to `.env`, the LAN integration profile and endpoints are selected automatically:

```powershell
go run ./cmd/edgeproxy -pretty-logs
```

For an explicit local integration test that ignores `EDGEPROXY_CONFIG` but still permits the other environment overrides:

```powershell
go run ./cmd/edgeproxy `
  -config ../../integration/edgeproxy-local-behind-waf.json `
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
- active health checks;
- a per-route load-balancing algorithm and adaptive scheduler parameters;
- per-origin names, weights, and failover priorities.

### Load-balancing algorithms

Each route selects one independent scheduler through `load_balancing.algorithm`:

| Algorithm | Behavior |
|---|---|
| `round_robin` | Distributes requests evenly across healthy Origins. |
| `weighted_round_robin` | Uses each Origin's `weight` for deterministic proportional distribution. |
| `least_connections` | Selects the healthy Origin with the fewest active requests, using weight to break proportional ties. |
| `priority_failover` | Sends traffic to the lowest numeric priority tier and fails over only when that tier is unavailable. Recovered higher-priority Origins automatically resume service. |
| `adaptive_latency` | Combines weight, active work, and EWMA response latency; `latency_sensitivity` controls how strongly latency affects selection. |
| `random_weighted` | Randomly selects a healthy Origin in proportion to its configured weight. |

`ewma_alpha` controls how quickly adaptive latency reacts to recent responses. Scheduling is health-aware, retries exclude an already-attempted Origin when another healthy candidate exists, and every Origin reports active requests, EWMA latency, scheduler selections, and health failure/recovery counters.

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

Authenticated observability endpoints:

```text
GET     /api/v1/status
GET     /api/v1/metrics
GET     /api/v1/logs
DELETE  /api/v1/logs
POST    /api/v1/cache/purge
```

Authenticated configuration Control Plane:

```text
GET     /api/v1/config
PUT     /api/v1/config
POST    /api/v1/config/reload
GET     /api/v1/config/watch
GET     /api/v1/routes
POST    /api/v1/routes
GET     /api/v1/routes/{route}
PUT     /api/v1/routes/{route}
DELETE  /api/v1/routes/{route}
GET     /api/v1/routes/{route}/origins
POST    /api/v1/routes/{route}/origins
GET     /api/v1/routes/{route}/origins/{origin}
PUT     /api/v1/routes/{route}/origins/{origin}
DELETE  /api/v1/routes/{route}/origins/{origin}
```

Control Plane writes use strict JSON decoding, reject unknown fields and bodies larger than 4 MiB, validate the complete candidate, preserve a supplied `[REDACTED]` Admin token, create timestamped backups, and atomically replace the configuration file. Route and Origin lookup is case-insensitive; route names are immutable after creation so SecurityEdge policy identities cannot silently drift. A route must retain at least one Origin.

Hot-applicable routing, cache, health, and scheduler changes return `200 OK` and are installed without dropping traffic. Listener, TLS, Admin listener/auth/log-store, and process-timeout changes are persisted and return `202 Accepted`; the managed process coalesces pending work and performs an automatic graceful generation restart. Invalid JSON or `.env` revisions never replace the last healthy runtime. `GET /api/v1/config/watch` reports watched files, digests, revisions, the last apply mode/error, and pending restart state.

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

`/healthz` reports process liveness. `/readyz` returns a generic `ready` or `not_ready` payload and reports `503 Service Unavailable` when any configured route has no healthy Origin. The unauthenticated readiness response deliberately omits route and Origin details; use the authenticated `/api/v1/status` endpoint for diagnostics.

The in-memory Admin log ring accepts a configured capacity from `1` through `100000` entries. Request-method metrics preserve the standard HTTP methods and aggregate nonstandard or extension methods under `OTHER` to keep metric label cardinality bounded.

## Admin credential

`EDGEPROXY_ADMIN_TOKEN` always takes precedence over the JSON credential. Use the same strong value in `apps/edgeproxy/.env` and `apps/securityedge/.env`; SecurityEdge uses it only for authenticated backend calls to the EdgeProxy Admin API.

## Scripts

Run from `apps/edgeproxy`:

```powershell
.\scripts\start-origin.ps1
.\scripts\start-proxy.ps1
.\scripts\test-proxy.ps1
.\scripts\test-observability.ps1

# Explicit alternatives
.\scripts\start-origin.ps1 -EnvFile ./.env
.\scripts\start-proxy.ps1 -Config ./configs/local-dev.json -EnvFile ./.env
.\scripts\start-proxy.ps1 -NoEnv -Config ./configs/local-dev.json
.\scripts\test-proxy.ps1 -NoEnv -ProxyUrl http://127.0.0.1:8080 -Token dev-token
```

The test scripts load `apps/edgeproxy/.env` automatically and derive the data-plane target from the effective first route, listener port, and TLS setting. They preserve the configured route host while using curl `--connect-to` to reach the actual local listener, so component verification does not depend on public or Technitium DNS. Process environment variables take precedence; explicit `-ProxyUrl`, `-AdminUrl`, `-OriginUrl`, and `-Token` parameters override the derived values, and `-NoEnv` preserves an isolated JSON/default test. Use `-Insecure` only for an intentional development TLS certificate that is not trusted by the local machine. Wildcard listeners are contacted through the corresponding loopback family, explicitly bound hostnames/LAN IPs/IPv6 addresses are retained, and a listener configured with port `0` requires an explicit URL because its runtime port cannot be predicted. If the first route contains only wildcard host patterns, supply `-ProxyUrl` explicitly.

On POSIX systems, `scripts/demo.sh` is a small explicit-environment smoke test. It deliberately does not source `.env` as shell code. Export `EDGEPROXY_ADMIN_TOKEN` and override `PROXY_URL` or `ADMIN_URL` when the active deployment differs from the local defaults:

```sh
EDGEPROXY_ADMIN_TOKEN='replace-with-the-active-token' \
PROXY_URL='http://project.local:8080' \
ADMIN_URL='http://127.0.0.1:9090' \
./scripts/demo.sh
```

The script fails before sending requests when no Admin token is supplied and bypasses ambient HTTP proxy settings for local verification.

Without `.env` or explicit parameters, `start-origin.ps1` uses the built-in `127.0.0.1:9000` / `origin-a` defaults. For a deliberate LAN deployment, set `ORIGIN_DEMO_LISTEN_ADDR=0.0.0.0:9000` in `.env` and protect the Origin port with the host firewall.

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

## Configuration automation from PowerShell

The management client works directly against EdgeProxy and prints structured JSON suitable for interactive use or automation:

```powershell
.\scripts\manage-config.ps1 -Action Status
.\scripts\manage-config.ps1 -Action Watch
.\scripts\manage-config.ps1 -Action ListRoutes
.\scripts\manage-config.ps1 -Action UpdateRoute -Route demo-app -BodyFile .\route.json
.\scripts\manage-config.ps1 -Action CreateOrigin -Route demo-app -BodyJson '{"name":"origin-b","url":"http://127.0.0.1:9001","weight":2,"priority":1}'
.\scripts\manage-config.ps1 -Action Telemetry
```

The script reads `EDGEPROXY_ADMIN_TOKEN` from the process environment or `.env`, bypasses ambient system proxies for local/LAN control traffic, rejects invalid JSON before sending it, and fails on non-success HTTP responses.

## Docker

### Standalone EdgeProxy Compose stack

Run from `apps/edgeproxy`. First create the local environment file and replace `EDGEPROXY_ADMIN_TOKEN`; the Compose definition rejects a missing or empty token instead of using a public default:

```powershell
Copy-Item ./.env.example ./.env
docker compose up --build
```

The Compose file builds two minimal non-root images from this Dockerfile. EdgeProxy configuration is stored in a writable named volume mounted at `/app/config`; this is required for atomic rename, backups, Dashboard/API changes, and automatic file watching while the root filesystem remains read-only:

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

To run SecurityEdge in front of EdgeProxy, create the deployment environment file, replace both Admin tokens, and use the repository-level deployment:

```powershell
Copy-Item ../../deployments/docker/.env.example ../../deployments/docker/.env

docker compose `
  --env-file ../../deployments/docker/.env `
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
