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
- generic HTTP/1.1 protocol upgrades, including WebSocket-style bidirectional tunnels;
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

Route names are converted to uppercase environment suffixes with non-alphanumeric characters replaced by underscores. For example, `demo-app` uses `EDGEPROXY_ROUTE_DEMO_APP_UPSTREAM_URLS`. Only Origin URLs are environment-overridable. Existing Origin metadata is preserved by position, including `name`, `weight`, `priority`, and `insecure_skip_verify`; newly appended URLs receive the normal validation defaults, and no route may supply more than 256 environment URLs. Route names, host selectors, and path prefixes remain in the shared JSON profile because SecurityEdge reads the same route contract when selecting per-route security policies. A legacy `EDGEPROXY_ROUTE_<ROUTE>_HOSTS` value is rejected instead of being silently ignored.

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

SecurityEdge's periodic data-plane connectivity check is a **synthetic operational probe**, not application traffic. Integrated EdgeProxy recognizes its reserved marker only when the request is a `HEAD` probe received directly from loopback or a configured trusted-proxy peer. Accepted probes bypass the shared cache and are excluded from application request/cache/upstream metrics, retained access/origin-attempt logs, scheduler selection/active counters, adaptive-latency EWMA, and Origin health transitions while still exercising a real Route and Origin. Probe retries prefer a different configured Origin; when a complete retryable `502`/`503`/`504` response is received and no alternate Origin remains, EdgeProxy preserves that response instead of discarding it and synthesizing a generic `502`. After a trusted probe actually matches a configured Route, EdgeProxy returns a private `X-SecureEdge-Internal-Probe: matched-v1` acknowledgement; unmatched 404s deliberately omit it even though ordinary unmatched responses still receive an `X-Request-ID`. The marker is stripped before the Origin request is sent, and any Origin-supplied copy is removed from responses so the acknowledgement remains authoritative. An untrusted client that copies the marker is handled as ordinary application traffic, and SecurityEdge also strips client-supplied copies before forwarding accepted public requests. EdgeProxy's own active Origin health checker remains an out-of-band subsystem and does not pass through the application cache/request metric path.

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

`ewma_alpha` controls how quickly adaptive latency reacts to recent responses. Scheduling is health-aware, retries exclude an already-attempted Origin when another healthy candidate exists, and every Origin reports active requests, EWMA latency, scheduler selections, and health failure/recovery counters. Active health probes run concurrently but remain bounded at two levels: up to 16 probes per Route and 64 probes across the EdgeProxy Handler as a whole. That shared process-level budget also covers overlapping old/new route states during hot reload, so large Origin sets recover and fail over promptly without creating a connection or goroutine storm.

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
- the internal `X-SecureEdge-Internal-Probe` header is reserved control-plane metadata and cannot be selected as `server.forwarded_for_header`; EdgeProxy strips it before resolving the client address and before Origin forwarding;
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

Configuration validation also places explicit ceilings on work-amplifying and memory-backed settings: at most 2,048 Routes, 256 hosts and 256 Origins per Route, 10 retries, 1,000,000 transport idle-connection slots, 4,096 trusted-proxy CIDRs, and 128 entries in each cache-header, cache-status, or health-status collection. Validation work itself stops at these ceilings, so a rejected oversized profile cannot amplify CPU or diagnostic-memory use before it is discarded.

## Native HTTPS/TLS data plane

EdgeProxy can terminate TLS directly on its data-plane listener when it is deployed as a public proxy or when the SecurityEdge-to-EdgeProxy hop crosses a host or trust boundary:

```json
{
  "server": {
    "listen_addr": "0.0.0.0:443",
    "tls": {
      "enabled": true,
      "cert_file": "/etc/edgeproxy/tls/fullchain.pem",
      "key_file": "/etc/edgeproxy/tls/privkey.pem"
    }
  }
}
```

The certificate chain and matching private key are loaded before a TLS generation is committed, and the native listener enforces TLS 1.2 or newer. Changes to the listener or any `server.tls` field are restart-required. The Control Plane, file watcher, Dashboard, and `EDGEPROXY_TLS_*` environment overrides all use the same managed restart path: certificate/key material and newly claimed listeners are preflighted before the healthy generation is drained. If startup still fails after preflight, EdgeProxy restores both the latest known-good file-backed configuration and the dotenv-managed environment that produced the healthy generation. Process/systemd environment variables remain authoritative and are never rewritten by this rollback.

Environment-only TLS changes affect the effective runtime without being persisted to JSON. Certificate **contents** are intentionally not watched independently when a configured path stays unchanged; after replacing or renewing PEM files in place, perform a controlled process restart so the new key pair is loaded.

HTTPS Origins are supported per Origin URL. EdgeProxy verifies Origin certificates by default and explicitly requires TLS 1.2 or newer on outbound HTTPS connections. `insecure_skip_verify` remains an explicit per-Origin development/testing escape hatch and should remain `false` in a trusted production deployment.

The integrated single-host systemd profile intentionally keeps EdgeProxy on HTTP loopback behind SecurityEdge. Enabling EdgeProxy TLS there is optional and normally unnecessary because that hop never leaves the host. For a split-host deployment, enable native TLS and use a certificate trusted by SecurityEdge.

## HTTP cache

The cache is an in-memory, thread-safe LRU with a validated maximum of 1,000,000 entries, 64 GiB total configured capacity, and 1 GiB per object. It provides:

- entry-count, total-byte, and per-object limits;
- TTL derived from `s-maxage`, `max-age`, `Expires`, or the route default;
- `X-Cache: HIT`, `MISS`, `BYPASS`, or `STALE`;
- `Age` response headers;
- conditional `304 Not Modified` support, including `If-None-Match: *` for fresh successful cached representations without an explicit ETag;
- per-key locking to prevent cache stampedes;
- stale-if-error fallback, except when the Origin requires revalidation with `must-revalidate` or `proxy-revalidate`;
- route/host/path purge support.

Requests or responses are bypassed when caching would be unsafe, including common cases involving `Authorization`, cookies, `Set-Cookie`, `Range`, `private`, `no-store`, `no-cache`, legacy `Pragma: no-cache`, or unsupported `Vary` values. If authenticated or cookie-bearing request caching is explicitly enabled, EdgeProxy automatically partitions cache keys with SHA-256 fingerprints of those headers. Responses that are explicitly allowed to be cached despite `Set-Cookie` keep the cookie on the live Origin response but never replay it from shared cache.

Requests carrying an HTTP protocol upgrade (`Connection: Upgrade` plus one valid `Upgrade` token) always bypass cache lookup and storage. EdgeProxy forwards only an unambiguous upgrade token, verifies that the Origin selects the same protocol, returns `101 Switching Protocols`, and then proxies bytes in both directions until either side closes. The client-to-Origin tunnel continues through the `bufio.Reader` returned by `Hijack`, so protocol bytes that `net/http` read ahead while parsing the upgrade request are preserved instead of being stranded before the raw socket stream begins. The route's normal `proxy.request_timeout` and the HTTP server's `read_timeout` / `write_timeout` protect the handshake path but do not become lifetime limits for an established upgraded connection; EdgeProxy explicitly clears any server deadline from the hijacked client socket before tunneling. Tunnel traffic is included in request byte telemetry, and successful `101` handshakes count as successful requests. `active_requests` remains incremented until the complete response body or upgraded tunnel ends, so `least_connections` continues to account for long-lived streams while EWMA latency remains based on the Origin response-header time. Because hijacked connections are outside `net/http` server shutdown tracking, EdgeProxy explicitly owns active tunnels and closes them when a managed generation is retired; WebSocket clients should reconnect after an automatic restart.

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
GET     /api/v1/telemetry
GET     /api/v1/routes/{route}/telemetry
GET     /api/v1/routes/{route}/origins/{origin}/telemetry
GET     /api/v1/logs
DELETE  /api/v1/logs
POST    /api/v1/cache/purge
```

Request, cache-hit/miss, upstream-latency, Route, scheduler, and retained access-log telemetry describe **application traffic**. Synthetic SecurityEdge connectivity probes are deliberately excluded so a five-second dependency check cannot dilute the cache hit ratio, inflate request or MISS totals, skew upstream latency, or look like user traffic in the Dashboard. Origin health-check counters remain health telemetry by design and are separate from these application counters. Metric snapshots also use a short consistency boundary: concurrent request/upstream writers remain concurrent with each other, while a snapshot briefly excludes writers so aggregate totals, per-Route/per-Origin counters, dimensions, latency samples, and derived rates are read from one coherent update generation instead of being mixed across an in-progress update. Route-status readiness is derived from the same captured Origin health values returned in that status payload, so a concurrent health transition cannot make a single response claim `ready=false` while listing a captured healthy Origin (or the reverse).

Client-facing request status accounting follows the final HTTP response rather than any preceding informational response: `1xx` responses such as `103 Early Hints` are forwarded without being latched as the completed outcome, while `101 Switching Protocols` remains final for an upgraded connection. Client-facing error totals are derived from HTTP `4xx` and `5xx` request counters. `proxy_errors` is a diagnostic subset/cause flag for requests that failed inside proxy processing and can overlap a `5xx` response, so it must not be added to `client_errors + server_errors` as though it represented another request. A request terminated by the client is tracked independently in `canceled_requests`: the physical `requests`/method/traffic/retry/cache-activity counters still describe work that actually reached EdgeProxy, and `bytes_in` records only request-body bytes actually consumed by the proxy rather than trusting a larger declared `Content-Length`. A canceled request is excluded from client-facing status codes, success/client/server error outcomes, `proxy_errors`, response-latency samples, and success/error-rate denominators because no complete client-facing HTTP outcome exists. EdgeProxy also stops processing a known client cancellation without synthesizing a `502` response or serving a stale-cache fallback to a client that is no longer waiting. Origin `success`/`failures` telemetry uses completed HTTP semantics independently of retry policy: any Origin `5xx` response is a failed Origin attempt for observability, while the retry policy remains limited to its configured retryable statuses. If the client cancels while an Origin attempt is in flight, that physical attempt is recorded separately as `canceled`; it is excluded from Origin success/failure, timeout, latency, EWMA, and reliability-rate denominators because it is not evidence that the Origin failed. Retry counts still describe physical retry attempts, including a retry that is subsequently canceled by the client.

Requests that reach EdgeProxy but do not match any configured Route are still observable application traffic. They receive an `X-Request-ID`, are recorded as HTTP `404` client errors in aggregate telemetry/access logs, and are grouped under the internal `__unmatched__` pseudo-route in metrics. The identifier `__unmatched__` is reserved case-insensitively and cannot be used as a configured Route name, preventing real Route telemetry from colliding with unmatched traffic. Trusted operational probes remain excluded even when their synthetic request does not match a Route, so connectivity checks cannot inflate application totals.

The live JSON snapshot's top-level `requests_per_second` value is the cumulative average physical application-request arrival rate since the current EdgeProxy process started (synthetic operational probes are excluded) and therefore includes requests that later become client-canceled; interval/request-window rates should be derived from adjacent monotonic counters rather than interpreting that field as an instantaneous rate. Ratio and latency fields are mathematically meaningful only when their underlying denominator/sample count is nonzero: for example, `cache_hit_ratio` requires at least one hit or miss, client-facing success/error rates require at least one completed/evaluable HTTP outcome (`success + client_errors + server_errors`), Origin success/error rates require at least one evaluated Origin outcome (`success + failures`), and latency summaries require at least one latency observation. A canceled-only Route can therefore have real request/cancellation/activity counters but no measured client-facing success/error rate or response-latency sample; similarly, a canceled-only Origin has real call/cancellation counters but no measured reliability rate or Origin-latency sample. The SecurityEdge Dashboard uses those counters/counts to render undefined derived measurements as unavailable instead of presenting an unobserved value as a real zero.

The access-log endpoint supports bounded server-side filters for `route`, `client_ip`, `upstream`, `request_id`, `method`, `event`, `level`, `cache`, exact status or status class, minimum duration, time range, and free-text `q`. Cursor pagination uses `before_sequence`; responses expose `has_more` and `next_before_sequence` so operators can traverse retained history without requesting the entire ring at once. The `client_ip` filter applies to the canonical client identity already resolved by EdgeProxy's trusted-proxy boundary rather than to an untrusted forwarding header.

Log-filter values are bounded before the in-memory ring is scanned: named filters accept at most 512 bytes and the free-text `q` search accepts at most 2,048 bytes. Search normalization is performed once per request rather than once per retained event, preventing an oversized authenticated query from amplifying CPU and allocation work across a large log store.

Authenticated configuration Control Plane:

```text
GET     /api/v1/config
PUT     /api/v1/config
POST    /api/v1/config/reload
GET     /api/v1/config/watch
GET     /api/v1/server
PUT     /api/v1/server
GET     /api/v1/admin
PUT     /api/v1/admin
GET     /api/v1/routes
POST    /api/v1/routes
GET     /api/v1/routes/{route}
PUT     /api/v1/routes/{route}
DELETE  /api/v1/routes/{route}
GET     /api/v1/routes/{route}/load-balancing
PUT     /api/v1/routes/{route}/load-balancing
GET     /api/v1/routes/{route}/proxy
PUT     /api/v1/routes/{route}/proxy
GET     /api/v1/routes/{route}/cache
PUT     /api/v1/routes/{route}/cache
POST    /api/v1/routes/{route}/cache/purge
GET     /api/v1/routes/{route}/health-check
PUT     /api/v1/routes/{route}/health-check
GET     /api/v1/routes/{route}/origins
POST    /api/v1/routes/{route}/origins
GET     /api/v1/routes/{route}/origins/{origin}
PUT     /api/v1/routes/{route}/origins/{origin}
DELETE  /api/v1/routes/{route}/origins/{origin}
```

Control Plane writes use strict JSON decoding, reject unknown fields and bodies larger than 4 MiB, validate the complete candidate, preserve a supplied `[REDACTED]` Admin token, create timestamped backups, and atomically replace the configuration file. Route and Origin lookup is case-insensitive; route names are immutable after creation so SecurityEdge policy identities cannot silently drift. A route must retain at least one Origin.

Hot-applicable routing, cache, health, and scheduler changes return `200 OK` and are installed without dropping traffic. Listener, TLS, Admin listener/auth/log-store, and process-timeout changes are persisted and return `202 Accepted`; the managed process coalesces pending work and performs an automatic graceful generation restart. Before a healthy generation is drained, EdgeProxy revalidates enabled TLS material and probes every newly claimed listener. A certificate that disappeared, an occupied port, or another unusable restart candidate is rejected, API writes are rolled back, and file-watcher errors are exposed without interrupting the active listeners. Listener sockets are also bound synchronously before a new generation is announced as started, so partial startup cannot leak one listener or report a false success. If a socket is claimed by another process in the narrow interval after preflight, EdgeProxy atomically restores the last successfully started configuration and retries that generation instead of terminating the managed process.

Invalid JSON or `.env` revisions never replace the last healthy runtime. Dotenv reload is transactional across parsing, environment overrides, an optional `EDGEPROXY_CONFIG` target switch, complete configuration validation, runtime application, and restart recovery; a rejected revision or a late restart failure restores the previous dotenv-managed environment exactly while preserving process/systemd-owned variables. `GET /api/v1/config/watch` reports watched files, revisions, the last apply mode/error, and pending restart state.

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

The test scripts load `apps/edgeproxy/.env` automatically and derive the data-plane target from the effective first route, listener port, and TLS setting. They preserve the configured route host while using curl `--connect-to` to reach the actual local listener, so component verification does not depend on public or local DNS resolution. Process environment variables take precedence; explicit `-ProxyUrl`, `-AdminUrl`, `-OriginUrl`, and `-Token` parameters override the derived values, and `-NoEnv` preserves an isolated JSON/default test. Use `-Insecure` only for an intentional development TLS certificate that is not trusted by the local machine. Wildcard listeners are contacted through the corresponding loopback family, explicitly bound hostnames/LAN IPs/IPv6 addresses are retained, and a listener configured with port `0` requires an explicit URL because its runtime port cannot be predicted. If the first route contains only wildcard host patterns, supply `-ProxyUrl` explicitly.

On POSIX systems, `scripts/demo.sh` is a small explicit-environment smoke test. It deliberately does not source `.env` as shell code. Export `EDGEPROXY_ADMIN_TOKEN` and override `PROXY_URL` or `ADMIN_URL` when the active deployment differs from the local defaults:

```sh
EDGEPROXY_ADMIN_TOKEN='replace-with-the-active-token' \
PROXY_URL='http://project.local:8080' \
ADMIN_URL='http://127.0.0.1:9090' \
bash ./scripts/demo.sh
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

The script reads `EDGEPROXY_ADMIN_TOKEN` from the process environment or `.env`, bypasses ambient system proxies for local/LAN control traffic, rejects invalid JSON before sending it, and fails on non-success HTTP responses. High-level actions cover Server/Admin sections, complete Route and Origin CRUD, cache enable/disable/TTL/purge, scheduler tuning, proxy/retry settings, health checks, and route/origin telemetry; `-BodyFile` and `-BodyJson` remain available for full structured updates. A field pinned by a non-empty `EDGEPROXY_*` runtime override returns a clear validation error and must be changed in the deployment environment instead.

## Linux systemd deployment

The supplied unit runs EdgeProxy as an unprivileged service without ambient Linux capabilities while preserving writable transactional configuration. Its integrated profile binds only loopback ports above `1024`; SecurityEdge owns the public native-HTTPS boundary on port `443` in the supplied systemd deployment. Commands below assume a release binary has already been built. Run them as `root` from `apps/edgeproxy` or adapt the source paths to your release directory.

Create the service account and install the binary, unit, secret environment, and initial active profile:

```sh
getent group edgeproxy >/dev/null || groupadd --system edgeproxy
id edgeproxy >/dev/null 2>&1 || \
  useradd --system --gid edgeproxy --home-dir /var/lib/edgeproxy \
    --shell /usr/sbin/nologin edgeproxy

install -o root -g root -m 0755 ./bin/edgeproxy /usr/local/bin/edgeproxy
install -o root -g root -m 0644 ./deploy/systemd/edgeproxy.service \
  /etc/systemd/system/edgeproxy.service
install -d -o root -g edgeproxy -m 0750 /etc/edgeproxy
install -o root -g edgeproxy -m 0640 ./deploy/systemd/edgeproxy.env.example \
  /etc/edgeproxy/edgeproxy.env
install -d -o edgeproxy -g edgeproxy -m 0750 /var/lib/edgeproxy
install -o edgeproxy -g edgeproxy -m 0640 \
  ./deploy/systemd/edgeproxy.json \
  /var/lib/edgeproxy/config.json
```

Replace the placeholder token in `/etc/edgeproxy/edgeproxy.env` before starting. Enable the service; startup validates the installed profile after applying the same environment overrides used at runtime:

```sh
systemctl daemon-reload
systemctl enable --now edgeproxy.service
systemctl status edgeproxy.service
journalctl -u edgeproxy.service -f
```

The active profile must remain in `/var/lib/edgeproxy`, not `/etc/edgeproxy`: Route and Origin CRUD, Dashboard changes, automatic reload, atomic rename, and timestamped backups all require write access to the containing directory. Secrets remain read-only in `/etc/edgeproxy/edgeproxy.env`.

The supplied systemd environment template intentionally contains only `EDGEPROXY_ADMIN_TOKEN`. Listener, TLS, trusted-proxy, Admin, Route, cache, health-check, retry, and scheduler settings remain in `/var/lib/edgeproxy/config.json`, so a successful Control Plane update remains authoritative after reload and restart. Adding the corresponding `EDGEPROXY_*` environment variables is supported for an intentional deployment lock. The Control Plane rejects changes to fields currently managed by an environment override instead of reporting a successful but ineffective update. Rotate `EDGEPROXY_ADMIN_TOKEN` in `/etc/edgeproxy/edgeproxy.env`, then restart EdgeProxy.

For the complete platform, SecurityEdge reads `/var/lib/edgeproxy/config.json` through membership in the `edgeproxy` supplementary group; keep the directory at `0750` and the active profile at `0640`. EdgeProxy remains the only writer. A standalone deployment that intentionally binds EdgeProxy below port `1024` must add `CAP_NET_BIND_SERVICE` to a local systemd override rather than granting it to the integrated deployment by default.

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

The Origin is available only inside the Compose network. Both services use read-only root filesystems, drop Linux capabilities, and enable `no-new-privileges`. Docker marks the EdgeProxy container healthy from the process-liveness `/healthz` endpoint; `/readyz` remains a separate operational signal and can become `503` when an Origin is unavailable without misclassifying the EdgeProxy process itself as dead.

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

For standalone production Docker operation on a fresh host or as part of the full private-network platform, use [`../../deployments/docker-production/README.md`](../../deployments/docker-production/README.md). It does not require the systemd deployment; optional migration is documented separately. The existing application Docker workflow remains the local/demo path.

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
