# SecurityEdge — WAF, Rate Limiting, and Operations Dashboard

This repository implements the **last two phases** of the bachelor's project:

- Phase 3: Web Application Firewall and rate limiting
- Phase 4: Security configuration UI and system monitoring dashboard

It is designed against the first two phases of the project repository (`EdgeProxy`) and consumes its existing routes, origins, Admin API, metrics schema, structured logs, health/readiness endpoints, and cache-purge endpoint. The EdgeProxy source is not modified by this repository.

## Final request order

```text
Client
  -> EdgeProxy route-compatible request classification
  -> SecurityEdge WAF and per-client rate limiting
  -> EdgeProxy reverse proxy
  -> EdgeProxy HTTP cache
  -> healthy origin selection
  -> origin server
```

The recommended final integration is the exported Go middleware (`securityedge.Runtime.Wrap`) so WAF inspection occurs before the EdgeProxy cache without losing the real client address. A standalone gateway mode is also provided for independent development and demonstration.

## Implemented security controls

- Deterministic request inspection with bounded regular-expression rules
- SQL injection, XSS, path traversal, command injection, CRLF injection, template injection, sensitive-file probing, and scanner identification
- Anomaly scoring with `block`, `log`, and `off` modes
- Per-route policy overrides using the exact route names from the EdgeProxy config
- Request body inspection only for configured media types and only up to a bounded byte limit
- Request body restoration so the downstream EdgeProxy/origin receives the original body
- Token-bucket rate limiting keyed by `route + client IP`
- IP allowlist and denylist support using individual IPs or CIDR ranges
- Allowed-method policy and excluded path prefixes
- Rule disabling per policy
- Correlated `X-Request-ID` propagation
- Metadata-only security logging; request bodies, cookies, authorization headers, and raw attack payloads are never retained

## Dashboard and administration

The self-contained dashboard has no Node.js or external CDN dependency. It provides:

- Combined EdgeProxy and SecurityEdge overview
- EdgeProxy requests, response latency, upstream latency, errors, retries, cache counters, and cache hit ratio
- Route readiness, origin health, cache entries/bytes/evictions
- Security detections, blocks, rate limits, top rules, and per-route counters
- Filterable and paginated SecurityEdge logs
- Recent EdgeProxy access logs through its Admin API
- Persistent default and per-route policy editing
- Cache purge through the original EdgeProxy endpoint
- Built-in rule catalog and dependency health

The browser authenticates to SecurityEdge. The EdgeProxy Admin token remains server-side and is never sent to browser JavaScript.

## Local run

Requirements: Go 1.23 or newer.

### 1. Start the demo origin from the EdgeProxy project

```powershell
go run ./cmd/origin-demo -listen 127.0.0.1:9000 -name origin-a
```

### 2. Start the EdgeProxy behind the WAF

From the EdgeProxy project directory:

```powershell
go run ./cmd/edgeproxy `
  -config ..\edgeproxy-go-second-member\integration\edgeproxy-local-behind-waf.json `
  -pretty-logs
```

This copy preserves all final first-member route/cache/health settings while binding the public proxy internally to `127.0.0.1:8080`. It does not change the first-member repository.

### 3. Start SecurityEdge

From this repository:

```powershell
go run ./cmd/securityedge -config .\configs\local-dev.json -pretty-logs
```

Public test endpoint:

```text
http://project.test:8081
```

Dashboard:

```text
http://127.0.0.1:9191
```

Dashboard token:

```text
dev-security-token
```

Add this hosts entry for local testing:

```text
127.0.0.1 project.test
```

## Tests

Clean request and cache:

```powershell
curl.exe -i http://project.test:8081/api/products
curl.exe -i http://project.test:8081/api/products
```

Expected:

```text
first request  -> X-Security-Action: ALLOW and X-Cache: MISS
second request -> X-Security-Action: ALLOW and X-Cache: HIT
```

Blocked XSS:

```powershell
curl.exe -i "http://project.test:8081/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

Expected status: `403 Forbidden` with `error.code = waf_blocked`.

Blocked SQL injection:

```powershell
curl.exe -i "http://project.test:8081/login?username=admin%27%20OR%201%3D1--"
```

## Admin API

SecurityEdge listener: `127.0.0.1:9191`

```text
GET     /healthz
GET     /readyz
GET     /api/v1/session
GET     /api/v1/status
GET     /api/v1/metrics
GET     /api/v1/logs
DELETE  /api/v1/logs
GET     /api/v1/rules
GET     /api/v1/policies
PUT     /api/v1/policies/default
PUT     /api/v1/policies/{route}
DELETE  /api/v1/policies/{route}
POST    /api/v1/reload
GET     /api/v1/dashboard/overview
GET     /api/v1/edgeproxy/status
GET     /api/v1/edgeproxy/metrics
GET     /api/v1/edgeproxy/logs
DELETE  /api/v1/edgeproxy/logs
POST    /api/v1/edgeproxy/cache/purge
```

Protected endpoints require:

```http
Authorization: Bearer <SecurityEdge admin token>
```

## Secret environment overrides

```powershell
$env:SECURITYEDGE_ADMIN_TOKEN = "replace-with-a-long-random-token"
$env:EDGEPROXY_ADMIN_TOKEN = "the-token-used-by-edgeproxy"
```

Environment values override JSON only in memory. Policy edits never persist environment-provided tokens back to disk.

## Build verification

```bash
gofmt -w .
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/securityedge
```

No third-party Go dependency is used.

## Important boundaries

- The built-in WAF is an educational deterministic rules engine, not a replacement for a continuously updated commercial managed WAF.
- Request bodies are bounded for inspection and are never stored in logs.
- Metrics and logs are process-local and reset on restart.
- Gateway mode is for independent development. Embedded middleware mode is the preferred final architecture because it preserves the original client connection metadata.
- The optional integration patch is provided under `integration/` but has not been applied to the uploaded first-member project.
