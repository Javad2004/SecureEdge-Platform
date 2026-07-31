# EdgeProxy Go — Reverse Proxy, Load Balancer, HTTP Cache, and Observability

This repository implements the first two phases of the bachelor's project:

> Design and Implementation of a Web Application Firewall Featuring Reverse Proxy, Caching, and Web Security Mechanisms Using Go

The code in this repository covers **Phase 1 (reverse proxy and traffic management)** and **Phase 2 (HTTP caching and performance optimization)**. The WAF and graphical dashboard remain separate later phases.

## What is implemented

### Reverse proxy and traffic management

- Real HTTP reverse proxy between client and origin devices
- Host- and path-based routing for multiple websites and APIs
- Exact-host, wildcard-host, and longest-path route precedence
- Multiple origins per route with round-robin load balancing
- Active health checks and route-level readiness
- Retry of replayable idempotent requests on transport failures and 502/503/504 responses
- Connection pooling and optional HTTPS connections to origins
- Forwarding headers: `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`
- Correlated requests through `X-Request-ID`
- Hop-by-hop header removal
- Graceful shutdown of proxy, admin server, and demo origin
- Optional inbound TLS termination

### HTTP cache

- Thread-safe in-memory LRU cache
- Entry-count, total-byte, and per-object limits
- TTL from `s-maxage`, `max-age`, or `Expires`
- Safe bypass rules for `no-store`, `private`, Authorization, Cookie, Set-Cookie, Range, and unsupported `Vary`
- Cache keys based on method, canonical host, URI, and configured request headers
- `X-Cache: HIT`, `MISS`, `BYPASS`, or `STALE`
- `Age` header and conditional 304 responses
- Cache-stampede prevention with per-key locking
- Stale-if-error fallback
- Route/host/path cache purge API

### Observability and administration

- Global, per-route, and per-origin metrics
- Request, status-code, cache, retry, timeout, byte, and latency statistics
- Histogram-based P50/P95/P99 latency estimates
- Bounded thread-safe in-memory log ring buffer
- Correlated request, origin-attempt, health-change, and cache-purge events
- Filtering, time ranges, pagination, and sensitive query-value redaction
- Separate admin listener protected by Bearer token
- `EDGEPROXY_ADMIN_TOKEN` environment override for deployments

## Active three-device configuration

`configs/edgeproxy.json` is the current Windows/LAN demonstration configuration:

```text
Phone or client
    |
    | DNS: project.test -> Proxy IP
    | HTTP port 80
    v
EdgeProxy device
    | public: 0.0.0.0:80
    | admin:  127.0.0.1:9090
    v
Origin device
    | http://10.36.74.43:9000
```

Supported hosts in that file include:

```text
project.local
project.test
www.project.test
localhost
127.0.0.1
```

Change the upstream URL when the Origin IP changes.

## Run the three-device configuration

On the Origin device:

```powershell
go run ./cmd/origin-demo -listen 0.0.0.0:9000 -name origin-a
```

On the Proxy device:

```powershell
go run ./cmd/edgeproxy -config .\configs\edgeproxy.json -validate
go run ./cmd/edgeproxy -config .\configs\edgeproxy.json -pretty-logs
```

From the client:

```text
http://project.test
http://project.test/api/products
```

For a reliable cache test, send two ordinary requests rather than browser refresh requests:

```bash
curl -i http://project.test/api/products
curl -i http://project.test/api/products
```

Expected result:

```text
first request  -> X-Cache: MISS
second request -> X-Cache: HIT
```

## Local development on one computer

`configs/local-dev.json` intentionally uses port `8080` and token `dev-token`:

```bash
go run ./cmd/origin-demo -listen :9000 -name origin-a
go run ./cmd/edgeproxy -config configs/local-dev.json -pretty-logs
```

Add `127.0.0.1 project.local` to the local hosts file and test:

```bash
curl -i http://project.local:8080/api/products
```

## Admin API

The active three-device configuration binds the admin listener to loopback only. Run these commands on the Proxy device:

```powershell
$AdminUrl = "http://127.0.0.1:9090"
$Token = "EdgeProxyDemo2026"
$Auth = "Authorization: Bearer $Token"
```

Endpoints:

```text
GET     /healthz
GET     /readyz
GET     /api/v1/status
GET     /api/v1/metrics
GET     /api/v1/logs
DELETE  /api/v1/logs
POST    /api/v1/cache/purge
```

Examples:

```powershell
curl.exe -i "$AdminUrl/healthz"
curl.exe -i "$AdminUrl/readyz"
curl.exe -s -H $Auth "$AdminUrl/api/v1/status"
curl.exe -s -H $Auth "$AdminUrl/api/v1/metrics"
curl.exe -s -H $Auth "$AdminUrl/api/v1/logs?limit=100"
```

`/healthz` is process liveness. `/readyz` returns `503 Service Unavailable` when any route has no healthy origin.

Purge one route's cache:

```powershell
curl.exe -X POST -H $Auth `
  "$AdminUrl/api/v1/cache/purge?route=demo-app"
```

## Admin-token environment override

The environment variable takes precedence over the JSON value:

```powershell
$env:EDGEPROXY_ADMIN_TOKEN = "replace-with-a-long-random-token"
go run ./cmd/edgeproxy -config .\configs\edgeproxy.json -pretty-logs
```

This is preferable for non-demo deployments because the real token does not need to be committed to the repository.

## Multiple origins and routes

Ready-to-copy examples are provided in:

```text
configs/examples/multi-origin.json
configs/examples/multi-route.json
```

Each route has independent hosts, path prefix, origin pool, health state, cache, metrics, and filterable logs.

## Build and verification

```bash
gofmt -w ./cmd ./internal
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/edgeproxy
go build ./cmd/origin-demo
```

No third-party Go dependency is required.

## Docker

The container runs as a non-root user and therefore uses internal port `8080`:

```bash
docker compose up --build
```

Then access:

```text
http://project.local:8080
```

The admin port is published only on host loopback:

```text
127.0.0.1:9090
```