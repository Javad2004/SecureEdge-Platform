# EdgeProxy Go — Reverse Proxy and HTTP Cache

This repository is the implementation of **Phases 1 and 2** of the bachelor’s project:

> Design and Implementation of a Web Application Firewall Featuring Reverse Proxy, Caching, and Web Security Mechanisms Using Go

The first two phases are a deployable edge proxy that receives real client traffic, forwards it to one or more origin servers, caches eligible HTTP responses, exposes operational metrics, and provides a stable integration boundary for the later WAF and dashboard phases.

## Implemented scope

### Phase 1 — Reverse Proxy and Traffic Management

- Real HTTP reverse proxy between a client device and an origin-server device
- Host- and path-based routing
- Multiple upstreams with round-robin selection
- Active upstream health checks
- Connection pooling and HTTP/2 support toward HTTPS origins
- Configurable request, dial, response-header, idle, and shutdown timeouts
- Retry for idempotent requests on network failures and 502/503/504 responses
- Standard forwarding headers: `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`
- Request correlation through `X-Request-ID`
- Hop-by-hop header removal
- Graceful shutdown
- Structured JSON request logs plus a bounded, filterable in-memory Admin Log API
- Optional inbound TLS termination

### Phase 2 — HTTP Caching and Performance Optimization

- Thread-safe in-memory LRU cache
- Entry-count, total-byte, and per-object size limits
- TTL from `Cache-Control: s-maxage`, `max-age`, or `Expires`
- Configurable default TTL
- `no-store`, `private`, `Authorization`, `Cookie`, and `Set-Cookie` safety rules
- Safe handling of `Vary`: responses are cached only when every varied header is included in the configured cache key
- Cache keys based on method, canonical host, URI, and configured request headers
- Range requests are bypassed to prevent partial-response cache poisoning
- `X-Cache: HIT`, `MISS`, `BYPASS`, or `STALE`
- `Age` response header
- Conditional cache responses with `If-None-Match` and `If-Modified-Since`
- Cache-stampede prevention by serializing fills per cache key
- Stale-if-error fallback when the origin is unavailable
- Cache purge API
- Professional global, per-route, and per-origin metrics for the later dashboard phase

## Three-device deployment model

```text
Client device
    |
    |  project.local resolves to Proxy-IP
    v
Proxy device (Go application, public port 80 in `edgeproxy.json`; admin port 9090)
    |
    v
Origin device (demo or real web application, port 9000)
```

Example addresses:

```text
Client:  192.168.1.5
Proxy:   192.168.1.10
Origin:  192.168.1.20
```

On the client, add this hosts-file entry:

```text
192.168.1.10 project.local
```

In `configs/edgeproxy.json`, set the upstream URL to:

```json
"url": "http://192.168.1.20:9000"
```

## Quick local run

Terminal 1:

```bash
go run ./cmd/origin-demo -listen :9000 -name origin-a
```

Terminal 2:

```bash
go run ./cmd/edgeproxy -config configs/local-dev.json -pretty-logs
```

Add to the local hosts file:

```text
127.0.0.1 project.local
```

Then test:

```bash
curl -i http://project.local:8080/api/products
curl -i http://project.local:8080/api/products
curl -i http://project.local:8080/api/time
```

The first `/api/products` response should show `X-Cache: MISS`; the second should show `X-Cache: HIT`. `/api/time` always uses `Cache-Control: no-store` and should show `X-Cache: BYPASS`.

## Admin, metrics, and logs API

The admin server is deliberately separated from the public proxy listener. Protect it with a strong token and firewall rules. Metrics are available globally, per route, and independently for every origin. Recent structured events are kept in a bounded in-memory ring buffer and can be filtered by route, origin, request ID, event, status, cache result, time range, and duration.

```bash
curl -H "Authorization: Bearer dev-token" \
  http://127.0.0.1:9090/api/v1/metrics

curl -H "Authorization: Bearer dev-token" \
  http://127.0.0.1:9090/api/v1/status

curl -H "Authorization: Bearer dev-token" \
  "http://127.0.0.1:9090/api/v1/logs?limit=100"

curl -H "Authorization: Bearer dev-token" \
  "http://127.0.0.1:9090/api/v1/logs?event=upstream_attempt&status=5xx"
```

Purge all cache entries for a route:

```bash
curl -X POST -H "Authorization: Bearer dev-token" \
  "http://127.0.0.1:9090/api/v1/cache/purge?route=demo-app"
```

Purge only a host/path prefix:

```bash
curl -X POST -H "Authorization: Bearer dev-token" \
  "http://127.0.0.1:9090/api/v1/cache/purge?route=demo-app&host=project.local&path_prefix=/api/products"
```

## Build and test

```bash
make fmt
make vet
make test
make build
```

No third-party Go dependency is required.

## Docker demonstration

```bash
docker compose up --build
```

Then add `127.0.0.1 project.local` and access `http://project.local:8080` for the Docker/local-development configuration. The three-device `configs/edgeproxy.json` uses standard HTTP port 80.


