# SecurityEdge

SecurityEdge is the application-security gateway and operations component of the [SecureEdge Platform](../../README.md). It runs in front of [EdgeProxy](../edgeproxy/README.md), inspects incoming HTTP requests, enforces traffic policies, records security telemetry, and exposes an authenticated dashboard and Admin API.

This README assumes commands are executed from:

```text
apps/securityedge
```

The active deployment mode is **standalone non-embedded gateway mode**. EdgeProxy remains an independently executable application and its source code is not modified.

## Architecture

```text
HTTP client
    │
    │ public request
    ▼
SecurityEdge ingress
    │  WAF inspection
    │  request-size and protocol controls
    │  per-client and global rate limiting
    │  concurrency admission and temporary bans
    ▼
EdgeProxy loopback data plane
    │  routing, cache, origin selection, retries
    ▼
Application origin
```

SecurityEdge also calls the EdgeProxy Admin API over loopback to obtain routes, origin health, cache metrics, access logs, and readiness information for its operations dashboard.

## Main capabilities

### Web Application Firewall

- deterministic RE2-based rules;
- configurable anomaly scoring;
- `block`, `log`, and `off` policy modes;
- route-specific and default policies;
- path, query, header, cookie, JSON, form, XML, and text-body inspection;
- multi-stage URL and HTML-entity normalization;
- SQL injection, XSS, path traversal, command injection, SSRF, XXE, NoSQL injection, LDAP injection, CRLF injection, template injection, Log4Shell/JNDI, PHP wrapper, sensitive-file, scanner, and reconnaissance detection;
- validated custom rules;
- method, path, query, header, content-type, content-encoding, and body-size limits;
- IP allowlists and denylists;
- bounded inspection and fail-closed options.

### HTTP flood and overload protection

- per-client token-bucket rate limits;
- route-wide global rate limits;
- global and per-client concurrency limits;
- bounded limiter state;
- adaptive temporary bans;
- trusted-proxy-aware client IP resolution and verified propagation to EdgeProxy and the Origin;
- spoof-resistant forwarded-address handling;
- upstream and server timeouts.

SecurityEdge provides application-layer HTTP protection. SYN floods, UDP floods, link saturation, and other volumetric network-layer attacks require firewall, CDN, load-balancer, or provider-side controls.

### Operations and observability

- responsive authenticated dashboard;
- SecurityEdge metrics and Prometheus exposition;
- WAF and admission-control event browsing;
- recent privacy-safe client traffic telemetry;
- dependency monitoring for DNS, SecurityEdge ingress, EdgeProxy data plane, EdgeProxy Admin API, route readiness, and Origin health;
- EdgeProxy metrics, logs, and cache purge through a backend-for-frontend;
- policy editing with validation and atomic persistence;
- temporary-ban management;
- CSV and NDJSON event exports;
- bounded dependency transition history.

## Configuration profiles

| Configuration | SecurityEdge ingress | EdgeProxy profile | Purpose |
|---|---:|---|---|
| `configs/local-dev.json` | `127.0.0.1:8081` | `../../integration/edgeproxy-local-behind-waf.json` | Local integrated development |
| `configs/securityedge.json` | `0.0.0.0:80` | `../../integration/edgeproxy-behind-waf.json` | Reference LAN deployment |
| `configs/embedded.json` | no standalone ingress | local integration profile | Optional future embedded mode |
| `configs/compose.json` | `0.0.0.0:8081` | `../../integration/edgeproxy-compose-behind-waf.json` | Full-platform Docker Compose deployment |

The JSON value stored in `edgeproxy.config_path` is resolved relative to the SecurityEdge configuration file, not relative to the shell's current directory. The checked-in values therefore use `../../../integration/...` internally and correctly resolve to the repository-level `integration` directory.

## Quick start: local integrated development

Run all commands below from `apps/securityedge` in separate terminals.

### 1. Start the demo Origin

```powershell
go run ../edgeproxy/cmd/origin-demo `
  -listen 127.0.0.1:9000 `
  -name origin-local
```

### 2. Start EdgeProxy

```powershell
go run ../edgeproxy/cmd/edgeproxy `
  -config ../../integration/edgeproxy-local-behind-waf.json `
  -pretty-logs
```

### 3. Start SecurityEdge

```powershell
go run ./cmd/securityedge `
  -config ./configs/local-dev.json `
  -pretty-logs
```

### 4. Send requests through SecurityEdge

```powershell
curl.exe -i http://127.0.0.1:8081/api/products
curl.exe -i http://127.0.0.1:8081/api/products
```

Expected cache behavior from EdgeProxy:

```text
first request   X-Cache: MISS
second request  X-Cache: HIT
```

Test a blocked XSS request:

```powershell
curl.exe -i "http://127.0.0.1:8081/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

Expected status:

```text
403 Forbidden
```

### Local dashboard

```text
URL:    http://127.0.0.1:9191
Token:  dev-security-token
```

## Reference LAN deployment

The supplied LAN profile uses:

```text
SecurityEdge ingress       0.0.0.0:80
EdgeProxy data plane       127.0.0.1:8080
EdgeProxy Admin API        127.0.0.1:9090
SecurityEdge dashboard     127.0.0.1:9191
DNS resolver endpoint      10.36.74.241:53
Origin                     10.36.74.43:9000
Public hostnames           project.test, www.project.test
```

Update the configuration when the gateway address, Origin address, hostnames, or DNS service changes.

Run from `apps/securityedge`.

### Origin host

```powershell
go run ../edgeproxy/cmd/origin-demo `
  -listen 0.0.0.0:9000 `
  -name origin-a
```

### Gateway host: EdgeProxy

```powershell
go run ../edgeproxy/cmd/edgeproxy `
  -config ../../integration/edgeproxy-behind-waf.json `
  -pretty-logs
```

### Gateway host: SecurityEdge

```powershell
go run ./cmd/securityedge `
  -config ./configs/securityedge.json `
  -pretty-logs
```

### Dashboard credentials

```text
SecurityEdge dashboard token   SecurityEdgeDemo2026
EdgeProxy Admin API token      EdgeProxyDemo2026
```

The dashboard token is entered by the operator. The EdgeProxy token is used only by the SecurityEdge backend and is not exposed to browser JavaScript.

## Expected listener exposure

```text
0.0.0.0:80       public SecurityEdge ingress
127.0.0.1:8080   internal EdgeProxy data plane
127.0.0.1:9090   internal EdgeProxy Admin API
127.0.0.1:9191   local SecurityEdge dashboard and Admin API
```

The Origin should permit its application port only from the gateway host. Untrusted clients should not connect directly to EdgeProxy, either Admin API, or the Origin port.

SecurityEdge connects to the configured EdgeProxy data plane directly and does not inherit ambient `HTTP_PROXY` or `HTTPS_PROXY` settings. This prevents internal application traffic from being redirected through an unrelated host-level proxy.

## Dashboard behavior

The Overview page separates service health from traffic activity.

### Service Health & Dependencies

The health topology contains only dependencies that SecurityEdge can actively inspect:

```text
DNS Resolution → SecurityEdge → EdgeProxy → Routes → Origins
```

The dashboard reports component status, probe latency, HTTP status, last success or failure, consecutive failures, route readiness, Origin health, and transition history.

### Recent Client Traffic

This panel is updated by real requests that reach SecurityEdge. It can show:

- last request time;
- privacy-safe client IP metadata;
- HTTP method and sanitized path;
- selected route;
- `ALLOW` or `BLOCK` decision;
- downstream HTTP status;
- response duration;
- EdgeProxy cache result;
- request and unique-client counts within the bounded recent window.

No external acceptance-test reporter is required. No recent traffic is informational and does not make service health degraded or down.

## Authentication and secrets

For non-demonstration environments, override both example credentials:

```powershell
$env:SECURITYEDGE_ADMIN_TOKEN = "<strong-random-token>"
$env:EDGEPROXY_ADMIN_TOKEN = "<matching-edgeproxy-token>"
```

Generate a SecurityEdge token:

```powershell
.\scripts\generate-admin-token.ps1
```

Environment variables take precedence over JSON values.

Repeated invalid Admin authentication attempts are rate-limited and can trigger a temporary in-memory lockout according to the selected profile.

## Admin API

The Admin listener provides the dashboard plus these endpoints.

Unauthenticated process endpoints:

```text
GET /healthz
GET /readyz
```

Authenticated SecurityEdge endpoints:

```text
GET     /api/v1/session
GET     /api/v1/status
GET     /api/v1/info
GET     /api/v1/metrics
GET     /api/v1/metrics/prometheus
GET     /api/v1/logs
DELETE  /api/v1/logs
GET     /api/v1/logs/export
GET     /api/v1/rules
GET     /api/v1/policies
PUT     /api/v1/policies/default
PUT     /api/v1/policies/{route}
DELETE  /api/v1/policies/{route}
POST    /api/v1/reload
GET     /api/v1/bans
DELETE  /api/v1/bans/{client}
DELETE  /api/v1/bans
GET     /api/v1/dashboard/overview
GET     /api/v1/traffic/recent
GET     /api/v1/connectivity
POST    /api/v1/connectivity/check
```

`DELETE /api/v1/logs` clears the in-memory event ring, truncates the active NDJSON log, and removes rotated backups. CSV exports neutralize spreadsheet-formula prefixes in user-controlled fields before writing rows.

### Live reload boundaries

`POST /api/v1/reload` validates the complete configuration before changing the live runtime. It can apply security policies, WAF custom rules, trusted-proxy lists, route metadata, and EdgeProxy Admin connectivity without interrupting traffic.

Settings owned by already-running listeners or long-lived process resources require a SecurityEdge restart. This includes listener addresses and HTTP timeouts, the upstream data-plane URL and transport, Admin listener/authentication/log-store settings, and the process-wide rate-limiter cleanup lifecycle. When one of these values changes, the reload endpoint returns `409 Conflict` with the `restart_required` error code instead of reporting a partial success.

Dashboard policy updates are prepared before the configuration file is replaced. A validation or reload-preparation failure therefore leaves both the persisted file and the active runtime unchanged.

Authenticated EdgeProxy backend-for-frontend endpoints:

```text
GET     /api/v1/edgeproxy/status
GET     /api/v1/edgeproxy/metrics
GET     /api/v1/edgeproxy/logs
DELETE  /api/v1/edgeproxy/logs
POST    /api/v1/edgeproxy/cache/purge
```

Example:

```powershell
$AdminUrl = "http://127.0.0.1:9191"
$Token = "dev-security-token"
$Headers = @{ Authorization = "Bearer $Token" }

Invoke-RestMethod "$AdminUrl/api/v1/dashboard/overview" -Headers $Headers
```

## Operational scripts

Run from `apps/securityedge`.

Validate listener exposure:

```powershell
.\scripts\check-listeners.ps1 -Config ./configs/securityedge.json
```

Force dependency checks:

```powershell
.\scripts\check-connectivity.ps1 -Force
```

Validate the complete LAN deployment:

```powershell
.\scripts\test-deployment.ps1 `
  -Config ./configs/securityedge.json
```

Run protection tests:

```powershell
.\scripts\test-protection.ps1
```

Start with validation:

```powershell
.\scripts\start-security.ps1 `
  -Config ./configs/securityedge.json
```

Preview or create Windows Firewall rules for the public SecurityEdge ingress:

```powershell
.\scripts\setup-proxy-firewall.ps1 `
  -Config ./configs/securityedge.json

.\scripts\setup-proxy-firewall.ps1 `
  -Config ./configs/securityedge.json `
  -Apply
```

The firewall script intentionally does not expose EdgeProxy or Admin ports.

## Build and verification

```powershell
go fmt ./...

go vet ./...
go test ./...
go test -race ./...

node --check ./internal/admin/web/app.js

go build -trimpath -o ./bin/securityedge ./cmd/securityedge
```

Validate configurations:

```powershell
go run ./cmd/securityedge -config ./configs/local-dev.json -validate
go run ./cmd/securityedge -config ./configs/securityedge.json -validate
go run ./cmd/securityedge -config ./configs/embedded.json -validate
go run ./cmd/securityedge -config ./configs/compose.json -validate
```

Makefile targets:

```powershell
make fmt
make test
make race
make vet
make js
make build
make validate
make validate-network
make verify
```

## Docker

### Build the SecurityEdge image

The Dockerfile copies files from both `apps/securityedge` and the repository-level `integration` directory. Commands in this README start from `apps/securityedge`, so the build context must be the repository root (`../..`):

```powershell
docker build `
  -f ./Dockerfile `
  -t securityedge:latest `
  ../..
```

The image uses `/app/config/securityedge.json`, initialized from `configs/compose.json`. Its container-specific settings are:

```text
SecurityEdge ingress       0.0.0.0:8081
SecurityEdge Admin API     0.0.0.0:9191
EdgeProxy data plane       http://edgeproxy:8080
EdgeProxy Admin API        http://edgeproxy:9090
EdgeProxy route profile    /integration/edgeproxy-compose-behind-waf.json
```

The `/app/config` and `/app/logs` paths are writable volumes owned by the non-root application user. This allows dashboard policy changes to be atomically persisted and allows rotated NDJSON logs to survive container recreation. Real credentials should be injected through `SECURITYEDGE_ADMIN_TOKEN` and `EDGEPROXY_ADMIN_TOKEN`.

The image is designed to participate in a container network with services named `edgeproxy` and `origin`; running it alone will not provide a reachable upstream.

### Run the complete platform

From `apps/securityedge`:

```powershell
docker compose `
  -f ../../deployments/docker/compose.yml `
  up --build
```

Optional environment overrides can be loaded with:

```powershell
Copy-Item ../../deployments/docker/.env.example ../../deployments/docker/.env

docker compose `
  --env-file ../../deployments/docker/.env `
  -f ../../deployments/docker/compose.yml `
  up --build
```

The full stack publishes:

```text
SecurityEdge ingress    http://127.0.0.1:8081
SecurityEdge dashboard  http://127.0.0.1:9191
```

EdgeProxy and the Origin remain internal to the Docker network, preventing direct host-side bypass of SecurityEdge.

To reset persisted policy configuration and logs:

```powershell
docker compose `
  -f ../../deployments/docker/compose.yml `
  down -v
```

See [../../deployments/docker/README.md](../../deployments/docker/README.md) for service topology, volumes, ports, and credential overrides.

## Privacy and log handling

SecurityEdge avoids retaining raw sensitive attack payloads in recent-traffic telemetry. Security events use bounded in-memory storage and optional NDJSON persistence with rotation.

Generated files under `logs/` are runtime artifacts and must not be committed. Keep only `logs/.gitkeep` in source control.

## Embedded mode

`configs/embedded.json` and [`../../integration/edgeproxy-embedded-integration.patch`](../../integration/edgeproxy-embedded-integration.patch) document an optional future mode in which SecurityEdge wraps the EdgeProxy handler in-process.

This mode is not required by the current deployment and the patch is not applied to the active EdgeProxy source tree. The supported demonstration path remains standalone non-embedded gateway mode.

## Related documentation

- [SecureEdge Platform](../../README.md)
- [EdgeProxy](../edgeproxy/README.md)
- [Platform integration](../../integration/README.md)

## License

See [../../LICENSE](../../LICENSE).
