# SecurityEdge

SecurityEdge is an independent application-security gateway and operations console designed to run in front of EdgeProxy. It provides Web Application Firewall inspection, layered HTTP traffic protection, security event logging, policy management, dependency monitoring, and a backend-for-frontend for the EdgeProxy Admin API.

The active deployment mode is **standalone non-embedded gateway mode**. The EdgeProxy source tree is not modified.

## Product architecture

```text
External client
    │
    │ DNS resolution
    ▼
SecurityEdge public ingress
    │
    │ inspected and admitted HTTP traffic
    ▼
EdgeProxy loopback data plane
    │
    │ route matching, cache, origin selection
    ▼
Application origin
```

Clients may be browsers, mobile or desktop applications, API tools, services, or other HTTP endpoints. Name resolution may be provided by any standards-compliant resolver or a controlled static host mapping. These deployment choices are deliberately kept out of the product-level UI.

## Reference deployment profile

The included `configs/securityedge.json` and integration files target the current lab profile:

```text
SecurityEdge ingress       0.0.0.0:80
EdgeProxy data plane       127.0.0.1:8080
EdgeProxy Admin API        127.0.0.1:9090
SecurityEdge Admin UI      127.0.0.1:9191
DNS resolver endpoint      10.36.74.241:53
Origin                     10.36.74.43:9000
```

The names `project.test` and `www.project.test` are expected to resolve to `10.36.74.241`. These values are deployment settings, not product assumptions, and can be changed in configuration.

## Main capabilities

### Application-layer security

- deterministic RE2-based WAF rules;
- anomaly scoring and block/log/off modes;
- inspection of path, query, headers, cookies, JSON, form, XML, and text bodies;
- multi-stage URL and HTML entity normalization;
- SQL injection, XSS, traversal, command injection, SSRF, XXE, NoSQLi, LDAP injection, CRLF, template injection, Log4Shell, PHP wrapper, sensitive-file, scanner, and reconnaissance detection;
- custom validated rules;
- bounded body inspection and fail-closed options;
- method, path, query, header, body, content-encoding, and content-type controls;
- IP allowlists and denylists.

### HTTP flood and overload mitigation

- per-client token-bucket rate limits;
- route-wide global token-bucket limits;
- global and per-client concurrency admission limits;
- bounded rate-limit state;
- adaptive temporary bans;
- trusted-proxy-aware client identity resolution;
- spoof-resistant forwarded-address handling;
- server and upstream transport timeouts.

This is application-layer protection. Network-layer attacks such as SYN flood, UDP flood, and upstream bandwidth exhaustion require firewall, load-balancer, CDN, or provider-side mitigation.

### Operations dashboard

The authenticated console is served at `http://127.0.0.1:9191` in the reference profile. Its Overview starts with **Service Health & Dependencies**, which distinguishes:

- server-side DNS resolution;
- SecurityEdge ingress health;
- EdgeProxy TCP and HTTP data-plane connectivity;
- EdgeProxy Admin API health and readiness;
- route readiness;
- origin health;
- metrics and cache observability.

A separate **Recent Client Traffic** panel is driven by requests that actually reach the SecurityEdge ingress. It shows the latest bounded request metadata, recent request volume, unique clients, policy decision, downstream HTTP status, and cache result. No external reporting test is required, and inactivity is shown as informational rather than as a service failure.

The console also includes:

- SecurityEdge and EdgeProxy metrics;
- cache counters and cache purge;
- route and origin status;
- EdgeProxy access logs;
- WAF and admission-control events;
- temporary-ban management;
- policy editing with validation and atomic persistence;
- CSV and NDJSON exports;
- Prometheus exposition;
- bounded status-transition history.

## Authentication

Two credentials have separate purposes:

```text
SecurityEdge Admin UI/API token: SecurityEdgeDemo2026
EdgeProxy Admin API token:       EdgeProxyDemo2026
```

The first token is entered in the dashboard login. The second is used only by the SecurityEdge backend and is never sent to browser JavaScript.

For non-lab use, set secrets through environment variables:

```powershell
$env:SECURITYEDGE_ADMIN_TOKEN = "<strong-random-token>"
$env:EDGEPROXY_ADMIN_TOKEN = "<matching-edgeproxy-token>"
```

Generate a random SecurityEdge token with:

```powershell
.\scripts\generate-admin-token.ps1
```

## Running the reference deployment

### 1. Start the Origin

From the EdgeProxy repository on the Origin host:

```powershell
go run ./cmd/origin-demo `
  -listen 0.0.0.0:9000 `
  -name origin-a
```

### 2. Start EdgeProxy

From the EdgeProxy repository on the gateway host:

```powershell
go run ./cmd/edgeproxy `
  -config ..\securityedge\integration\edgeproxy-behind-waf.json `
  -pretty-logs
```

### 3. Start SecurityEdge

From this repository on the same gateway host:

```powershell
go run ./cmd/securityedge `
  -config .\configs\securityedge.json `
  -pretty-logs
```

### 4. Validate

```powershell
.\scripts\check-listeners.ps1
.\scripts\check-connectivity.ps1 -Force
.\scripts\test-deployment.ps1 -Config .\configs\securityedge.json
```

To verify a client path, simply send a normal request to the public hostname. When it reaches SecurityEdge, the **Recent Client Traffic** panel updates automatically. No client-side reporting script is required.

## Expected listener exposure

```text
0.0.0.0:80       public SecurityEdge ingress
127.0.0.1:8080   internal EdgeProxy data plane
127.0.0.1:9090   internal EdgeProxy Admin API
127.0.0.1:9191   local SecurityEdge operations console
```

The Origin should permit TCP/9000 only from the gateway host. Untrusted clients should not be able to connect directly to ports 8080, 9090, 9191, or the Origin port.

## Useful commands

```powershell
# Validate configuration
go run ./cmd/securityedge -config .\configs\securityedge.json -validate

# Run all tests
go test ./...
go test -race ./...
go vet ./...

# Force dependency probes
.\scripts\check-connectivity.ps1 -Force

# Run security tests
.\scripts\test-protection.ps1

# Build
make build
```

## Embedded mode

`configs/embedded.json` and `integration/edgeproxy-embedded-integration.patch` are retained as an optional future integration path. They are not required for the active standalone deployment and have not been applied to the EdgeProxy project.
