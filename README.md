# SecureEdge Platform

SecureEdge Platform is a modular, multi-module Go project that combines a high-performance reverse proxy and HTTP cache with an application-security gateway and operations dashboard.

The repository contains two independently executable applications:

- **[EdgeProxy](apps/edgeproxy/README.md)** — host/path routing, reverse proxying, origin health, retries, HTTP caching, access logs, metrics, and an authenticated Admin API.
- **[SecurityEdge](apps/securityedge/README.md)** — Web Application Firewall inspection, HTTP flood and overload controls, security telemetry, dependency monitoring, and an operations dashboard placed in front of EdgeProxy.

The active platform deployment uses **standalone non-embedded gateway mode**. SecurityEdge accepts public HTTP traffic, inspects and admits each request, and forwards accepted traffic to EdgeProxy over loopback.

## Architecture

```text
HTTP client
    │
    │ DNS or static host mapping
    ▼
SecurityEdge public ingress
    │  WAF inspection, rate limiting, admission control
    ▼
EdgeProxy loopback data plane
    │  routing, cache, health-aware origin selection
    ▼
Application origin
```

The administrative listeners remain local to the gateway host:

```text
SecurityEdge ingress       0.0.0.0:80       public in the LAN profile
EdgeProxy data plane       127.0.0.1:8080   internal only
EdgeProxy Admin API        127.0.0.1:9090   internal only
SecurityEdge dashboard     127.0.0.1:9191   local operations access
```

## Repository layout

```text
.
├── apps/
│   ├── edgeproxy/        # Reverse proxy, cache, health, logs, and metrics
│   └── securityedge/     # WAF, traffic protection, telemetry, and dashboard
├── integration/          # Shared EdgeProxy profiles used behind SecurityEdge
├── deployments/          # Platform deployment assets and notes
├── examples/             # Platform-level usage examples
├── scripts/              # Platform-level operational scripts
├── go.work               # Go workspace for both application modules
├── LICENSE
└── README.md
```

Each application has its own `go.mod`, tests, configuration files, scripts, Dockerfile, Makefile, and README.

## Requirements

- Go **1.23** or later
- Windows PowerShell for the supplied `.ps1` operational scripts
- `curl` or `curl.exe` for HTTP verification
- Docker only for the optional container workflows
- A DNS record or static host mapping for named LAN testing

No third-party Go module is required by either application.

## Quick start: local development

Run these commands from the **repository root** in separate terminals.

### 1. Start the demo Origin

```powershell
go run ./apps/edgeproxy/cmd/origin-demo `
  -listen 127.0.0.1:9000 `
  -name origin-local
```

### 2. Start EdgeProxy behind SecurityEdge

```powershell
go run ./apps/edgeproxy/cmd/edgeproxy `
  -config ./integration/edgeproxy-local-behind-waf.json `
  -pretty-logs
```

### 3. Start SecurityEdge

```powershell
go run ./apps/securityedge/cmd/securityedge `
  -config ./apps/securityedge/configs/local-dev.json `
  -pretty-logs
```

### 4. Send traffic through the complete stack

```powershell
curl.exe -i http://127.0.0.1:8081/api/products
curl.exe -i http://127.0.0.1:8081/api/products
```

Expected cache behavior:

```text
first request   X-Cache: MISS
second request  X-Cache: HIT
```

The local SecurityEdge dashboard is available at:

```text
http://127.0.0.1:9191
```

Local-development dashboard token:

```text
dev-security-token
```

## Reference LAN deployment

The checked-in reference profile uses the following lab values:

```text
Gateway host / DNS address    10.36.74.241
Origin host                   10.36.74.43:9000
Public hostnames              project.test, www.project.test
SecurityEdge Admin token      SecurityEdgeDemo2026
EdgeProxy Admin token         EdgeProxyDemo2026
```

These are demonstration settings, not hard-coded product requirements. Update the JSON profiles before using another network.

Run from the repository root.

### Origin host

```powershell
go run ./apps/edgeproxy/cmd/origin-demo `
  -listen 0.0.0.0:9000 `
  -name origin-a
```

### Gateway host: EdgeProxy

```powershell
go run ./apps/edgeproxy/cmd/edgeproxy `
  -config ./integration/edgeproxy-behind-waf.json `
  -pretty-logs
```

### Gateway host: SecurityEdge

```powershell
go run ./apps/securityedge/cmd/securityedge `
  -config ./apps/securityedge/configs/securityedge.json `
  -pretty-logs
```

Open the public hostname from any permitted HTTP client. Requests that reach SecurityEdge appear automatically in the **Recent Client Traffic** panel; no external reporting script is required.

## Configuration profiles

### EdgeProxy

| Profile | Purpose |
|---|---|
| `apps/edgeproxy/configs/local-dev.json` | EdgeProxy-only local development |
| `apps/edgeproxy/configs/edgeproxy.json` | EdgeProxy-only LAN demonstration |
| `integration/edgeproxy-local-behind-waf.json` | Local integrated deployment behind SecurityEdge |
| `integration/edgeproxy-behind-waf.json` | LAN integrated deployment behind SecurityEdge |
| `apps/edgeproxy/configs/compose.json` | EdgeProxy Docker Compose demonstration |

### SecurityEdge

| Profile | Purpose |
|---|---|
| `apps/securityedge/configs/local-dev.json` | Local gateway on `127.0.0.1:8081` |
| `apps/securityedge/configs/securityedge.json` | LAN gateway on `0.0.0.0:80` |
| `apps/securityedge/configs/embedded.json` | Optional future embedded integration profile |

See [integration/README.md](integration/README.md) for the shared deployment contract.

SecurityEdge log paths are relative to the process working directory. When SecurityEdge is started from the repository root as shown in this README, generated NDJSON logs are written under `./logs/`. When it is started from `apps/securityedge`, they are written under `apps/securityedge/logs/`. Both locations are ignored by the supplied `.gitignore`.

## Build and test

Because the repository is a Go workspace containing two modules, run explicit workspace package patterns from the root:

```powershell
go -C ./apps/edgeproxy fmt ./...
go -C ./apps/securityedge fmt ./...

go -C ./apps/edgeproxy vet ./...
go -C ./apps/securityedge vet ./...

go -C ./apps/edgeproxy test ./...
go -C ./apps/securityedge test ./...

go -C ./apps/edgeproxy test -race ./...
go -C ./apps/securityedge test -race ./...
```

Build both executables into a root-level `build` directory:

```powershell
New-Item -ItemType Directory -Force ./build | Out-Null

go build -trimpath -o ./build/edgeproxy ./apps/edgeproxy/cmd/edgeproxy
go build -trimpath -o ./build/origin-demo ./apps/edgeproxy/cmd/origin-demo
go build -trimpath -o ./build/securityedge ./apps/securityedge/cmd/securityedge
```

Validate the integrated profiles:

```powershell
go run ./apps/edgeproxy/cmd/edgeproxy `
  -config ./integration/edgeproxy-behind-waf.json `
  -validate

go run ./apps/securityedge/cmd/securityedge `
  -config ./apps/securityedge/configs/securityedge.json `
  -validate
```

> `go test ./...` from the repository root is not the correct command for this multi-module workspace. Use the explicit `./apps/edgeproxy/...` and `./apps/securityedge/...` patterns shown above.

## Docker

### EdgeProxy Compose demonstration

Run from the repository root:

```powershell
docker compose `
  -f ./apps/edgeproxy/docker-compose.yml `
  --project-directory ./apps/edgeproxy `
  up --build
```

### SecurityEdge image

SecurityEdge's Dockerfile requires the repository root as its build context because it copies both the SecurityEdge application and the root-level `integration` directory:

```powershell
docker build `
  -f ./apps/securityedge/Dockerfile `
  -t securityedge:3.3.0 `
  .
```

The repository does not currently include a complete multi-container Compose deployment for the full platform. A containerized runtime must provide SecurityEdge with an EdgeProxy endpoint reachable from its container network.

## Administrative credentials

The two tokens are intentionally separate:

```text
SecurityEdge Admin UI/API token  authenticates dashboard and SecurityEdge API users
EdgeProxy Admin API token        authenticates SecurityEdge-to-EdgeProxy control-plane calls
```

For non-demonstration environments, do not rely on committed example values:

```powershell
$env:SECURITYEDGE_ADMIN_TOKEN = "<strong-random-token>"
$env:EDGEPROXY_ADMIN_TOKEN = "<matching-edgeproxy-token>"
```

Environment variables override the JSON values.

## Security boundaries

- Only SecurityEdge should expose the public HTTP ingress in the integrated deployment.
- EdgeProxy data and Admin listeners should remain bound to loopback.
- The SecurityEdge dashboard should remain bound to loopback unless protected by an additional trusted access layer.
- The Origin should accept its application port only from the gateway host.
- Runtime logs, `.env` files, generated binaries, and real secrets must not be committed.
- SecurityEdge provides application-layer HTTP protection; volumetric network-layer attacks still require firewall, CDN, load-balancer, or provider-side mitigation.

## Component documentation

- [EdgeProxy documentation](apps/edgeproxy/README.md)
- [SecurityEdge documentation](apps/securityedge/README.md)
- [Integration contract](integration/README.md)

## License

This project is licensed under the terms in [LICENSE](LICENSE).
