# SecureEdge Platform

SecureEdge Platform is a modular, multi-module Go project that combines a high-performance reverse proxy and HTTP cache with an application-security gateway and operations dashboard.

The repository contains two independently executable applications:

- **[EdgeProxy](apps/edgeproxy/README.md)** — host/path routing, six per-route load-balancing algorithms, health-aware failover, reverse proxying, HTTP caching, detailed telemetry, automatic reload/restart, and a transactional Admin Control Plane.
- **[SecurityEdge](apps/securityedge/README.md)** — Web Application Firewall inspection, HTTP flood and overload controls, security telemetry, independent configuration watchers, and an authenticated operations/control dashboard placed in front of EdgeProxy.

The active runtime model uses **standalone non-embedded gateway mode**. SecurityEdge accepts public HTTP traffic, inspects and admits each request, and forwards accepted traffic to EdgeProxy over loopback in host deployments or over a private service network in Docker Compose.

SecurityEdge resolves the original client address using an explicit trusted-proxy policy and forwards only that verified address to EdgeProxy. EdgeProxy independently trusts forwarding metadata only from the expected SecurityEdge peer, preserving client identity without accepting spoofed headers from direct clients.

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

## Managed operations

The platform can be administered without manually stopping either executable:

- EdgeProxy watches its JSON profile and `.env`, hot-applies data-plane changes, and gracefully restarts listener generations for process-owned changes.
- SecurityEdge independently watches its own JSON, the shared EdgeProxy Route table, and `.env`; Route changes never trigger an unnecessary SecurityEdge listener restart.
- Authenticated APIs and PowerShell tools provide full configuration replacement, Server/Admin sections, Route and Origin CRUD, dedicated cache/load-balancing/proxy/health-check operations, and security-policy CRUD.
- The Dashboard exposes the same Control Plane with complete form-based Route, scheduler, retry, cache, health-check, Origin, SecurityEdge runtime/Admin/WAF, EdgeProxy dependency, and EdgeProxy listener/Admin management; raw JSON remains available only as an advanced escape hatch.
- Complete per-route and per-Origin telemetry includes traffic, cache efficiency, status distributions, failures, retries, latency percentiles, scheduler selections, EWMA, active work, and watcher/revision state.
- SecurityEdge retains a bounded, atomically persisted telemetry timeline for request/rejection rates and condensed Route/Origin history, so dashboard trends survive refreshes and service restarts.
- Atomic persistence, timestamped backups, strict JSON validation, redacted secrets, bounded resource settings, restart preflight for sockets/TLS/persistent resources, synchronous listener binding, and post-preflight rollback to the latest successfully started or hot-applied file-backed revision protect management operations.

## Requirements

- Go **1.26.5** or later
- Windows PowerShell for the supplied `.ps1` operational scripts
- Bash and GNU `find` for the optional Linux development watcher
- `curl` or `curl.exe` for HTTP verification
- Docker only for the optional container workflows
- A DNS record or static host mapping for named LAN testing

No third-party Go module is required by either application.

## Go module paths

The nested modules use paths that match this GitHub repository:

```text
github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy
github.com/Javad2004/SecureEdge-Platform/apps/securityedge
```

The root `go.work` file connects both modules for local development and repository-wide builds.

## Environment files

Each application has its own committed template:

```text
apps/edgeproxy/.env.example
apps/securityedge/.env.example
```

Create local files before a LAN deployment:

```powershell
Copy-Item ./apps/edgeproxy/.env.example ./apps/edgeproxy/.env
Copy-Item ./apps/securityedge/.env.example ./apps/securityedge/.env
```

Replace the IP addresses, ports, hostnames, DNS values, and tokens for the target environment. The `EDGEPROXY_ADMIN_TOKEN` value must be identical in both files. The real `.env` files are ignored by Git; only `.env.example` belongs in the repository.

Both programs automatically find their application-specific `.env` whether launched from the repository root or the application directory. A repository-root `.env` is intentionally not auto-discovered or shared between the applications; use the two application files or select an external file explicitly. Both programs also work normally when no application `.env` exists by using the selected JSON profile and built-in defaults.

Precedence is:

```text
CLI flags > process environment > application .env > JSON profile > built-in defaults
```

Use `-env <path>` for an explicit file, or `-no-env` to disable dotenv loading for an isolated test. `EDGEPROXY_ENV_FILE` and `SECURITYEDGE_ENV_FILE` provide the equivalent service-manager setting. Relative `EDGEPROXY_CONFIG` and `SECURITYEDGE_CONFIG` paths loaded from `.env` are resolved from that file. Relative paths supplied through CLI flags or pre-existing process environment variables retain normal current-working-directory semantics. Dotenv inputs must be regular UTF-8 files no larger than 1 MiB; invalid files are rejected before any values are applied. Double-quoted values use JSON-compatible escapes in both the Go services and PowerShell tools; Go-only escapes such as `\xNN` are rejected.

The component PowerShell verification, listener, connectivity, and firewall scripts follow the same process-environment-over-dotenv precedence. Their explicit parameters remain the highest-priority one-off overrides, so the commands stay aligned with the effective runtime ports, URLs, Origin address, DNS values, and credentials.

Route names, host selectors, and path prefixes remain in the shared EdgeProxy JSON profile rather than `.env`. This keeps EdgeProxy routing and SecurityEdge per-route policy selection on one authoritative contract; environment overrides are reserved for deployment endpoints such as Origin URLs, listeners, DNS, and credentials.

See the component READMEs for the complete variable and script references.

## Quick start: local development

Run these commands from the **repository root** in separate terminals. `-no-env` makes this local test independent of any LAN `.env` files.

### 1. Start the demo Origin

```powershell
go run ./apps/edgeproxy/cmd/origin-demo `
  -no-env `
  -listen 127.0.0.1:9000 `
  -name origin-local
```

### 2. Start EdgeProxy behind SecurityEdge

```powershell
go run ./apps/edgeproxy/cmd/edgeproxy `
  -no-env `
  -config ./integration/edgeproxy-local-behind-waf.json `
  -pretty-logs
```

### 3. Start SecurityEdge

```powershell
go run ./apps/securityedge/cmd/securityedge `
  -no-env `
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

### Automatic rebuild and restart during development

For a single development command that supervises both applications, run from the repository root:

```powershell
.\scripts\dev-watch.ps1 -PrettyLogs
```

On Linux:

```bash
bash ./scripts/dev-watch.sh
```

The watcher fingerprints the repository, debounces save bursts, builds an isolated candidate generation before stopping a healthy process, and restores the previous generation if startup fails. Go source, embedded Dashboard assets, workspace files, deployment files, and integration contracts restart only the affected applications. Its default EdgeProxy profile is the same authoritative `integration/edgeproxy-local-behind-waf.json` Route table referenced by the SecurityEdge local profile, so Dashboard/API mutations and both runtime watchers remain synchronized. The active JSON and `.env` files remain owned by each application's transactional runtime watcher, so hot-applicable revisions do not cause a development-process restart. Build products are written under ignored `.dev/`.

## Reference LAN deployment

The checked-in reference profile uses the following lab values:

```text
Gateway host / DNS address    10.36.74.241
Origin host                   10.36.74.43:9000
Public hostnames              project.test, www.project.test
SecurityEdge Admin fallback   SecurityEdgeDemo2026
EdgeProxy Admin fallback      EdgeProxyDemo2026
```

These are demonstration fallbacks, not hard-coded product requirements. For another network, copy and edit the two application `.env.example` files rather than committing machine-specific changes to JSON.

After copying and editing both `.env.example` files, run from the repository root.

### Origin host

```powershell
go run ./apps/edgeproxy/cmd/origin-demo
```

### Gateway host: EdgeProxy

```powershell
go run ./apps/edgeproxy/cmd/edgeproxy -pretty-logs
```

### Gateway host: SecurityEdge

```powershell
go run ./apps/securityedge/cmd/securityedge -pretty-logs
```

Use `-env <path>` when the real environment file is stored outside the application directory. Explicit `-listen`, `-config`, or other CLI values still override `.env` for one-off tests.

Open the public hostname from any permitted HTTP client. Requests that reach SecurityEdge appear automatically in the **Recent Client Traffic** panel; no external reporting script is required.

## Configuration profiles

### EdgeProxy

| Profile | Purpose |
|---|---|
| `apps/edgeproxy/configs/local-dev.json` | EdgeProxy-only local development |
| `apps/edgeproxy/configs/edgeproxy.json` | EdgeProxy-only LAN demonstration |
| `integration/edgeproxy-local-behind-waf.json` | Local integrated deployment behind SecurityEdge |
| `integration/edgeproxy-behind-waf.json` | LAN integrated deployment behind SecurityEdge |
| `apps/edgeproxy/configs/compose.json` | Standalone EdgeProxy Compose demonstration |
| `integration/edgeproxy-compose-behind-waf.json` | Full-platform container deployment behind SecurityEdge |

### SecurityEdge

| Profile | Purpose |
|---|---|
| `apps/securityedge/configs/local-dev.json` | Local gateway on `127.0.0.1:8081` |
| `apps/securityedge/configs/securityedge.json` | LAN gateway on `0.0.0.0:80` |
| `apps/securityedge/configs/embedded.json` | Optional future embedded integration profile |
| `apps/securityedge/configs/compose.json` | Full-platform container profile using Docker service discovery |

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

## Linux systemd deployment

Hardened host-service units are supplied for both applications:

- [`apps/edgeproxy/deploy/systemd/edgeproxy.service`](apps/edgeproxy/deploy/systemd/edgeproxy.service)
- [`apps/securityedge/deploy/systemd/securityedge.service`](apps/securityedge/deploy/systemd/securityedge.service)

The units deliberately separate immutable secrets from mutable Control Plane state:

```text
/etc/edgeproxy/edgeproxy.env                 read-only secrets and overrides
/etc/securityedge/securityedge.env           read-only secrets and overrides
/var/lib/edgeproxy/config.json               writable authoritative Route table
/var/lib/securityedge/securityedge.json      writable SecurityEdge configuration
/var/lib/securityedge/telemetry-history.json writable bounded telemetry history
/var/log/securityedge/                       writable rotated security events
```

Initial production profiles are supplied at `apps/edgeproxy/deploy/systemd/edgeproxy.json` and `apps/securityedge/deploy/systemd/securityedge.json`. The matching environment templates contain credentials only. Mutable listener, TLS, dependency, WAF, Route, cache, telemetry, and logging settings stay in the writable JSON profiles so successful Dashboard/API changes remain effective after reload and restart.

This layout is required because Dashboard and Admin API changes use atomic replacement and timestamped backups. Keeping an active JSON profile under a read-only `/etc` directory would make otherwise valid Route, Origin, WAF, and policy updates fail. Defining optional configuration environment overrides is still supported as an intentional deployment lock. The Control Plane rejects attempts to change an environment-managed field with an explicit error instead of persisting a value that cannot become effective; rotate environment-provided credentials in the service environment file and restart the affected service.

Install EdgeProxy first, then SecurityEdge. Use the application READMEs for the complete user/group, permission, environment, validation, and `systemctl` commands.

## Docker

The repository provides two container workflows.

### Standalone EdgeProxy demonstration

This stack runs only the demo Origin and EdgeProxy. Create the application environment file and replace the Admin API token before starting:

```powershell
Copy-Item ./apps/edgeproxy/.env.example ./apps/edgeproxy/.env
```

Run from the repository root:

```powershell
docker compose `
  -f ./apps/edgeproxy/docker-compose.yml `
  --project-directory ./apps/edgeproxy `
  up --build
```

Compose rejects a missing or empty `EDGEPROXY_ADMIN_TOKEN`; it never falls back to a checked-in credential.

The standalone proxy is exposed at `http://127.0.0.1:8080`; its Admin API is bound to `http://127.0.0.1:9090`.

### Complete SecureEdge Platform

The platform Compose deployment runs the demo Origin, EdgeProxy, and SecurityEdge on one private Docker network:

```text
Host client → SecurityEdge → EdgeProxy → Origin
```

EdgeProxy and the Origin are not published to the host. SecurityEdge ingress is published on port `8081`, while the dashboard remains loopback-only on port `9191`.

Create the deployment environment file and replace both placeholder tokens before starting the stack:

```powershell
Copy-Item ./deployments/docker/.env.example ./deployments/docker/.env
```

The Compose definition treats both Admin credentials as required and stops with an explicit interpolation error when either value is missing or empty. Start the stack with the selected file:

```powershell
docker compose `
  --env-file ./deployments/docker/.env `
  -f ./deployments/docker/compose.yml `
  up --build
```

Verify the complete request path:

```powershell
curl.exe -i http://127.0.0.1:8081/api/products
curl.exe -i http://127.0.0.1:8081/api/products
```

Open the dashboard at `http://127.0.0.1:9191` and authenticate with the `SECURITYEDGE_ADMIN_TOKEN` value from `deployments/docker/.env`.

Stop the stack without deleting persisted SecurityEdge configuration or logs:

```powershell
docker compose `
  --env-file ./deployments/docker/.env `
  -f ./deployments/docker/compose.yml `
  down
```

Delete the stack and its named volumes when a clean configuration reset is required:

```powershell
docker compose `
  --env-file ./deployments/docker/.env `
  -f ./deployments/docker/compose.yml `
  down -v
```

The full stack stores EdgeProxy configuration, SecurityEdge configuration, and rotated SecurityEdge NDJSON logs in named Docker volumes. SecurityEdge receives the same EdgeProxy volume read-only, so Dashboard/API Route changes are atomically persisted once and observed by both services without copying files. Environment-provided tokens and endpoint overrides take precedence at runtime and are never written into persisted JSON.

### Build the SecurityEdge image directly

SecurityEdge's Dockerfile requires the repository root as its build context because it copies both the application and the root-level `integration` directory:

```powershell
docker build `
  -f ./apps/securityedge/Dockerfile `
  -t securityedge:latest `
  .
```

The image defaults to the container-specific profile at `/app/config/securityedge.json`. That profile uses Docker service names and expects services named `edgeproxy` and `origin`; use the full-platform Compose file for the supported multi-container workflow.

See [deployments/docker/README.md](deployments/docker/README.md) for the complete container contract.

## Administrative credentials

The two tokens are intentionally separate:

```text
SecurityEdge Admin UI/API token  authenticates dashboard and SecurityEdge API users
EdgeProxy Admin API token        authenticates SecurityEdge-to-EdgeProxy control-plane calls
```

For non-demonstration environments, copy the two application templates, generate strong values, and keep the shared EdgeProxy token synchronized:

```powershell
Copy-Item ./apps/edgeproxy/.env.example ./apps/edgeproxy/.env
Copy-Item ./apps/securityedge/.env.example ./apps/securityedge/.env
```

Process-level environment variables remain supported and take precedence over `.env`, which allows production service managers or secret stores to inject the same values without local files.

## Security boundaries

- Only SecurityEdge should expose the public HTTP ingress in the integrated deployment.
- EdgeProxy data and Admin listeners should remain bound to loopback on host deployments, or remain unpublished on a private container network.
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
