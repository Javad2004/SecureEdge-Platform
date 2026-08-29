# Docker Deployment

This directory contains the supported full-platform Docker Compose deployment.

## Topology

```text
Host client
    │ published port 8081
    ▼
SecurityEdge
    │ private Docker network
    ▼
EdgeProxy
    │ private Docker network
    ▼
Demo Origin
```

Published host ports:

```text
0.0.0.0:8081       SecurityEdge HTTP ingress
127.0.0.1:9191     SecurityEdge dashboard and Admin API
```

EdgeProxy ports `8080` and `9090`, and Origin port `9000`, are exposed only to the private Compose network. The network uses `172.30.0.0/24`, and SecurityEdge is assigned `172.30.0.10` so EdgeProxy can trust client forwarding headers from one explicit peer rather than an entire dynamic subnet.

## Start from the repository root

Copy the deployment template and replace both placeholder Admin tokens before starting. The Compose definition treats these credentials as required and refuses to render the stack when either value is missing or empty:

```powershell
Copy-Item ./deployments/docker/.env.example ./deployments/docker/.env

docker compose `
  --env-file ./deployments/docker/.env `
  -f ./deployments/docker/compose.yml `
  up --build
```

Run in detached mode by adding `-d`.

## Verify

```powershell
curl.exe -i http://127.0.0.1:8081/api/products
curl.exe -i http://127.0.0.1:8081/api/products
```

Expected EdgeProxy cache result:

```text
first request   X-Cache: MISS
second request  X-Cache: HIT
```

Dashboard:

```text
URL:    http://127.0.0.1:9191
Token:  the SECURITYEDGE_ADMIN_TOKEN value from deployments/docker/.env
```

## Persistent state

Three named volumes are used:

```text
edgeproxy-config      mutable shared EdgeProxy routes, Origins, and scheduler configuration
securityedge-config   mutable SecurityEdge policy and gateway configuration
securityedge-logs     rotated SecurityEdge NDJSON logs and bounded telemetry history
```

The EdgeProxy image initializes `/app/config/config.json` on first creation and mounts the directory read-write so atomic rename and timestamped backups remain valid. SecurityEdge mounts the same volume read-only at `/edgeproxy-config` and receives `SECURITYEDGE_EDGEPROXY_CONFIG_PATH=/edgeproxy-config/config.json`; both watchers therefore observe one authoritative Route table. The SecurityEdge image initializes its own configuration volume separately.

Dashboard/API changes are atomically written to the corresponding configuration volume. Rebuilding images does not overwrite existing volume data. Values injected from the Compose `.env` remain runtime-only and are not written into persisted JSON.

To stop services while retaining state:

```powershell
docker compose `
  --env-file ./deployments/docker/.env `
  -f ./deployments/docker/compose.yml `
  down
```

To reset configuration and logs completely:

```powershell
docker compose `
  --env-file ./deployments/docker/.env `
  -f ./deployments/docker/compose.yml `
  down -v
```

## Container hardening

The deployment:

- runs all application processes as non-root users;
- uses read-only root filesystems;
- provides narrowly scoped writable volumes for EdgeProxy configuration, SecurityEdge configuration, and SecurityEdge logs;
- drops all Linux capabilities;
- enables `no-new-privileges`;
- keeps EdgeProxy and Origin unpublished from the host;
- uses an explicit private subnet and a fixed SecurityEdge address for least-privilege forwarded-header trust;
- binds the dashboard host port to loopback;
- uses process-liveness `/healthz` container checks and dependency ordering; `/readyz` remains available separately for operational readiness diagnostics.

## Configuration files

```text
apps/securityedge/configs/compose.json
integration/edgeproxy-compose-behind-waf.json
```

SecurityEdge reaches dependencies through Docker service discovery:

```text
http://edgeproxy:8080
http://edgeproxy:9090
http://origin:9000
```

## Production notes

The checked-in Compose profile intentionally uses HTTP ingress on port `8081` for local reproducibility. Native SecurityEdge TLS is available through `server.tls`; an Internet-facing container profile can enable it and mount the configured certificate chain/private key paths read-only. If TLS terminates outside SecurityEdge instead, restrict `trusted_proxy_cidrs` to the actual terminating proxy addresses so forwarded client identity remains trustworthy.


The checked-in stack is a hardened project demonstration, not a complete Internet-edge production deployment. Before external use:

- rotate both Admin tokens through a secret manager or protected environment file;
- either enable native SecurityEdge TLS with certificate/key material mounted read-only into the container, or place a trusted TLS-terminating load balancer/CDN in front of SecurityEdge;
- apply host firewall policy and Docker daemon hardening;
- verify that `172.30.0.0/24` does not overlap an existing local or VPN network, or change the subnet and matching EdgeProxy trusted-proxy CIDR together;
- define resource limits appropriate to the host;
- export logs and metrics to managed observability systems;
- use an external application Origin instead of the included demo Origin;
- test backup and restore of both configuration volumes and the SecurityEdge log volume.
