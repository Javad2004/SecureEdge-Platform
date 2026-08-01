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

The Compose file contains demonstration credential defaults, so this command works without an environment file:

```powershell
docker compose -f ./deployments/docker/compose.yml up --build
```

For explicit overrides, copy the template and replace the values:

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
Token:  dev-security-token, unless overridden
```

## Persistent state

Two named volumes are used:

```text
securityedge-config   mutable SecurityEdge policy configuration
securityedge-logs     rotated SecurityEdge NDJSON event logs
```

The image initializes `securityedge-config` with the container profile on first creation. Dashboard policy changes are atomically written to this volume. Rebuilding the image does not overwrite an existing configuration volume.

To stop services while retaining state:

```powershell
docker compose -f ./deployments/docker/compose.yml down
```

To reset configuration and logs completely:

```powershell
docker compose -f ./deployments/docker/compose.yml down -v
```

## Container hardening

The deployment:

- runs all application processes as non-root users;
- uses read-only root filesystems;
- provides writable volumes only for SecurityEdge configuration and logs;
- drops all Linux capabilities;
- enables `no-new-privileges`;
- keeps EdgeProxy and Origin unpublished from the host;
- uses an explicit private subnet and a fixed SecurityEdge address for least-privilege forwarded-header trust;
- binds the dashboard host port to loopback;
- uses health checks and dependency ordering.

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

The checked-in stack is a hardened project demonstration, not a complete Internet-edge production deployment. Before external use:

- replace both demonstration tokens;
- place TLS termination, a trusted load balancer, or a CDN in front of SecurityEdge;
- apply host firewall policy and Docker daemon hardening;
- verify that `172.30.0.0/24` does not overlap an existing local or VPN network, or change the subnet and matching EdgeProxy trusted-proxy CIDR together;
- define resource limits appropriate to the host;
- export logs and metrics to managed observability systems;
- use an external application Origin instead of the included demo Origin;
- test backup and restore of the SecurityEdge configuration volume.
