# Platform Integration

This directory defines the shared runtime contract between the two applications in the [SecureEdge Platform](../README.md):

- [`apps/edgeproxy`](../apps/edgeproxy/README.md) — routing, reverse proxying, caching, origin health, logs, and metrics;
- [`apps/securityedge`](../apps/securityedge/README.md) — WAF inspection, traffic admission, security telemetry, dependency monitoring, and dashboard.

The files are stored at repository level because they describe how both applications participate in one deployment. They are not owned exclusively by either application.

## Supported deployment modes

### Host or LAN gateway mode

```text
HTTP client → SecurityEdge → EdgeProxy → Application Origin
```

SecurityEdge and EdgeProxy run as separate processes on the gateway host. EdgeProxy binds its data and Admin listeners to loopback so clients cannot bypass SecurityEdge.

### Docker Compose mode

```text
Host client → SecurityEdge container → EdgeProxy container → Origin container
```

All services share a private Docker network. Only SecurityEdge ingress and its loopback-bound host dashboard port are published. EdgeProxy and the Origin remain internal services.

## Integration files

### `edgeproxy-local-behind-waf.json`

Local host-development profile paired with `apps/securityedge/configs/local-dev.json`.

```text
Data plane    127.0.0.1:8080
Admin API     127.0.0.1:9090
Admin token   dev-token
Origin        127.0.0.1:9000
```

### `edgeproxy-behind-waf.json`

Reference LAN profile paired with `apps/securityedge/configs/securityedge.json`.

```text
Data plane    127.0.0.1:8080
Admin API     127.0.0.1:9090
Admin token   EdgeProxyDemo2026
Origin        10.36.74.43:9000
```

Update the demonstration Origin address and hostnames before using another network.

### `edgeproxy-compose-behind-waf.json`

Container-network profile paired with `apps/securityedge/configs/compose.json`.

```text
Data plane    0.0.0.0:8080 inside the container network
Admin API     0.0.0.0:9090 inside the container network
Admin token   dev-token, normally overridden by environment
Origin        http://origin:9000
```

Binding to `0.0.0.0` is required inside the container, but the platform Compose file does not publish either EdgeProxy port to the host.

### `edgeproxy-embedded-integration.patch`

Optional experimental patch for a possible future in-process integration in which EdgeProxy imports the SecurityEdge package and wraps its HTTP handler. It is not applied to the active source tree and is not required for the supported gateway or Compose deployments.

## Configuration mapping

| SecurityEdge profile | EdgeProxy profile | Runtime |
|---|---|---|
| `apps/securityedge/configs/local-dev.json` | `integration/edgeproxy-local-behind-waf.json` | Local host development |
| `apps/securityedge/configs/securityedge.json` | `integration/edgeproxy-behind-waf.json` | Reference LAN deployment |
| `apps/securityedge/configs/compose.json` | `integration/edgeproxy-compose-behind-waf.json` | Full-platform Docker Compose |
| `apps/securityedge/configs/embedded.json` | `integration/edgeproxy-local-behind-waf.json` | Optional embedded experiment |

SecurityEdge resolves `edgeproxy.config_path` relative to the directory containing its own JSON configuration. The checked-in `../../../integration/...` values therefore work both in the source tree and after the Compose profile is copied to `/app/config/securityedge.json` inside the image:

```text
Source tree: /repository/apps/securityedge/configs + ../../../integration = /repository/integration
Container:   /app/config                         + ../../../integration = /integration
```

Do not rewrite these values as paths relative to the shell's working directory.

## Credential contract

The two credentials protect different trust boundaries:

```text
SecurityEdge Admin token   authenticates dashboard and SecurityEdge API operators
EdgeProxy Admin token      authenticates SecurityEdge control-plane calls to EdgeProxy
```

Paired EdgeProxy tokens must match:

| Deployment | SecurityEdge `edgeproxy.admin_token` | EdgeProxy `admin.auth_token` |
|---|---|---|
| Local | `dev-token` | `dev-token` |
| Reference LAN | `EdgeProxyDemo2026` | `EdgeProxyDemo2026` |
| Compose | `dev-token` | `dev-token` |

For non-demonstration environments, inject both values:

```powershell
$env:SECURITYEDGE_ADMIN_TOKEN = "<strong-random-dashboard-token>"
$env:EDGEPROXY_ADMIN_TOKEN = "<strong-random-shared-token>"
```

SecurityEdge deliberately loads environment-provided secrets after reading the file and does not persist them during policy updates.

## Validate profiles

Run these commands from `integration`.

```powershell
go -C ../apps/edgeproxy run ./cmd/edgeproxy `
  -config ../../integration/edgeproxy-local-behind-waf.json `
  -validate

go -C ../apps/edgeproxy run ./cmd/edgeproxy `
  -config ../../integration/edgeproxy-behind-waf.json `
  -validate

go -C ../apps/edgeproxy run ./cmd/edgeproxy `
  -config ../../integration/edgeproxy-compose-behind-waf.json `
  -validate

go -C ../apps/securityedge run ./cmd/securityedge `
  -config ./configs/local-dev.json `
  -validate

go -C ../apps/securityedge run ./cmd/securityedge `
  -config ./configs/securityedge.json `
  -validate

go -C ../apps/securityedge run ./cmd/securityedge `
  -config ./configs/compose.json `
  -validate
```

## Change-management checklist

When changing a paired deployment profile:

1. keep SecurityEdge `server.upstream_proxy_url` aligned with the EdgeProxy data listener;
2. keep SecurityEdge `edgeproxy.admin_url` aligned with the EdgeProxy Admin listener;
3. keep `EDGEPROXY_ADMIN_TOKEN` synchronized for both processes;
4. keep SecurityEdge route-policy names aligned with EdgeProxy route names;
5. verify that EdgeProxy can reach every configured Origin;
6. validate both JSON profiles;
7. test cache `MISS/HIT`, WAF blocking, route readiness, Origin health, and recovery after dependency restarts.

## Security boundaries

- SecurityEdge is the only public HTTP ingress.
- EdgeProxy and Origin listeners are loopback-only on host deployments or unpublished on private container networks.
- The SecurityEdge dashboard remains loopback-bound on the host unless another trusted access layer is added.
- Runtime tokens, logs, `.env` files, and generated artifacts are not committed.
- Demonstration tokens and lab IP addresses must be replaced before non-lab use.

## Related documentation

- [Repository overview](../README.md)
- [EdgeProxy](../apps/edgeproxy/README.md)
- [SecurityEdge](../apps/securityedge/README.md)
- [Docker deployment](../deployments/docker/README.md)
