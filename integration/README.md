# Platform Integration

This directory defines the shared runtime contract between the two applications in the [SecureEdge Platform](../README.md):

- [`apps/edgeproxy`](../apps/edgeproxy/README.md) — routing, reverse proxying, caching, origin health, logs, and metrics;
- [`apps/securityedge`](../apps/securityedge/README.md) — WAF inspection, traffic admission, security telemetry, dependency monitoring, and dashboard.

The files are stored at repository level because they describe how both applications participate in one deployment. They are not owned exclusively by either application.

## Supported deployment modes

### Host or LAN gateway mode

```text
HTTP/HTTPS client → SecurityEdge → EdgeProxy → Application Origin
```

SecurityEdge and EdgeProxy run as separate processes on the gateway host. EdgeProxy binds its data and Admin listeners to loopback so clients cannot bypass SecurityEdge.

### Docker Compose mode

```text
Host client → SecurityEdge container → EdgeProxy container → Origin container
```

All services share a private Docker network. Only SecurityEdge ingress and its loopback-bound host dashboard port are published. EdgeProxy and the Origin remain internal services. A named configuration volume is writable only by EdgeProxy and mounted read-only by SecurityEdge for synchronized Route-table watching.

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
Admin token   required `EDGEPROXY_ADMIN_TOKEN` from `deployments/docker/.env`
Origin        http://origin:9000
```

Binding to `0.0.0.0` is required inside the container, but the platform Compose file does not publish either EdgeProxy port to the host. The private network uses `172.30.0.0/24`, assigns SecurityEdge `172.30.0.10`, and configures EdgeProxy to trust forwarded client addresses only from that exact container address.

### `edgeproxy-embedded-integration.patch`

Optional experimental patch for a possible future in-process integration in which EdgeProxy imports the SecurityEdge package and wraps its HTTP handler. It is not applied to the active source tree and is not required for the supported gateway or Compose deployments. The patch is generated against the current managed-generation implementation rather than the earlier single-generation server: EdgeProxy, its Admin API, and the embedded SecurityEdge Admin dashboard all bind synchronously, and a partial startup closes every acquired listener and runtime resource.

After the patch is applied, the EdgeProxy command loads `apps/edgeproxy/.env` and `apps/securityedge/.env` independently. Set `SECURITYEDGE_CONFIG=configs/embedded.json` in the SecurityEdge file for this mode. `SECURITYEDGE_ENV_FILE` can select an external SecurityEdge environment file, and EdgeProxy's `-no-env` flag disables both dotenv loaders. The loaded EdgeProxy/SecurityEdge dotenv files and the active EdgeProxy TLS certificate/key paths are passed to the embedded SecurityEdge runtime as protected resources, so SecurityEdge log/history persistence cannot overwrite them or occupy the configuration backup namespace. Validation through the patched EdgeProxy command checks both the EdgeProxy and embedded SecurityEdge configurations. The patch requires `server.mode` to be `embedded`; applying a gateway profile is rejected before any listener starts.

## Configuration mapping

| SecurityEdge profile | EdgeProxy profile | Runtime |
|---|---|---|
| `apps/securityedge/configs/local-dev.json` | `integration/edgeproxy-local-behind-waf.json` | Local host development |
| `apps/securityedge/configs/securityedge.json` | `integration/edgeproxy-behind-waf.json` | Reference LAN deployment |
| `apps/securityedge/configs/compose.json` | `integration/edgeproxy-compose-behind-waf.json` | Full-platform Docker Compose |
| `apps/securityedge/configs/embedded.json` | `integration/edgeproxy-local-behind-waf.json` | Optional embedded experiment |

SecurityEdge resolves `edgeproxy.config_path` relative to the directory containing its own JSON configuration. The checked-in `../../../integration/...` values are the source-tree defaults:

```text
Source tree: /repository/apps/securityedge/configs + ../../../integration = /repository/integration
```

The full-platform Compose deployment intentionally overrides this value with `SECURITYEDGE_EDGEPROXY_CONFIG_PATH=/edgeproxy-config/config.json`. EdgeProxy writes that file through a named volume, while SecurityEdge mounts the same volume read-only. This arrangement preserves atomic rename and backups and ensures that both processes watch one authoritative, writable Route table. Do not rewrite host-mode values as paths relative to the shell's working directory.

## Client-address forwarding contract

SecurityEdge resolves the client address using its own `server.trusted_proxy_cidrs` policy and forwards that resolved address to EdgeProxy. EdgeProxy independently verifies that the immediate peer is trusted before accepting `X-Forwarded-For`.

```text
Host/LAN deployment   EdgeProxy trusts loopback SecurityEdge only
Compose deployment    EdgeProxy trusts 172.30.0.10/32 only
Standalone EdgeProxy  forwarded client headers are not trusted
```

Do not broaden the EdgeProxy trusted-proxy list unless the data-plane listener remains inaccessible to untrusted clients. If the Compose subnet or fixed SecurityEdge address is changed, update both `deployments/docker/compose.yml` and `integration/edgeproxy-compose-behind-waf.json`.

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
| Compose | required `EDGEPROXY_ADMIN_TOKEN` environment value | the same required environment value |

For non-demonstration environments, copy the application templates:

```powershell
Copy-Item ../apps/edgeproxy/.env.example ../apps/edgeproxy/.env
Copy-Item ../apps/securityedge/.env.example ../apps/securityedge/.env
```

Set a unique `SECURITYEDGE_ADMIN_TOKEN`, and set the same strong `EDGEPROXY_ADMIN_TOKEN` in both files. For the full Compose deployment, copy `deployments/docker/.env.example` to `deployments/docker/.env` and replace both placeholders; Compose refuses to render when either Admin token is missing or empty. The application templates also centralize the paired listener URLs, Origin URL, trusted-proxy CIDRs, and DNS acceptance values.

Both programs load environment values after JSON. SecurityEdge deliberately keeps every environment-derived secret and endpoint runtime-only, so dashboard policy updates never persist them into the JSON profile.

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
3. keep `EDGEPROXY_ADMIN_TOKEN` synchronized in both application `.env` files;
4. keep SecurityEdge route-policy names aligned with EdgeProxy route names;
5. keep EdgeProxy trusted-proxy CIDRs aligned with the SecurityEdge transport address;
6. verify that EdgeProxy can reach every configured Origin;
7. validate both JSON profiles;
8. test cache `MISS/HIT`, WAF blocking, original client-address propagation, route readiness, Origin health, and recovery after dependency restarts.

## Security boundaries

- SecurityEdge is the only public HTTP/HTTPS ingress; native TLS may terminate there or at a deliberately trusted external edge.
- SecurityEdge-to-EdgeProxy and EdgeProxy-to-Origin data-plane connections are direct and do not use ambient `HTTP_PROXY` or `HTTPS_PROXY` variables.
- EdgeProxy and Origin listeners are loopback-only on host deployments or unpublished on private container networks.
- The SecurityEdge dashboard remains loopback-bound on the host unless another trusted access layer is added.
- Runtime tokens, logs, `.env` files, and generated artifacts are not committed.
- Demonstration tokens and lab IP addresses must be replaced before non-lab use.

## Related documentation

- [Repository overview](../README.md)
- [EdgeProxy](../apps/edgeproxy/README.md)
- [SecurityEdge](../apps/securityedge/README.md)
- [Docker deployment](../deployments/docker/README.md)
