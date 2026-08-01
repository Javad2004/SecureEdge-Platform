# Platform Integration

This directory contains the shared deployment contract between the two applications in the [SecureEdge Platform](../README.md):

- [`apps/edgeproxy`](../apps/edgeproxy/README.md) — reverse proxy, routing, cache, origin health, access logs, and metrics;
- [`apps/securityedge`](../apps/securityedge/README.md) — WAF inspection, traffic admission, security telemetry, dependency monitoring, and dashboard.

The files are stored at repository level because they describe how both applications participate in one deployment. They are not owned exclusively by either application.

## Active deployment mode

The supported project workflow is standalone non-embedded gateway mode:

```text
HTTP client
    │
    ▼
SecurityEdge public ingress
    │
    │ accepted HTTP requests
    ▼
EdgeProxy loopback data plane
    │
    ▼
Application origin
```

SecurityEdge and EdgeProxy remain separate processes. SecurityEdge uses two EdgeProxy interfaces:

1. the **data plane** for forwarding accepted application requests;
2. the **Admin API** for status, metrics, logs, readiness, and cache operations.

## Files

### `edgeproxy-behind-waf.json`

Reference LAN profile for EdgeProxy behind SecurityEdge.

```text
EdgeProxy data plane    127.0.0.1:8080
EdgeProxy Admin API     127.0.0.1:9090
Admin token             EdgeProxyDemo2026
Origin                   10.36.74.43:9000
Route                    demo-app
Health endpoint          /healthz
Cache                    enabled
```

The profile supports these demonstration hosts:

```text
project.local
project.test
www.project.test
localhost
127.0.0.1
```

Update the Origin URL and hostnames when the deployment network changes.

### `edgeproxy-local-behind-waf.json`

Local integrated-development profile.

```text
EdgeProxy data plane    127.0.0.1:8080
EdgeProxy Admin API     127.0.0.1:9090
Admin token             dev-token
Origin                   127.0.0.1:9000
Route                    demo-app
Cache                    enabled
```

Use this profile with `apps/securityedge/configs/local-dev.json`.

### `edgeproxy-embedded-integration.patch`

Optional reference patch for a possible future in-process integration in which EdgeProxy imports the SecurityEdge package and wraps its HTTP handler.

The patch is not applied in the active source tree and is not required for the supported gateway deployment. It should be treated as an experimental integration artifact and revalidated whenever either application's internal server structure changes.

## Configuration mapping

| SecurityEdge profile | EdgeProxy integration profile |
|---|---|
| `apps/securityedge/configs/local-dev.json` | `integration/edgeproxy-local-behind-waf.json` |
| `apps/securityedge/configs/securityedge.json` | `integration/edgeproxy-behind-waf.json` |
| `apps/securityedge/configs/embedded.json` | `integration/edgeproxy-local-behind-waf.json` |

SecurityEdge resolves its `edgeproxy.config_path` relative to the directory containing the SecurityEdge JSON file. For example:

```text
apps/securityedge/configs/securityedge.json
+ ../../../integration/edgeproxy-behind-waf.json
= integration/edgeproxy-behind-waf.json
```

Do not simplify that JSON value to a path relative to the shell's current working directory; the application intentionally resolves it relative to the configuration file.

## Credential contract

The two administrative tokens serve different trust boundaries:

```text
SecurityEdge Admin token   authenticates operators to the dashboard and API
EdgeProxy Admin token      authenticates SecurityEdge to the EdgeProxy Admin API
```

The values must match across the paired profiles:

| Deployment | SecurityEdge `edgeproxy.admin_token` | EdgeProxy `admin.auth_token` |
|---|---|---|
| Local | `dev-token` | `dev-token` |
| Reference LAN | `EdgeProxyDemo2026` | `EdgeProxyDemo2026` |

For non-demonstration use, inject the real tokens through environment variables instead of committing them:

```powershell
$env:SECURITYEDGE_ADMIN_TOKEN = "<strong-random-token>"
$env:EDGEPROXY_ADMIN_TOKEN = "<matching-edgeproxy-token>"
```

## Validate the shared profiles

The commands below assume the current directory is `integration`. The Go `-C` option runs each application from its own module directory, so relative runtime paths such as SecurityEdge log files remain inside the owning application.

Validate the local EdgeProxy profile:

```powershell
go -C ../apps/edgeproxy run ./cmd/edgeproxy `
  -config ../../integration/edgeproxy-local-behind-waf.json `
  -validate
```

Validate the LAN EdgeProxy profile:

```powershell
go -C ../apps/edgeproxy run ./cmd/edgeproxy `
  -config ../../integration/edgeproxy-behind-waf.json `
  -validate
```

Validate the paired SecurityEdge profiles:

```powershell
go -C ../apps/securityedge run ./cmd/securityedge `
  -config ./configs/local-dev.json `
  -validate

go -C ../apps/securityedge run ./cmd/securityedge `
  -config ./configs/securityedge.json `
  -validate
```

## Security boundaries

The integrated deployment should preserve these boundaries:

- SecurityEdge is the only public HTTP ingress.
- EdgeProxy data and Admin listeners remain on loopback.
- The SecurityEdge dashboard remains on loopback unless protected by another trusted access layer.
- The Origin accepts traffic only from the gateway host.
- The public client cannot bypass SecurityEdge by connecting directly to EdgeProxy or the Origin.
- Demo tokens and addresses are replaced before non-lab use.

## Change-management rules

When changing an integration profile:

1. keep the EdgeProxy data-plane URL synchronized with SecurityEdge's `server.upstream_proxy_url`;
2. keep the EdgeProxy Admin URL synchronized with SecurityEdge's `edgeproxy.admin_url`;
3. keep the EdgeProxy Admin token synchronized across both paired profiles;
4. keep SecurityEdge route-policy names aligned with EdgeProxy route names;
5. validate both JSON profiles;
6. test route readiness, Origin health, cache `MISS/HIT`, WAF blocking, and automatic recovery after EdgeProxy restart.

## Related documentation

- [Repository overview](../README.md)
- [EdgeProxy](../apps/edgeproxy/README.md)
- [SecurityEdge](../apps/securityedge/README.md)
