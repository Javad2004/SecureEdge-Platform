# Deployments

This directory contains tested deployment definitions for local/demo, production Docker, and Linux service-manager operation.

Available deployment paths:

- [`docker/`](docker/README.md) — unchanged local/demo three-container Compose stack for Origin, EdgeProxy, and SecurityEdge.
- [`docker-production/`](docker-production/README.md) — production Docker deployments for EdgeProxy-only, SecurityEdge-only, or the complete EdgeProxy + SecurityEdge platform with a real external Origin.
- Linux `systemd` host deployment — hardened application-owned units and environment templates:
  - [`../apps/edgeproxy/deploy/systemd/`](../apps/edgeproxy/deploy/systemd/)
  - [`../apps/securityedge/deploy/systemd/`](../apps/securityedge/deploy/systemd/)

Application-specific units remain next to the application they execute so their configuration contract, runtime paths, and documentation stay versioned together. Each systemd directory contains a hardened unit, a credentials-only environment template, and an initial production JSON profile. The deployment keeps secrets read-only under `/etc`, while transactionally managed JSON, telemetry history, and security logs live in writable `/var/lib` and `/var/log` locations. Mutable settings are intentionally not active environment assignments; otherwise systemd would reapply them over file-backed values after every reload or restart. If an operator deliberately adds such an override, the Control Plane rejects attempts to change that managed field rather than returning a misleading success response.

## TLS boundaries

The supplied single-host systemd deployment uses SecurityEdge as the public native-HTTPS boundary on port `443` and keeps EdgeProxy on HTTP loopback at `127.0.0.1:8080`. This is intentional: encrypting a hop that never leaves the same host provides little additional transport protection while adding certificate lifecycle overhead.

EdgeProxy nevertheless supports native TLS independently. When SecurityEdge and EdgeProxy are placed on different hosts or cross an untrusted network boundary, enable `server.tls` on EdgeProxy, use an `https://` SecurityEdge upstream URL, and provide a certificate trusted by the SecurityEdge host. SecurityEdge-to-EdgeProxy HTTPS and EdgeProxy-to-Origin HTTPS both enforce TLS 1.2 or newer with certificate verification enabled by default. Management listeners remain private boundaries unless a deployment deliberately places a separately trusted TLS access layer in front of them.


## Production Docker

The production Docker path is intentionally separate from the reproducible demo
stack. It supports staged migration from the supplied systemd deployment while
preserving the same mutable `/var/lib` and `/var/log` state, read-only TLS
material, non-root service identities, and rollback path. The combined
production topology publishes only the SecurityEdge data plane publicly, keeps
EdgeProxy data private and both Admin endpoints loopback-only, and expects a
real Origin rather than the repository's demo Origin.

See [`docker-production/README.md`](docker-production/README.md) for bootstrap,
Docker-secret handling, preflight validation, resource limits, Tailscale/VPN
Origin routing, full-stack startup, update, reboot, and rollback procedures.
