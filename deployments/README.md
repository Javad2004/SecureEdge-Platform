# Deployments

This directory contains tested, platform-level deployment definitions that coordinate more than one application.

Available deployment paths:

- [`docker/`](docker/README.md) — complete three-service Docker Compose stack for Origin, EdgeProxy, and SecurityEdge.
- Linux `systemd` host deployment — hardened application-owned units and environment templates:
  - [`../apps/edgeproxy/deploy/systemd/`](../apps/edgeproxy/deploy/systemd/)
  - [`../apps/securityedge/deploy/systemd/`](../apps/securityedge/deploy/systemd/)

Application-specific units remain next to the application they execute so their configuration contract, runtime paths, and documentation stay versioned together. Each systemd directory contains a hardened unit, a credentials-only environment template, and an initial production JSON profile. The deployment keeps secrets read-only under `/etc`, while transactionally managed JSON, telemetry history, and security logs live in writable `/var/lib` and `/var/log` locations. Mutable settings are intentionally not active environment assignments; otherwise systemd would reapply them over file-backed values after every reload or restart. If an operator deliberately adds such an override, the Control Plane rejects attempts to change that managed field rather than returning a misleading success response.
