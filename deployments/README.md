# Deployments

This directory contains tested, platform-level deployment definitions that coordinate more than one application.

Available deployment paths:

- [`docker/`](docker/README.md) — complete three-service Docker Compose stack for Origin, EdgeProxy, and SecurityEdge.
- Linux `systemd` host deployment — hardened application-owned units and environment templates:
  - [`../apps/edgeproxy/deploy/systemd/`](../apps/edgeproxy/deploy/systemd/)
  - [`../apps/securityedge/deploy/systemd/`](../apps/securityedge/deploy/systemd/)

Application-specific units remain next to the application they execute so their configuration contract, runtime paths, and documentation stay versioned together. The systemd deployment keeps secrets read-only under `/etc`, while transactionally managed JSON, telemetry history, and security logs live in writable `/var/lib` and `/var/log` locations.
