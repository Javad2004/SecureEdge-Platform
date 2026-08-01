# Deployments

This directory contains tested, platform-level deployment definitions that coordinate more than one application.

Current deployment:

- [`docker/`](docker/README.md) — complete three-service Docker Compose stack for Origin, EdgeProxy, and SecurityEdge.

Application-specific deployment assets remain with their owning application, such as the EdgeProxy systemd unit under `apps/edgeproxy/deploy/systemd`.
