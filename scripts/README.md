# Platform Scripts

This directory is reserved for scripts that coordinate the complete platform, such as starting all host processes, validating the end-to-end request path, or collecting combined diagnostics.

Component-specific scripts remain with their owning application:

- `apps/edgeproxy/scripts/`
- `apps/securityedge/scripts/`

The full container stack is currently managed through `deployments/docker/compose.yml` rather than a wrapper script.
