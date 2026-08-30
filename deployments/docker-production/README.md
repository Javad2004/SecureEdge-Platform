# Standalone Production Docker Deployment

This directory is the **production** Docker deployment family for SecureEdge.
It is intentionally separate from the repository's local/demo Docker workflows,
which remain available for development and self-contained demonstrations.

The production deployment is fully standalone: a fresh Linux VPS needs Docker
Engine, Docker Compose v2, Python 3 and OpenSSL, but it does **not** need
SecureEdge systemd units, host `edgeproxy`/`securityedge` accounts, existing
`/var/lib/...` state, or a previous installation. Runtime state lives under one
self-contained host root, `/srv/secureedge` by default.

An existing systemd installation can still be imported with the explicitly
optional `scripts/import-systemd.sh` helper. That is a migration convenience,
not a runtime dependency.

## Production modes

| Compose file | Containers | Peer dependency |
|---|---|---|
| `compose.edgeproxy.yml` | EdgeProxy | Real external Origin |
| `compose.securityedge.yml` | SecurityEdge | Independently operated EdgeProxy + local read-only route-config mirror |
| `compose.platform.yml` | EdgeProxy + SecurityEdge | Real external Origin |

The production family never runs `origin-demo`. The existing demo stack remains
available under `deployments/docker/` for self-contained demonstrations.

## Full-platform topology

```text
Internet / clients
       │ HTTPS :443
       ▼
SecurityEdge container
       │ HTTPS by default
       │ private Docker bridge
       ▼
EdgeProxy container
       │ HTTPS by default
       ▼
Real Origin (LAN / cloud / Tailscale / VPN)
```

In full-platform mode only SecurityEdge publishes a public data-plane port.
EdgeProxy's data plane stays private to the Docker network, so clients cannot
bypass the WAF. Both Admin APIs are published only to configurable non-public
host addresses; the defaults are loopback:

```text
127.0.0.1:9090 → EdgeProxy Admin
127.0.0.1:9191 → SecurityEdge Admin
```

## Independent runtime tree

`bootstrap.sh` creates this structure by default:

```text
/srv/secureedge/
├── edgeproxy/
│   └── config.json
├── securityedge/
│   ├── securityedge.json
│   └── telemetry-history.json      # created at runtime
├── logs/
│   └── securityedge/
├── tls/
│   ├── edgeproxy/
│   │   ├── fullchain.pem
│   │   └── privkey.pem
│   └── securityedge/
│       ├── fullchain.pem
│       └── privkey.pem
├── ca/                              # optional private CA certificates
└── secrets/
    ├── edgeproxy_admin_token
    └── securityedge_admin_token
```

Change `SECUREEDGE_DATA_ROOT` in `.env` before bootstrap when another absolute
host path is required. No matching host user accounts are necessary: the
containers and bind mounts use numeric identities (`10001:10001` and
`10002:10002` by default). `doctor.sh` requires those selected UIDs/GIDs to be
unassigned on the host and keeps the two services' UIDs/GIDs distinct. If a
fresh server already uses one of the defaults, choose unused values in `.env`
before bootstrap rather than sharing a host identity with a container.

Mutable config is mounted as a **directory**, not a single file. This preserves
atomic Control Plane updates, timestamped backups and file replacement. TLS and
CA directories are read-only inside containers. Container root filesystems are
read-only; `/tmp` is a bounded `tmpfs`.

## Security baseline

Host prerequisites include a rootful Docker Engine **28.0.0 or newer** and
Docker Compose v2. Engine 28+ is required because the deployment relies on
loopback-only Admin port publication as a security boundary; `doctor.sh` checks
the server version before rendering/starting production Compose.

Production services use:

- dedicated multi-stage production images;
- non-root numeric identities;
- `read_only: true` container roots;
- `cap_drop: ALL` and `no-new-privileges`;
- bounded CPU, memory, PID and file-descriptor limits;
- Docker log rotation;
- an init process and graceful `SIGTERM` shutdown;
- Docker secrets rather than raw Admin-token environment values;
- fail-closed bind mounts (`create_host_path: false`) provisioned only by bootstrap;
- root-owned data/CA/secret roots and non-group-writable shared config state;
- TLS and private-CA validation before deployment;
- Origin HTTPS + certificate verification by default;
- Admin publication restricted to non-public host addresses;
- `/healthz` for container health and `/readyz` for operational readiness.

Health checks intentionally use `/healthz`: an Origin outage can make
`/readyz` return 503 while the EdgeProxy/SecurityEdge process itself is healthy
and should remain running. Deployment smoke tests check both endpoints.

## 1. Fresh-host bootstrap

From the repository root:

```bash
cd deployments/docker-production
cp .env.example .env
```

Review `.env`, especially hostnames, ports and resource limits, then bootstrap
the required mode. Production helpers intentionally accept a strict, unambiguous
`KEY=value` subset: keep one definition per key, do not quote values, do not add
inline comments after values, and write resolved values instead of `$VAR`
interpolation. This prevents the preflight parser and Docker Compose from
interpreting the same deployment setting differently.


```bash
bash ./scripts/bootstrap.sh edgeproxy
bash ./scripts/bootstrap.sh securityedge
bash ./scripts/bootstrap.sh platform
```

`bootstrap.sh` is idempotent. It never overwrites existing state, secrets, TLS
or CA files. Fresh EdgeProxy/full-platform modes generate a cryptographically
random EdgeProxy Admin token; fresh SecurityEdge/full-platform modes generate a
SecurityEdge Admin token. Admin credentials are used as single HTTP Bearer-token
fields that must be valid UTF-8 and have a maximum normalized size of 8192 UTF-8 bytes; bootstrap-generated
values already satisfy this contract, while oversized imported credentials or
manually supplied tokens containing embedded whitespace or control characters
are rejected by application configuration validation. The literal `[REDACTED]`
value is reserved for Control Plane secret-preservation responses and is rejected
as a deployable credential. `doctor.sh` validates staged Secret-file contents against
the same contract before Compose is started, reading the credential through standard input
rather than process arguments and without echoing the credential itself.

### SecurityEdge-only special requirement

SecurityEdge needs the **actual Admin token of the independently operated
EdgeProxy**. Bootstrap therefore refuses to invent that credential. Place the
real token at:

```text
$SECUREEDGE_DATA_ROOT/secrets/edgeproxy_admin_token
```

with numeric group `EDGEPROXY_GID` and mode `0440`, then rerun bootstrap.
SecurityEdge-only also needs an accurate read-only EdgeProxy config mirror at:

```text
$SECUREEDGE_DATA_ROOT/edgeproxy/config.json
```

Keep that mirror **continuously synchronized** with the external EdgeProxy so
route-specific WAF, Dashboard and policy semantics remain accurate. SecurityEdge
watches this file at runtime; a one-time copy is not sufficient after the
external EdgeProxy route table changes. For a co-located independently managed
EdgeProxy, provide a safely synchronized/shared copy of its committed config;
for a remote EdgeProxy, use an atomic replication mechanism. If that live route
mirror cannot be guaranteed, use `compose.platform.yml` so both containers share
the same persistent EdgeProxy state directly.

## 2. Replace template placeholders

Fresh bootstrap seeds:

```text
$SECUREEDGE_DATA_ROOT/edgeproxy/config.json
$SECUREEDGE_DATA_ROOT/securityedge/securityedge.json
```

from `templates/`. The templates are syntactically valid but intentionally use
`.example.invalid` hosts. `doctor.sh` refuses to deploy them unchanged.

At minimum update the EdgeProxy route hosts and real Origin URL. Keep production
Origins HTTPS unless an explicit documented exception is required. Preflight
rejects placeholder/local Origin names (including canonicalized trailing-dot
forms), missing Origin hostnames, loopback/unspecified/multicast IPs, malformed
ports, and insecure TLS verification.

For SecurityEdge-only also set in `.env`:

```text
SECURITYEDGE_EXTERNAL_EDGEPROXY_URL=https://...
SECURITYEDGE_EXTERNAL_EDGEPROXY_ADMIN_URL=http://...
```

EdgeProxy Admin does not provide native TLS. A remote Admin URL therefore must
travel only over a trusted private/VPN/Tailscale path, never the public Internet.
`doctor.sh` enforces this baseline: an IP literal must be non-global, while a
hostname must resolve during preflight and every resolved address must remain
private/VPN-scoped. Loopback, unspecified, multicast, reserved and globally
routable Admin endpoints are rejected.

## 3. TLS and CA material

Install certificate chains and matching private keys under the independent data
root. Default container paths are:

```text
EdgeProxy:    /etc/edgeproxy/tls/fullchain.pem
              /etc/edgeproxy/tls/privkey.pem
SecurityEdge: /etc/securityedge/tls/fullchain.pem
              /etc/securityedge/tls/privkey.pem
```

Host sources are:

```text
$SECUREEDGE_DATA_ROOT/tls/edgeproxy/
$SECUREEDGE_DATA_ROOT/tls/securityedge/
```

The EdgeProxy-only certificate must cover `EDGEPROXY_PUBLIC_HOSTNAME`; the
full-platform EdgeProxy certificate must cover `EDGEPROXY_INTERNAL_HOSTNAME`;
SecurityEdge must cover `SECURITYEDGE_PUBLIC_HOSTNAME`.

Place private CA certificates (`.crt`/`.pem`) in:

```text
$SECUREEDGE_DATA_ROOT/ca/
```

when an internal EdgeProxy or Origin uses a private CA. System CA roots remain
trusted alongside this directory. `doctor.sh` validates PEM parsing, key match,
SAN coverage, expiry, chain trust, symlink containment and non-root readability.

## 4. Preflight and image/config validation

Run the non-destructive preflight:

```bash
bash ./scripts/doctor.sh platform
```

Then build images and run the application's own `-validate` command inside the
production container context:

```bash
bash ./scripts/validate.sh platform
```

Use `edgeproxy` or `securityedge` instead of `platform` for single-service
modes. In full-platform mode the validator is safe to run during an in-place
update: the live SecurityEdge keeps its fixed production address while the
one-off validation container automatically receives another free temporary
address on the same Docker network. This avoids the `Address already in use`
collision that a plain `docker compose run securityedge ...` would cause while
the production container is running. Do not put fresh production traffic on
new containers until both commands pass.

## 5. Start a fresh Docker deployment

### EdgeProxy only

```bash
docker compose --env-file .env -f compose.edgeproxy.yml up -d --build
```

The safe default publishes EdgeProxy only on `127.0.0.1:8443`. Change
`EDGEPROXY_HTTPS_BIND_IP`/`EDGEPROXY_HTTPS_PORT` deliberately when another
SecurityEdge host or public client must reach it.

### SecurityEdge only

```bash
docker compose --env-file .env -f compose.securityedge.yml up -d --build
```

This mode uses an ordinary bridge network; it does not assume an EdgeProxy on
host loopback. `SECURITYEDGE_EXTERNAL_EDGEPROXY_URL` and its Admin URL identify
the real independently operated peer. Preflight structurally validates both
endpoints, including DNS-host syntax, usable ports, credentials and URL
components; the HTTP Admin endpoint additionally must resolve only to a trusted
private/VPN address.

### Full platform

Before the first start, choose `SECUREEDGE_PROD_SUBNET`,
`SECUREEDGE_PROD_GATEWAY`, `SECURITYEDGE_CONTAINER_IPV4` and
`SECUREEDGE_PROD_NETWORK_NAME` so they do not collide with cloud/LAN/VPN or
existing Docker networks. The current fixed-address production contract is
IPv4-only and `SECURITYEDGE_TRUSTED_PROXY_CIDR` must be exactly the selected
SecurityEdge address as a `/32`. `EDGEPROXY_INTERNAL_HOSTNAME` must be a real
DNS hostname (not an IP literal) because Compose registers it as the private
network alias and SecurityEdge uses the same name for TLS/SNI. `doctor.sh`
rejects supernet/subnet host-route overlaps and conflicting Docker networks; an
already-running network owned by this same production deployment is recognized
and allowed for safe updates.

```bash
docker compose --env-file .env -f compose.platform.yml up -d --build
```

SecurityEdge waits until the EdgeProxy container passes its process-health
check before starting. EdgeProxy data traffic remains unexposed to the host.

## 6. Verify the deployment

Inspect status and logs:

```bash
docker compose --env-file .env -f compose.platform.yml ps
docker compose --env-file .env -f compose.platform.yml logs --tail=200
```

Process health:

```bash
curl -fsS http://127.0.0.1:${EDGEPROXY_ADMIN_PORT:-9090}/healthz
curl -fsS http://127.0.0.1:${SECURITYEDGE_ADMIN_PORT:-9191}/healthz
```

Operational readiness:

```bash
curl -i http://127.0.0.1:${EDGEPROXY_ADMIN_PORT:-9090}/readyz
curl -i http://127.0.0.1:${SECURITYEDGE_ADMIN_PORT:-9191}/readyz
```

Then test the real public chain without disabling certificate validation:

```bash
curl -v https://your-public-host.example/api/time
```

Verify cache `MISS → HIT`, WAF `403`, Dashboard Connectivity, Routes/Origins,
and that direct EdgeProxy data-plane access is unavailable in full-platform mode.

## 7. Updates

For normal source updates:

```bash
git pull --ff-only
cd deployments/docker-production
bash ./scripts/doctor.sh platform
bash ./scripts/validate.sh platform
docker compose --env-file .env -f compose.platform.yml up -d --build
```

Compose recreates changed containers while persistent state remains under
`SECUREEDGE_DATA_ROOT`.

## 8. Backups

Back up the entire independent data root plus the deployment `.env`:

```bash
sudo tar -C /srv -czf secureedge-data-$(date +%Y%m%d-%H%M%S).tar.gz secureedge
cp .env secureedge-production.env.backup
```

Protect backups because they contain Admin secrets and private keys. For a
custom `SECUREEDGE_DATA_ROOT`, back up that directory instead.

## 9. Credential and certificate rotation

Treat token and TLS rotation as explicit production operations rather than
editing values inside running containers. Back up the independent data root
first and run `doctor.sh` after replacing material.

For TLS renewal, replace the certificate/key files **inside the mounted TLS
directory** while preserving the expected ownership and restrictive modes. Then
run the mode-specific doctor and restart only the service that terminates that
certificate so it reopens the files. In full-platform mode, rotate EdgeProxy and
SecurityEdge certificates independently. Verify `/healthz`, `/readyz`, the
certificate hostname/expiry, and the complete HTTPS request path afterwards.

For Admin-token rotation, write the new token atomically to the corresponding
file under `$SECUREEDGE_DATA_ROOT/secrets`, restore `root:<service-gid> 0440`,
and make the same token authoritative at the service that authenticates it. A
SecurityEdge token requires recreating/restarting SecurityEdge. An EdgeProxy
Admin-token rotation requires recreating/restarting EdgeProxy **and**
SecurityEdge because SecurityEdge authenticates to EdgeProxy with that secret.
Use `docker compose up -d --force-recreate <service...>` after the secret files
are updated so file-backed secret mounts and process environments are rebuilt,
then rerun the normal health/readiness and control-plane checks. Never place
rotated credentials in `.env` or Compose `environment:` entries.

## 10. Reboot behavior

The services use `restart: unless-stopped`; ensure Docker itself is enabled at
boot. After a host reboot verify `docker compose ps`, both `/healthz` endpoints,
readiness, HTTPS, cache and WAF behavior.

## Optional: import an existing systemd deployment

This is only for an already-installed host such as a VPS migrating from the
repository's systemd deployment. It is **not** part of fresh Docker bootstrap.

1. Commit/pull this standalone Docker deployment.
2. Create the standalone environment without seeding fresh-install placeholders:

```bash
cp .env.example .env
chmod 0600 .env
```

Review `.env`, especially `SECUREEDGE_DATA_ROOT`, the numeric container IDs,
ports, hostnames and resource limits. The importer uses this environment
directly and does **not** run `bootstrap.sh`. This matters particularly for
`securityedge` mode because the real EdgeProxy Admin token is imported from the
existing deployment rather than generated as a fresh-install placeholder.
3. Validate that the old systemd deployment is healthy and take a backup.
4. Stop only the service(s) whose mutable state will move into Docker:
   - `edgeproxy`: stop `edgeproxy.service`; SecurityEdge may remain online.
   - `securityedge`: stop `securityedge.service`; EdgeProxy may remain online.
     The importer snapshots only EdgeProxy `config.json` plus its Admin token for
     the local read-only mirror; it does not import the remote EdgeProxy TLS/state.
   - `platform`: stop both services.
5. Run:

```bash
bash ./scripts/import-systemd.sh platform
```

The importer copies only the state owned by the selected Docker mode into
`SECUREEDGE_DATA_ROOT`, normalizes numeric Docker ownership, and does not start,
enable, disable or delete systemd units. Full-platform migration includes both
services' state/TLS/logs; single-service migration keeps the other service
independent. TLS symlinks (for example Certbot/Let's Encrypt links) are
dereferenced during import so the Docker TLS directories contain self-contained
regular files rather than references to host paths outside the bind mount. Then
run `doctor.sh` and `validate.sh` before `docker compose up`.

If Docker validation fails, the old systemd units remain available for rollback.
After the Docker deployment has passed full traffic tests and at least one
reboot, the operator may disable the old units separately.

## Why the demo Docker files are separate

`apps/edgeproxy/docker-compose.yml` and `deployments/docker/compose.yml` remain
self-contained local/demo workflows, including the synthetic Origin where
appropriate. This directory has different constraints: real TLS, real Origins,
persistent production state, secret handling, resource bounds, non-root
runtime, backup/restore and operational preflight. Keeping the two families
separate prevents production hardening from making the teaching/demo workflow
needlessly complex and prevents demo assumptions from leaking into production.
