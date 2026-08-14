# Production Docker Deployment

This directory adds production-oriented Docker deployments without changing the
existing local/demo workflows under `apps/edgeproxy/docker-compose.yml` and
`deployments/docker/compose.yml`.

The production definitions target Linux hosts and intentionally support three
operational modes. They use dedicated production Dockerfiles so the runtime
images contain only the required application binary, CA bundle, and minimal
secret-loading entrypoint; no helper script is bind-mounted from the checkout.

| Compose file | Runs in Docker | Expected peer |
|---|---|---|
| `compose.edgeproxy.yml` | EdgeProxy only | SecurityEdge remains a host service or other trusted peer |
| `compose.securityedge.yml` | SecurityEdge only | EdgeProxy remains a host service |
| `compose.platform.yml` | EdgeProxy + SecurityEdge | A real external Origin, including an Origin reached through Tailscale/VPN |

The full production stack does **not** run the repository's `origin-demo`.
Keeping the synthetic Origin exclusively in the existing demo Compose stack
prevents a test dependency from becoming part of a production topology.

## Production topology

Full platform:

```text
Internet / client
      │ HTTPS :443
      ▼
SecurityEdge container
      │ private Docker bridge
      ▼
EdgeProxy container
      │ host routing / VPN / Tailscale
      ▼
Real Origin
```

Only SecurityEdge's data plane is publicly published from the combined stack.
EdgeProxy's data plane remains private to the Docker network. Both Admin
listeners are published only on host loopback (`127.0.0.1:9090` for EdgeProxy
and `127.0.0.1:9191` for SecurityEdge) so local health/metrics tooling retains
the same operational boundary as the systemd deployment.

The two single-service definitions use Linux host networking deliberately. That
preserves an existing systemd deployment's loopback contract during a staged
migration:

```text
SecurityEdge systemd ──127.0.0.1──► EdgeProxy container
SecurityEdge container ──127.0.0.1──► EdgeProxy systemd
```

Using bridge NAT for these hybrid modes would change peer addresses and make a
host service bound only to `127.0.0.1` unreachable from the container. Host
networking avoids that semantic change. The combined deployment does not need
host networking and therefore uses the more isolated private bridge.

## Host requirements

The production helpers target a Linux Docker Engine host and require:

- a standard rootful Docker Engine with Docker Compose v2 (`docker compose`);
- Python 3 for bootstrap/preflight validation helpers;
- `sudo` when the operator account cannot create or inspect the protected
  `/var/lib`, `/var/log`, or `/etc` deployment paths;
- `openssl` for TLS certificate/key parsing, key matching, hostname/SAN checks,
  expiry checks, and automatic token generation when existing systemd
  credentials are not being imported (a `/dev/urandom` fallback is included).

The EdgeProxy-only and SecurityEdge-only migration profiles specifically use
Linux host networking. The full platform uses an ordinary user-defined bridge.
Rootless Docker is intentionally not supported by this production profile: the
protected systemd-compatible host paths, root-owned file-backed secrets, and
host-network migration modes rely on the standard rootful Docker Engine model.

## Security model

All production services:

- run as non-root numeric UID/GID values;
- use a read-only container root filesystem;
- drop all Linux capabilities unless one is strictly required;
- enable `no-new-privileges`;
- use an init process for signal/reaping correctness;
- receive bounded CPU, memory, PID, and file-descriptor limits;
- rotate Docker stdout/stderr logs;
- keep mutable Control Plane state outside the image;
- keep TLS material read-only;
- stop gracefully with `SIGTERM` and a 30-second grace period;
- use Docker health checks backed by each application's `/readyz` endpoint.

The two host-network single-service profiles add only `NET_BIND_SERVICE`. This
keeps both applications non-root while still allowing an operator to retain a
native privileged HTTPS listener such as port `443` when that standalone
profile is intentionally configured to use one. The combined deployment maps
public host `443` to unprivileged SecurityEdge container port `8443`, while its
private EdgeProxy data listener also uses an unprivileged port, so neither full-
platform container needs an added capability.

Admin tokens are Docker secrets, not Compose environment values. The minimal
entrypoint wrappers read the secret files immediately before `exec` and export
the variables only inside the application process. This keeps token values out
of the Compose manifest and out of normal `docker inspect` environment output.

## State and rollback compatibility

By default the production definitions reuse the same host paths as the systemd
deployment:

```text
/var/lib/edgeproxy/config.json
/var/lib/securityedge/securityedge.json
/var/lib/securityedge/telemetry-history.json
/var/log/securityedge/
/etc/edgeproxy/tls/
/etc/securityedge/tls/
```

This is deliberate. Route, Origin, scheduler, WAF, policy, and telemetry state
remain authoritative across a systemd-to-Docker migration, and rollback does
not require exporting a Docker named volume.

The JSON state directories are bind-mounted as directories rather than single
files. Both Control Planes use atomic replacement and timestamped backups, so a
single-file bind mount would break valid updates. The host paths remain
systemd-compatible, while the container targets follow the application image
contract:

```text
host /var/lib/edgeproxy       → EdgeProxy /app/config
host /var/lib/securityedge    → SecurityEdge /app/config
host /var/log/securityedge    → SecurityEdge /app/logs
host /var/lib/edgeproxy       → SecurityEdge /edgeproxy-config (read-only)
```

Using `/app/config` and `/app/logs` also satisfies the SecurityEdge image's
explicit volume contract and prevents Docker from creating unintended anonymous
volumes. SecurityEdge receives the EdgeProxy state directory read-only and uses
that shared file when rendering Routes/Origins and evaluating route-specific
policy state.

## 1. Prepare the production environment

From the repository root:

```bash
cd deployments/docker-production
cp .env.example .env
```

If the VPS already has the project installed through systemd, prefer the
bootstrap helper. It discovers existing `edgeproxy` / `securityedge` UID/GID
values, preserves existing JSON state, imports existing Admin tokens when
possible, never replaces existing state/TLS/secret contents, and normalizes
secret ownership for the non-root container identities:

```bash
bash ./scripts/bootstrap.sh platform
```

For a staged migration use one of:

```bash
bash ./scripts/bootstrap.sh edgeproxy
bash ./scripts/bootstrap.sh securityedge
```

For a fresh deployment, inspect `.env` after bootstrap and review the seeded
JSON profiles before starting anything. In particular, replace example Origin
URLs and hostnames with real production values. Full-platform preflight rejects
a profile that still contains only `.test`, `.local`, or loopback route hosts.

Production Origin guardrails default to HTTPS with certificate verification:

```text
EDGEPROXY_REQUIRE_HTTPS_ORIGINS=true
EDGEPROXY_ALLOW_INSECURE_ORIGIN_TLS=false
```

An operator can explicitly relax either guardrail in `.env` for a controlled
environment, but the exception should be deliberate rather than inherited from
a development profile.

### Existing service identities

On a host that already has the systemd deployment, these values should normally
match `.env` after bootstrap:

```bash
id -u edgeproxy
id -g edgeproxy
id -u securityedge
id -g securityedge
```

Do not work around ownership problems with `chmod 777` and do not run the
application containers as root.

## 2. Secrets

Production secret files contain only the raw token, followed by an optional
newline:

```text
deployments/docker-production/secrets/edgeproxy_admin_token
deployments/docker-production/secrets/securityedge_admin_token
```

They are excluded from Git. `bootstrap.sh` stores them as `root:<service-gid>`
with mode `0440`: the EdgeProxy token uses `EDGEPROXY_GID`, while the
SecurityEdge token uses `SECURITYEDGE_GID`. This matters because file-backed
Compose secrets are bind-mounted from the host; the non-root containers must
therefore receive read access through the service group without making the
secret world-readable. `doctor.sh` rejects ownership or mode drift.

For full-platform mode the same EdgeProxy token secret is mounted into both
applications, which guarantees that SecurityEdge and EdgeProxy use one shared
Admin credential without copying it into JSON.

For SecurityEdge-only mode, `edgeproxy_admin_token` **must** match the existing
host EdgeProxy. The bootstrap helper imports `/etc/edgeproxy/edgeproxy.env` when
available and refuses to invent a mismatched token for this mode.

## 3. Preflight and validation

Run the non-destructive preflight first:

```bash
bash ./scripts/doctor.sh platform
```

It checks state/config/TLS/secret presence, runtime UID/GID access to writable
state and logs, secret permissions, TLS certificate parsing/key matching/expiry/
SAN coverage and container-readable path traversal, fixed-IP network consistency,
Docker/rootless-engine constraints, existing Docker-network overlap, and
`docker compose config` when Docker Compose is installed. It also rejects
loopback Origins in the full stack and warns if the selected private subnet
overlaps a host route.

Then build both images and run each application's own configuration validator
inside its production container context:

```bash
bash ./scripts/validate.sh platform
```

Single-service equivalents:

```bash
bash ./scripts/validate.sh edgeproxy
bash ./scripts/validate.sh securityedge
```

Do not stop a working systemd service until these checks pass.

## 4. EdgeProxy-only production Docker

Use this mode when SecurityEdge continues to run through systemd or another
trusted host process.

Because this Compose file uses host networking, the existing EdgeProxy profile
can keep loopback listeners such as `127.0.0.1:8080` and `127.0.0.1:9090`.
SecurityEdge continues to connect to the same addresses. Set
`EDGEPROXY_ADMIN_PORT` in `.env` to the Admin port in the retained EdgeProxy
JSON profile; `doctor.sh` enforces that match so the container health check
cannot silently probe the wrong port.

Before starting Docker, stop only EdgeProxy:

```bash
sudo systemctl stop edgeproxy.service
```

Do **not** stop SecurityEdge unless its unit has a hard `Requires=edgeproxy`
relationship that stops it automatically. In that case start EdgeProxy Docker
first, verify it, then start/restart SecurityEdge.

Start:

```bash
docker compose \
  --env-file .env \
  -f compose.edgeproxy.yml \
  up -d --build
```

Verify:

```bash
docker compose --env-file .env -f compose.edgeproxy.yml ps
curl -fsS http://127.0.0.1:9090/healthz
a=0; until curl -fsS http://127.0.0.1:9090/readyz; do a=$((a+1)); [ "$a" -lt 30 ] || exit 1; sleep 1; done
```

If SecurityEdge is still a host service, verify its request path afterward.

## 5. SecurityEdge-only production Docker

Use this mode when EdgeProxy remains a systemd host service. Linux host
networking allows the container to continue using EdgeProxy loopback addresses
from the existing production JSON profile. Set `SECURITYEDGE_ADMIN_PORT` in
`.env` to the Admin port in that retained SecurityEdge profile; preflight
requires the values to match so the Docker health check targets the actual
listener.

Stop only SecurityEdge before starting the container:

```bash
sudo systemctl stop securityedge.service
```

Keep EdgeProxy running and verify it first:

```bash
curl -fsS http://127.0.0.1:9090/healthz
curl -fsS http://127.0.0.1:9090/readyz
```

Start SecurityEdge:

```bash
docker compose \
  --env-file .env \
  -f compose.securityedge.yml \
  up -d --build
```

Verify:

```bash
docker compose --env-file .env -f compose.securityedge.yml ps
curl -fsS http://127.0.0.1:9191/healthz
curl -fsS http://127.0.0.1:9191/readyz
```

Then verify public HTTPS using the real domain and certificate.

## 6. Full production platform

This is the preferred all-container production mode.

Before migration, validate the images while systemd is still serving traffic:

```bash
bash ./scripts/doctor.sh platform
bash ./scripts/validate.sh platform
```

Back up current binaries/configuration according to the systemd deployment
runbook, then stop the ingress first and EdgeProxy second:

```bash
sudo systemctl stop securityedge.service
sudo systemctl stop edgeproxy.service
```

Start the Docker platform:

```bash
docker compose \
  --env-file .env \
  -f compose.platform.yml \
  up -d --build
```

Observe startup:

```bash
docker compose --env-file .env -f compose.platform.yml ps
docker compose --env-file .env -f compose.platform.yml logs --tail=100 edgeproxy
docker compose --env-file .env -f compose.platform.yml logs --tail=100 securityedge
```

The combined deployment intentionally waits only for the EdgeProxy container to
start, not for it to become ready. An external Origin can be temporarily down;
SecurityEdge should still start so the dashboard can report the degraded state.
Health checks then expose readiness independently.

Verify local Admin endpoints:

```bash
curl -fsS http://127.0.0.1:9191/healthz
curl -fsS http://127.0.0.1:9191/readyz
```

EdgeProxy Admin remains loopback-only and can therefore be checked from the
host without exposing the data plane:

```bash
curl -fsS http://127.0.0.1:9090/healthz
curl -fsS http://127.0.0.1:9090/readyz
```

Then test the complete public path:

```bash
curl -v https://YOUR_DOMAIN/healthz
curl -i https://YOUR_DOMAIN/api/products
curl -i https://YOUR_DOMAIN/api/products
curl -i 'https://YOUR_DOMAIN/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'
```

Expected application behavior is still `MISS → HIT` for a cacheable endpoint
and `403` for the WAF test request.

## Tailscale / VPN Origins

The full platform bridge allows outbound traffic; EdgeProxy is not placed on an
`internal: true` Docker network because it must reach real Origins.

After startup, verify the configured Origin from the EdgeProxy container. Use a
real endpoint from the active route configuration, for example:

```bash
docker compose --env-file .env -f compose.platform.yml exec edgeproxy \
  wget -S -O /dev/null https://ORIGIN_TAILSCALE_NAME_OR_IP/healthz
```

If a host firewall or VPN policy blocks Docker-bridge traffic to the VPN
interface, fix that routing/firewall policy rather than publishing EdgeProxy to
the Internet. Keep the Origin health test and certificate verification enabled.

## Public TLS

The combined production stack always enables native SecurityEdge TLS and maps
host port `443` to unprivileged container port `8443` by default. The certificate
and key are mounted read-only from the host.

Defaults:

```text
/etc/securityedge/tls/fullchain.pem
/etc/securityedge/tls/privkey.pem
```

Set `SECURITYEDGE_PUBLIC_HOSTNAME` in `.env` to the public DNS name used by
clients. `doctor.sh` verifies that the mounted certificate covers that hostname.
For Internet-facing ingress, use a certificate chain trusted by the intended
public clients; adding a private CA to the containers' outbound trust directory
does not make browsers or external clients trust that CA. Do not use
`insecure_skip_verify` for public or Origin TLS merely to make a deployment
start.

### EdgeProxy TLS inside the private bridge

The production template defaults to HTTPS on the SecurityEdge → EdgeProxy data
plane as well as public ingress. Set `EDGEPROXY_INTERNAL_HOSTNAME` to a hostname
covered by the mounted EdgeProxy certificate; the same value becomes a private
Docker-network alias, so normal hostname verification remains enabled:

```text
EDGEPROXY_INTERNAL_SCHEME=https
EDGEPROXY_INTERNAL_PORT=8443
EDGEPROXY_INTERNAL_TLS_ENABLED=true
EDGEPROXY_INTERNAL_HOSTNAME=edgeproxy.example.com
```

`doctor.sh platform` validates that the certificate and key match, the
certificate is current, and its SAN covers this hostname. If an operator
explicitly accepts plaintext for this same-host private bridge, the supported
opt-out is:

```text
EDGEPROXY_INTERNAL_SCHEME=http
EDGEPROXY_INTERNAL_PORT=8080
EDGEPROXY_INTERNAL_TLS_ENABLED=false
```

The EdgeProxy data plane remains un-published in either case.

### Public and private CA trust

The production containers keep the standard Alpine CA bundle and additionally
set `SSL_CERT_DIR` to include the read-only host directory configured by
`SECUREEDGE_CA_DIR` (default `/etc/secureedge/ca`). Leave that directory empty
when every outbound HTTPS certificate chains to a normal public/system root.
For a private EdgeProxy or Origin PKI, place the **issuing CA certificate**, not
the server private key, in this directory as a `.crt` or `.pem` file. Both
SecurityEdge and EdgeProxy then retain normal public-root trust while also
trusting that private CA. `doctor.sh` parses each custom CA file and verifies it
is contained in and readable from the mounted CA directory.

This is preferable to `insecure_skip_verify`: certificate hostname/IP checking
and chain verification remain enabled. After changing CA files, recreate or
restart the application containers so newly created TLS clients load the new
trust set.

### Certificate mount and Certbot symlinks

Certificate and key paths must resolve **inside the directory that is actually
bind-mounted into the container**, and the configured non-root service UID/GID
must be able to traverse every parent directory and read both files.
`doctor.sh` enforces these rules before deployment.

This matters for a typical Certbot `live/` directory: files such as
`live/example.com/fullchain.pem` are symlinks into `archive/example.com/`.
Mounting only the `live/example.com` directory would leave those symlink targets
outside the container and is rejected. Use one of these production-safe
patterns instead:

1. deploy/copy the active certificate chain and key into the dedicated
   `/etc/securityedge/tls` or `/etc/edgeproxy/tls` directory with directory mode
   `0750`, files readable by the matching service group (for example `0640`),
   and update them atomically during renewal; or
2. deliberately bind a TLS directory that contains the complete relative
   symlink target tree and set the container certificate/key paths to matching
   nested paths.

Do not weaken private-key permissions or use `chmod 777` to make a mount work.

## Network trust contract

The full stack assigns SecurityEdge a fixed address because EdgeProxy may trust
forwarded client identity only from the actual SecurityEdge peer:

```text
SECUREEDGE_PROD_SUBNET=172.31.250.0/24
SECURITYEDGE_CONTAINER_IPV4=172.31.250.10
SECURITYEDGE_TRUSTED_PROXY_CIDR=172.31.250.10/32
```

These values are one contract. If the subnet/IP changes, update the `/32` CIDR
together. `scripts/doctor.sh platform` verifies this relationship.

Choose a subnet that does not overlap the VPS LAN, Docker networks, cloud VPC,
or VPN/Tailscale routes.

## Deployment-owned overrides

The combined Compose deployment uses environment overrides for topology fields
that must be fixed by orchestration rather than Dashboard state, including:

- container listen addresses;
- SecurityEdge-to-EdgeProxy service URLs;
- the EdgeProxy trusted SecurityEdge CIDR;
- public SecurityEdge TLS enablement and certificate paths;
- SecurityEdge log/history paths inside the container.

The applications intentionally reject Dashboard/API writes to environment-owned
fields. Route/Origin, cache, WAF, policy, scheduler, and other mutable settings
remain file-backed unless an operator deliberately adds another environment
override.

The single-service host-network definitions preserve the existing listener and
peer-network semantics during migration. SecurityEdge-only mode overrides only
container filesystem paths for its mutable config/history/logs and the
read-only EdgeProxy config view, because those host directories are mounted at
the image-native `/app/...` locations.

## Secret rotation

Admin secrets are read when each container starts. To rotate the shared
EdgeProxy Admin token in full-platform mode, create a new value, atomically
replace the host file with the same `root:EDGEPROXY_GID` / `0440` policy, and
recreate **both** application containers so both processes receive the same new
value:

```bash
EDGE_GID=$(awk -F= '$1=="EDGEPROXY_GID"{print $2}' .env)
tmp=$(mktemp)
openssl rand -hex 32 > "$tmp"
sudo install -o root -g "$EDGE_GID" -m 0440 "$tmp" secrets/.edgeproxy_admin_token.new
sudo mv -f secrets/.edgeproxy_admin_token.new secrets/edgeproxy_admin_token
rm -f "$tmp"
docker compose --env-file .env -f compose.platform.yml up -d --force-recreate edgeproxy securityedge
```

To rotate only the SecurityEdge Dashboard/Admin token, use the same procedure
with `SECURITYEDGE_GID` and `secrets/securityedge_admin_token`, then recreate
SecurityEdge only.

Do not rotate only one side of the shared EdgeProxy credential; SecurityEdge
would immediately lose authenticated access to the EdgeProxy Admin API.

## Certificate renewal

TLS directories are mounted read-only, so certificate renewal remains a host
operation. After the host certificate files/symlinks have been renewed, restart
the process that terminates that certificate so Go reloads it:

```bash
docker compose --env-file .env -f compose.platform.yml restart securityedge
```

Because internal EdgeProxy TLS is enabled by default in the full production
profile, restart EdgeProxy when its certificate is renewed and verify
SecurityEdge-to-EdgeProxy HTTPS before returning the deployment to service. If
you explicitly opted out of internal TLS, this EdgeProxy certificate step does
not apply.

## Updates

A normal source update does not require deleting state:

```bash
git pull --ff-only origin main
cd deployments/docker-production
bash ./scripts/validate.sh platform
docker compose --env-file .env -f compose.platform.yml up -d --build
```

Compose recreates changed application containers while preserving bind-mounted
state, logs, and TLS material.

Never use `docker compose down -v` as a production reset procedure. These
production definitions intentionally use host bind mounts rather than named
state volumes, but destructive host-state removal would still lose Control
Plane configuration/history.

## Rollback to systemd

Stop the production containers:

```bash
docker compose --env-file .env -f compose.platform.yml down
```

Because mutable state remains in the systemd-compatible host paths, restart in
dependency order:

```bash
sudo systemctl start edgeproxy.service
curl -fsS http://127.0.0.1:9090/readyz
sudo systemctl start securityedge.service
curl -fsS http://127.0.0.1:9191/readyz
```

Do not disable or delete the systemd unit files until the Docker deployment has
survived the required acceptance/reboot tests. Once Docker is the selected boot
path, disable the old units to prevent port conflicts after reboot:

```bash
sudo systemctl disable edgeproxy.service securityedge.service
```

## Reboot behavior

All production containers use `restart: unless-stopped`. After a successful
migration and after the old systemd units are disabled, verify a VPS reboot:

```bash
sudo reboot
```

After reconnecting:

```bash
cd ~/SecureEdge-Platform/deployments/docker-production
docker compose --env-file .env -f compose.platform.yml ps
curl -fsS http://127.0.0.1:9191/readyz
```

Also repeat public HTTPS, Origin reachability, cache, WAF, and dashboard checks.

## Existing demo Docker workflows remain unchanged

These files retain their original local/demo purpose:

```text
apps/edgeproxy/docker-compose.yml
apps/edgeproxy/Dockerfile
deployments/docker/compose.yml
deployments/docker/.env.example
deployments/docker/README.md
```

Use `deployments/docker-production/` only for production/container migration.
