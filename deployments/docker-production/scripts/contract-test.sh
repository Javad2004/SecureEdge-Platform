#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prod_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_root=$(CDPATH= cd -- "$prod_dir/../.." && pwd)

for script in "$script_dir"/*.sh; do bash -n "$script"; done
python3 - "$script_dir" <<'PYCODE'
from pathlib import Path
import ast, sys
for path in Path(sys.argv[1]).glob("*.py"):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
PYCODE
python3 - <<'PY' "$prod_dir/templates/edgeproxy.json" "$prod_dir/templates/securityedge.json"
import json, sys
for path in sys.argv[1:]:
    with open(path, encoding='utf-8') as fh:
        json.load(fh)
PY

python3 - <<'PY' "$prod_dir/.env.example"
from pathlib import Path
import re, sys
path = Path(sys.argv[1])
seen = set()
for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in raw:
        raise SystemExit(f"{path}:{lineno}: expected KEY=value")
    key, value = raw.split("=", 1)
    key = key.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in seen:
        raise SystemExit(f"{path}:{lineno}: invalid/duplicate key {key!r}")
    seen.add(key)
    if value != value.strip() or value.startswith(("'", '"')) or value.endswith(("'", '"')) or " #" in value or "\t#" in value or "$" in value:
        raise SystemExit(f"{path}:{lineno}: non-canonical production env value for {key}")
PY

# Core standalone files must not depend on systemd runtime paths or host
# networking. The explicit import-systemd.sh helper is intentionally excluded.
core=(
  "$prod_dir/.env.example"
  "$prod_dir/compose.edgeproxy.yml"
  "$prod_dir/compose.securityedge.yml"
  "$prod_dir/compose.platform.yml"
  "$script_dir/bootstrap.sh"
  "$script_dir/doctor.sh"
  "$script_dir/validate.sh"
)
if grep -nE 'network_mode:[[:space:]]*host|/var/lib/edgeproxy|/var/lib/securityedge|/var/log/securityedge|/etc/edgeproxy/edgeproxy\.env|/etc/securityedge/securityedge\.env|systemctl' "${core[@]}"; then
  echo "standalone Docker core still contains a systemd/host-network dependency" >&2
  exit 1
fi

for compose in "$prod_dir"/compose.*.yml; do
  grep -q 'read_only: true' "$compose"
  bind_count=$(grep -c 'type: bind' "$compose" || true)
  guarded_bind_count=$(grep -c 'create_host_path: false' "$compose" || true)
  [[ "$bind_count" -eq "$guarded_bind_count" ]] || {
    echo "every production bind mount must set create_host_path: false: $compose" >&2
    exit 1
  }
  grep -q 'cap_drop:' "$compose"
  grep -q 'no-new-privileges:true' "$compose"
  grep -q '/healthz' "$compose"
  if grep -q '/readyz' "$compose"; then
    echo "container healthcheck must use process health, not dependency readiness: $compose" >&2
    exit 1
  fi
done

# Single-service bootstrap/preflight must not couple SecurityEdge-only mode to
# EdgeProxy TLS material that it neither mounts nor consumes.
grep -q 'if \[\[ "$mode" == edgeproxy || "$mode" == platform \]\]; then' "$script_dir/bootstrap.sh"
grep -q 'tls_dirs=()' "$script_dir/doctor.sh"

grep -q 'condition: service_healthy' "$prod_dir/compose.platform.yml"
grep -q '28, 0, 0' "$script_dir/doctor.sh"
grep -q 'EDGEPROXY_UID and SECURITYEDGE_UID must be different' "$script_dir/doctor.sh"
grep -q 'EDGEPROXY_GID and SECURITYEDGE_GID must be different' "$script_dir/doctor.sh"
grep -q 'already assigned to a host account' "$script_dir/doctor.sh"
grep -q 'already assigned to a host group' "$script_dir/doctor.sh"
grep -q 'Full Platform Docker network is IPv4-only' "$script_dir/doctor.sh"
grep -q 'must be a DNS hostname, not an IP literal' "$script_dir/doctor.sh"
# Full platform must not expose EdgeProxy data plane.
python3 - "$prod_dir/compose.platform.yml" <<'PY'
from pathlib import Path
import sys
text=Path(sys.argv[1]).read_text()
edge=text.split('  securityedge:',1)[0]
if '${EDGEPROXY_HTTPS_PORT' in edge or ':8443:8443' in edge:
    raise SystemExit('full platform publishes EdgeProxy data plane')
PY
# Single-service modes must be bridge-isolated, not host-networked.
! grep -q 'network_mode:' "$prod_dir/compose.edgeproxy.yml"
! grep -q 'network_mode:' "$prod_dir/compose.securityedge.yml"


# Published ports use Compose long syntax with an explicit host_ip. This keeps
# host binding unambiguous for both IPv4 and IPv6 literals and makes exposure
# boundaries machine-auditable.
grep -q 'host_ip: "${EDGEPROXY_HTTPS_BIND_IP' "$prod_dir/compose.edgeproxy.yml"
grep -q 'host_ip: "${EDGEPROXY_ADMIN_BIND_IP' "$prod_dir/compose.edgeproxy.yml"
grep -q 'host_ip: "${SECURITYEDGE_HTTPS_BIND_IP' "$prod_dir/compose.securityedge.yml"
grep -q 'host_ip: "${SECURITYEDGE_ADMIN_BIND_IP' "$prod_dir/compose.securityedge.yml"
grep -q 'host_ip: "${EDGEPROXY_ADMIN_BIND_IP' "$prod_dir/compose.platform.yml"
grep -q 'host_ip: "${SECURITYEDGE_HTTPS_BIND_IP' "$prod_dir/compose.platform.yml"
grep -q 'host_ip: "${SECURITYEDGE_ADMIN_BIND_IP' "$prod_dir/compose.platform.yml"

# Existing demo Docker workflows must not be referenced as build/runtime state.
! grep -q 'origin-demo' "$prod_dir"/compose.*.yml

# Runtime credentials stay outside the build context by default.
grep -q 'deployments/docker-production/secrets/' "$repo_root/.dockerignore"

# Production Origin guardrails must reject placeholder/canonicalized local or
# structurally invalid endpoints before Docker is started.
checker="$script_dir/check-edgeproxy-profile.py"
valid_profile='{"routes":[{"name":"prod","hosts":["app.prod.secureedge"],"upstreams":[{"url":"https://origin.prod.secureedge:443","insecure_skip_verify":false}]}]}'
printf '%s\n' "$valid_profile" | python3 "$checker" --require-https true --allow-insecure false --require-real-hosts true --reject-loopback true
for bad_origin in \
  'https://origin.example.invalid:443' \
  'https://foo.localhost:443' \
  'https://localhost.:443' \
  'https://0.0.0.0:443' \
  'https://169.254.10.20:443' \
  'https://origin.prod.secureedge.internal:0' \
  'https://origin.prod.secureedge.internal:' \
  'https://bad host:443' \
  'https:///missing-host'; do
  bad_profile=$(python3 - "$bad_origin" <<'PYBAD'
import json, sys
print(json.dumps({"routes":[{"name":"prod","hosts":["app.prod.secureedge"],"upstreams":[{"url":sys.argv[1],"insecure_skip_verify":False}]}]}))
PYBAD
)
  if printf '%s\n' "$bad_profile" | python3 "$checker" --require-https true --allow-insecure false --require-real-hosts true --reject-loopback true >/dev/null 2>&1; then
    echo "production Origin guardrail accepted invalid endpoint: $bad_origin" >&2
    exit 1
  fi
done

# SecurityEdge-only external endpoints use a dedicated structural validator so
# malformed service names or unusable ports fail before container startup.
endpoint_checker="$script_dir/check-production-endpoint.py"
python3 "$endpoint_checker" --key DATA --value 'https://edge.prod.secureedge.internal:8443' --required-scheme https --scope any
python3 "$endpoint_checker" --key ADMIN --value 'http://10.123.45.68:9090' --required-scheme http --scope private
for bad_endpoint in \
  'https://bad_host:8443' \
  'https://edge.prod.secureedge.internal:0' \
  'https://edge.prod.secureedge.internal:' \
  'https://localhost.:8443' \
  'https://169.254.10.20:8443' \
  'https://user:pass@edge.prod.secureedge.internal:8443' \
  'https://edge.prod.secureedge.internal:8443/path' \
  'https://edge.example.invalid:8443'; do
  if python3 "$endpoint_checker" --key DATA --value "$bad_endpoint" --required-scheme https --scope any >/dev/null 2>&1; then
    echo "production external-endpoint guardrail accepted invalid endpoint: $bad_endpoint" >&2
    exit 1
  fi
done
if python3 "$endpoint_checker" --key ADMIN --value 'http://8.8.8.8:9090' --required-scheme http --scope private >/dev/null 2>&1; then
  echo 'production external Admin guardrail accepted globally routed HTTP endpoint' >&2
  exit 1
fi

# The fixed full-platform address has an explicit gateway/network identity so
# upgrades can distinguish the deployment's own existing bridge from conflicts.
grep -q '^SECUREEDGE_PROD_NETWORK_NAME=' "$prod_dir/.env.example"
grep -q '^SECUREEDGE_PROD_GATEWAY=' "$prod_dir/.env.example"
grep -q 'name: "${SECUREEDGE_PROD_NETWORK_NAME' "$prod_dir/compose.platform.yml"
grep -q 'gateway: "${SECUREEDGE_PROD_GATEWAY' "$prod_dir/compose.platform.yml"

echo "production Docker standalone contract: PASS"
