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
  grep -q 'cap_drop:' "$compose"
  grep -q 'no-new-privileges:true' "$compose"
  grep -q '/healthz' "$compose"
  if grep -q '/readyz' "$compose"; then
    echo "container healthcheck must use process health, not dependency readiness: $compose" >&2
    exit 1
  fi
done

grep -q 'condition: service_healthy' "$prod_dir/compose.platform.yml"
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

# Existing demo Docker workflows must not be referenced as build/runtime state.
! grep -q 'origin-demo' "$prod_dir"/compose.*.yml

# Runtime credentials stay outside the build context by default.
grep -q 'deployments/docker-production/secrets/' "$repo_root/.dockerignore"

echo "production Docker standalone contract: PASS"
