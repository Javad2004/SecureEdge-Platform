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
  "$script_dir/check-admin-secret.py"
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
  grep -q 'no-new-privileges=true' "$compose"
  ! grep -q 'no-new-privileges:true' "$compose"
  grep -q '/healthz' "$compose"
  if grep -q '/readyz' "$compose"; then
    echo "container healthcheck must use process health, not dependency readiness: $compose" >&2
    exit 1
  fi
done

# Docker Engine accepts both separators today, but current daemons deprecate
# the colon form for security options. Keep every checked-in Compose workflow
# on the canonical option=value form so container recreation stays warning-free.
all_compose=(
  "$prod_dir/compose.edgeproxy.yml"
  "$prod_dir/compose.securityedge.yml"
  "$prod_dir/compose.platform.yml"
  "$repo_root/deployments/docker/compose.yml"
  "$repo_root/apps/edgeproxy/docker-compose.yml"
)
for compose in "${all_compose[@]}"; do
  grep -q 'no-new-privileges=true' "$compose"
  if grep -q 'no-new-privileges:true' "$compose"; then
    echo "deprecated Docker security-opt separator remains: $compose" >&2
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
secret_checker="$script_dir/check-admin-secret.py"
grep -Fq 'protected_cat "$f" | python3 "$script_dir/check-admin-secret.py" --label "$label"' "$script_dir/doctor.sh"
grep -q 'secret cannot use the reserved \[REDACTED\] secret marker' "$secret_checker"
grep -q 'secret cannot contain embedded whitespace or control characters' "$secret_checker"
grep -q 'secret cannot exceed 8192 UTF-8 bytes' "$secret_checker"
grep -q 'secret must be valid UTF-8' "$secret_checker"
grep -q 'secret must contain only printable ASCII characters' "$secret_checker"
grep -q 'Go strings.TrimSpace uses unicode.IsSpace' "$secret_checker"
if grep -Eq 'check-admin-secret[.]py.*\$value|python3 - "\$label" "\$value"' "$script_dir/doctor.sh"; then
  echo "doctor.sh must not expose secret values through process arguments" >&2
  exit 1
fi

# The Doctor validator must normalize exactly like Go strings.TrimSpace. Python
# str.strip() additionally strips U+001C..U+001F, which would let preflight
# accept a secret that the application rejects as a control character.
printf 'valid-token' | python3 "$secret_checker" --label TEST
printf '\302\240valid-token\302\240' | python3 "$secret_checker" --label TEST
printf '\034valid-token\034' | python3 "$secret_checker" --label TEST >/dev/null 2>&1 && {
  echo 'production secret guardrail accepted U+001C at a credential boundary' >&2
  exit 1
}
printf '[REDACTED]' | python3 "$secret_checker" --label TEST >/dev/null 2>&1 && {
  echo 'production secret guardrail accepted the reserved marker' >&2
  exit 1
}
printf 'bad token' | python3 "$secret_checker" --label TEST >/dev/null 2>&1 && {
  echo 'production secret guardrail accepted embedded whitespace' >&2
  exit 1
}
printf 'Ã©-token' | python3 "$secret_checker" --label TEST >/dev/null 2>&1 && {
  echo 'production secret guardrail accepted a non-ASCII credential' >&2
  exit 1
}
python3 - <<'PYSECRET' | python3 "$secret_checker" --label TEST
import sys
sys.stdout.write("a" * 8192)
PYSECRET
python3 - <<'PYSECRET' | python3 "$secret_checker" --label TEST >/dev/null 2>&1 && {
import sys
sys.stdout.write("a" * 8193)
PYSECRET
  echo 'production secret guardrail accepted an oversized credential' >&2
  exit 1
}
printf '\377' | python3 "$secret_checker" --label TEST >/dev/null 2>&1 && {
  echo 'production secret guardrail accepted invalid UTF-8' >&2
  exit 1
}
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

# Python helpers are part of the production tooling. Bytecode/cache artifacts
# generated by local validation must never become repository or Docker context
# noise.
grep -Fqx '**/__pycache__/' "$repo_root/.gitignore"
grep -Fqx '*.py[cod]' "$repo_root/.gitignore"
grep -Fqx '**/__pycache__/' "$repo_root/.dockerignore"
grep -Fqx '**/*.py[cod]' "$repo_root/.dockerignore"

# Atomic configuration persistence retains timestamped rollback files using the
# suffix .bak-<UTC timestamp>. These copies can contain Admin credentials and
# must never become Git candidates or Docker build-context input.
grep -Fqx '*.bak-*' "$repo_root/.gitignore"
grep -Fqx '**/*.bak-*' "$repo_root/.dockerignore"
grep -Fqx '**/*.bak-*' "$repo_root/apps/edgeproxy/.dockerignore"
grep -Fqx '*.bak-*' "$repo_root/apps/securityedge/.gitignore"
grep -Fqx '*.tmp-*' "$repo_root/.gitignore"
grep -Fqx '**/*.tmp-*' "$repo_root/.dockerignore"
grep -Fqx '**/*.tmp-*' "$repo_root/apps/edgeproxy/.dockerignore"
grep -Fqx '*.tmp-*' "$repo_root/apps/securityedge/.gitignore"
grep -Fqx '.securityedge-write-probe-*' "$repo_root/.gitignore"
grep -Fqx '**/.securityedge-write-probe-*' "$repo_root/.dockerignore"
grep -Fqx '.securityedge-write-probe-*' "$repo_root/apps/securityedge/.gitignore"

# Doctor output must reflect Compose render failures accurately rather than
# printing a misleading OK line before the final preflight failure.
grep -Fq 'if (cd "$prod_dir" && docker compose --env-file .env -f "$compose" config -q); then' "$script_dir/doctor.sh"
grep -Fq 'Docker Compose render: FAILED ($compose)' "$script_dir/doctor.sh"

# Local/demo application images follow the same liveness/readiness split as
# production: Docker health tracks whether the process is alive, not whether
# every downstream dependency is currently ready.
for dockerfile in "$repo_root/apps/edgeproxy/Dockerfile" "$repo_root/apps/securityedge/Dockerfile"; do
  grep -q '/healthz' "$dockerfile"
  if grep -q '/readyz' "$dockerfile"; then
    echo "application container healthcheck must use process health, not dependency readiness: $dockerfile" >&2
    exit 1
  fi
done

# SecurityEdge's checked-in profiles reference repository-level integration
# fixtures. Both Docker build stages run go test ./..., so those fixtures must
# be copied before the test layer executes.
python3 - "$repo_root/apps/securityedge/Dockerfile" "$prod_dir/Dockerfile.securityedge" <<'PYDOCKER'
from pathlib import Path
import sys
for raw in sys.argv[1:]:
    path = Path(raw)
    text = path.read_text(encoding="utf-8")
    copy_pos = text.find("COPY integration /integration")
    test_pos = text.find("RUN CGO_ENABLED=0 go test ./...")
    if copy_pos < 0 or test_pos < 0 or copy_pos > test_pos:
        raise SystemExit(f"SecurityEdge Docker build must copy integration fixtures before go test: {path}")
PYDOCKER

# systemd migration must produce self-contained Docker TLS mounts even when the
# source installation uses Certbot/Let's Encrypt symlinks.
grep -q 'cp -aL "$src/." "$dst/"' "$script_dir/import-systemd.sh"

# Production Origin guardrails must reject placeholder/canonicalized local or
# structurally invalid endpoints before Docker is started.
checker="$script_dir/check-edgeproxy-profile.py"
valid_profile='{"routes":[{"name":"prod","hosts":["app.prod.secureedge"],"upstreams":[{"url":"https://origin.prod.secureedge:443","insecure_skip_verify":false}]}]}'
printf '%s\n' "$valid_profile" | python3 "$checker" --require-https true --allow-insecure false --require-real-hosts true --reject-loopback true
for private_origin in '10.123.45.67' '100.64.0.10' '[fd7a:115c:a1e0::2]'; do
  # Fixed contract literals contain no JSON metacharacters. Avoid a Python
  # encoder per case so this regression matrix stays lightweight in CI.
  private_profile=$(printf '{"routes":[{"name":"prod","hosts":["app.prod.secureedge"],"upstreams":[{"url":"https://%s:443","insecure_skip_verify":false}]}]}' "$private_origin")
  printf '%s\n' "$private_profile" | python3 "$checker" --require-https true --allow-insecure false --require-real-hosts true --reject-loopback true
done
for bad_origin in \
  'https://origin.example.invalid:443' \
  'https://foo.localhost:443' \
  'https://localhost.:443' \
  'https://0.0.0.0:443' \
  'https://169.254.10.20:443' \
  'https://192.0.2.1:443' \
  'https://198.51.100.1:443' \
  'https://203.0.113.1:443' \
  'https://198.18.0.1:443' \
  'https://[2001:db8::1]:443' \
  'https://origin.prod.secureedge.internal:0' \
  'https://origin.prod.secureedge.internal:' \
  'https://bad host:443' \
  'https:///missing-host'; do
  # bad_origin values above are fixed literals without JSON quotes or escapes.
  bad_profile=$(printf '{"routes":[{"name":"prod","hosts":["app.prod.secureedge"],"upstreams":[{"url":"%s","insecure_skip_verify":false}]}]}' "$bad_origin")
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
python3 "$endpoint_checker" --key ADMIN --value 'http://100.64.0.10:9090' --required-scheme http --scope private
python3 "$endpoint_checker" --key ADMIN --value 'http://[fd7a:115c:a1e0::1]:9090' --required-scheme http --scope private
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
for bad_admin_ip in '192.0.2.1' '198.51.100.1' '203.0.113.1' '198.18.0.1' '[2001:db8::1]'; do
  if python3 "$endpoint_checker" --key ADMIN --value "http://${bad_admin_ip}:9090" --required-scheme http --scope private >/dev/null 2>&1; then
    echo "production external Admin guardrail accepted non-routable special-use endpoint: $bad_admin_ip" >&2
    exit 1
  fi
done
if python3 "$endpoint_checker" --key ADMIN --value 'http://8.8.8.8:9090' --required-scheme http --scope private >/dev/null 2>&1; then
  echo 'production external Admin guardrail accepted globally routed HTTP endpoint' >&2
  exit 1
fi
link_local_error=$(python3 "$endpoint_checker" --key DATA --value 'https://169.254.10.20:8443' --required-scheme https --scope any 2>&1 || true)
if [[ "$link_local_error" != *"link-local address"* ]] || [[ "$link_local_error" == *"Traceback"* ]]; then
  echo 'production external-endpoint guardrail did not report a clean link-local validation error' >&2
  exit 1
fi

# Full-platform validation must remain safe while the production SecurityEdge
# container already owns its fixed ipv4_address. The one-off validator selects
# another free address on the same network rather than colliding with the live
# service.
grep -q 'platform_validation_ip()' "$script_dir/validate.sh"
grep -q 'SECURITYEDGE_CONTAINER_IPV4="$validation_ip"' "$script_dir/validate.sh"
grep -q 'select-validation-ip.py' "$script_dir/validate.sh"
validation_picker="$script_dir/select-validation-ip.py"
[[ "$(printf '%s\n' '[]' | python3 "$validation_picker" --subnet 172.31.250.0/24 --gateway 172.31.250.1 --reserved-ip 172.31.250.10)" == 172.31.250.254 ]]
occupied_network='[{"Containers":{"edge":{"IPv4Address":"172.31.250.2/24"},"live-security":{"IPv4Address":"172.31.250.10/24"},"other":{"IPv4Address":"172.31.250.254/24"}}}]'
[[ "$(printf '%s\n' "$occupied_network" | python3 "$validation_picker" --subnet 172.31.250.0/24 --gateway 172.31.250.1 --reserved-ip 172.31.250.10)" == 172.31.250.253 ]]
if printf '%s\n' '[]' | python3 "$validation_picker" --subnet 192.0.2.0/30 --gateway 192.0.2.1 --reserved-ip 192.0.2.2 >/dev/null 2>&1; then
  echo 'validation IP picker accepted a subnet with no spare address' >&2
  exit 1
fi

# The fixed full-platform address has an explicit gateway/network identity so
# upgrades can distinguish the deployment's own existing bridge from conflicts.
grep -q '^SECUREEDGE_PROD_NETWORK_NAME=' "$prod_dir/.env.example"
grep -q '^SECUREEDGE_PROD_GATEWAY=' "$prod_dir/.env.example"
grep -q 'name: "${SECUREEDGE_PROD_NETWORK_NAME' "$prod_dir/compose.platform.yml"
grep -q 'gateway: "${SECUREEDGE_PROD_GATEWAY' "$prod_dir/compose.platform.yml"

echo "production Docker standalone contract: PASS"
