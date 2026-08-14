#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bootstrap.sh edgeproxy|securityedge|platform

Initializes the standalone production Docker runtime. No systemd unit, host
service account, or previous SecureEdge installation is required. The script:
  - creates .env from .env.example when absent;
  - creates the self-contained SECUREEDGE_DATA_ROOT tree;
  - seeds missing mutable JSON from production Docker templates;
  - generates mode-appropriate Admin secrets;
  - assigns numeric container UID/GID ownership without creating host users.

Existing configuration, state, TLS material, CA certificates and secrets are
never overwritten. For an existing systemd installation use import-systemd.sh
explicitly after this bootstrap; migration is optional, not a runtime dependency.
USAGE
}

mode=${1:-}
case "$mode" in edgeproxy|securityedge|platform) ;; *) usage >&2; exit 64;; esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prod_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_root=$(CDPATH= cd -- "$prod_dir/../.." && pwd)
env_file="$prod_dir/.env"

if [[ ! -f "$env_file" ]]; then
  cp "$prod_dir/.env.example" "$env_file"
  chmod 0644 "$env_file"
  echo "created $env_file"
fi

read_env_value() {
  local key=$1
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$env_file"
}

replace_env() {
  local key=$1 value=$2
  python3 - "$env_file" "$key" "$value" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
key, value = sys.argv[2], sys.argv[3]
lines = path.read_text().splitlines()
prefix = key + "="
for i, line in enumerate(lines):
    if line.startswith(prefix):
        lines[i] = prefix + value
        break
else:
    lines.append(prefix + value)
path.write_text("\n".join(lines) + "\n")
PY
}

if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  replace_env SECUREEDGE_COMMIT "$(git -C "$repo_root" rev-parse --short=12 HEAD)"
  version=$(git -C "$repo_root" describe --tags --always --dirty 2>/dev/null || true)
  [[ -n "$version" ]] && replace_env SECUREEDGE_VERSION "$version"
fi
replace_env SECUREEDGE_BUILD_TIME "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

root=$(read_env_value SECUREEDGE_DATA_ROOT)
edge_uid=$(read_env_value EDGEPROXY_UID)
edge_gid=$(read_env_value EDGEPROXY_GID)
security_uid=$(read_env_value SECURITYEDGE_UID)
security_gid=$(read_env_value SECURITYEDGE_GID)

[[ "$root" == /* ]] || { echo "SECUREEDGE_DATA_ROOT must be an absolute path: $root" >&2; exit 78; }
for n in "$edge_uid" "$edge_gid" "$security_uid" "$security_gid"; do
  [[ "$n" =~ ^[1-9][0-9]*$ ]] || { echo "non-zero numeric UID/GID required in $env_file" >&2; exit 78; }
done

sudo_cmd=()
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || {
    echo "bootstrap needs privileges to create $root; run as root or install sudo" >&2
    exit 77
  }
  sudo_cmd=(sudo)
fi

edge_state="$root/edgeproxy"
security_state="$root/securityedge"
security_logs="$root/logs/securityedge"
edge_tls="$root/tls/edgeproxy"
security_tls="$root/tls/securityedge"
ca_dir="$root/ca"
secret_dir="$root/secrets"

"${sudo_cmd[@]}" install -d -o 0 -g 0 -m 0755 "$root"
"${sudo_cmd[@]}" install -d -o "$edge_uid" -g "$edge_gid" -m 0750 "$edge_state"
"${sudo_cmd[@]}" install -d -o 0 -g "$edge_gid" -m 0750 "$edge_tls"
"${sudo_cmd[@]}" install -d -o 0 -g 0 -m 0755 "$ca_dir"
"${sudo_cmd[@]}" install -d -o 0 -g 0 -m 0700 "$secret_dir"

# SecurityEdge always needs a read-only local mirror of EdgeProxy routing state,
# even in SecurityEdge-only mode where the real EdgeProxy runs elsewhere.
if [[ ! -f "$edge_state/config.json" ]]; then
  "${sudo_cmd[@]}" install -o "$edge_uid" -g "$edge_gid" -m 0640 \
    "$prod_dir/templates/edgeproxy.json" "$edge_state/config.json"
  echo "seeded $edge_state/config.json"
else
  echo "preserved existing $edge_state/config.json"
fi

if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  "${sudo_cmd[@]}" install -d -o "$security_uid" -g "$security_gid" -m 0750 "$security_state"
  "${sudo_cmd[@]}" install -d -o "$security_uid" -g "$security_gid" -m 0750 "$security_logs"
  "${sudo_cmd[@]}" install -d -o 0 -g "$security_gid" -m 0750 "$security_tls"
  if [[ ! -f "$security_state/securityedge.json" ]]; then
    "${sudo_cmd[@]}" install -o "$security_uid" -g "$security_gid" -m 0640 \
      "$prod_dir/templates/securityedge.json" "$security_state/securityedge.json"
    echo "seeded $security_state/securityedge.json"
  else
    echo "preserved existing $security_state/securityedge.json"
  fi
fi

generate_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
  fi
}

write_secret_if_missing() {
  local path=$1 gid=$2 label=$3
  if "${sudo_cmd[@]}" test -e "$path"; then
    "${sudo_cmd[@]}" test -s "$path" || { echo "$label secret exists but is empty: $path" >&2; exit 78; }
    "${sudo_cmd[@]}" chown 0:"$gid" "$path"
    "${sudo_cmd[@]}" chmod 0440 "$path"
    echo "preserved existing $label secret"
    return
  fi
  local value tmp
  value=$(generate_token)
  tmp=$(mktemp)
  umask 077
  printf '%s\n' "$value" > "$tmp"
  "${sudo_cmd[@]}" install -o 0 -g "$gid" -m 0440 "$tmp" "$path"
  rm -f "$tmp"
  echo "created $label secret"
}

edge_secret="$secret_dir/edgeproxy_admin_token"
security_secret="$secret_dir/securityedge_admin_token"

case "$mode" in
  edgeproxy)
    write_secret_if_missing "$edge_secret" "$edge_gid" "EdgeProxy Admin"
    ;;
  platform)
    write_secret_if_missing "$edge_secret" "$edge_gid" "EdgeProxy Admin"
    write_secret_if_missing "$security_secret" "$security_gid" "SecurityEdge Admin"
    ;;
  securityedge)
    # SecurityEdge must authenticate to an independently operated EdgeProxy.
    # Its token cannot be generated locally because it must match that peer.
    if ! "${sudo_cmd[@]}" test -s "$edge_secret"; then
      cat >&2 <<EOF2
SecurityEdge-only mode requires the real external EdgeProxy Admin token.
Create this file with the exact remote token, then rerun bootstrap:
  $edge_secret
Recommended ownership/mode:
  root:${edge_gid} 0440
EOF2
      exit 78
    fi
    "${sudo_cmd[@]}" chown 0:"$edge_gid" "$edge_secret"
    "${sudo_cmd[@]}" chmod 0440 "$edge_secret"
    write_secret_if_missing "$security_secret" "$security_gid" "SecurityEdge Admin"
    ;;
esac

cat <<EOF2

Standalone Docker bootstrap complete for: $mode
Environment: $env_file
Data root:   $root

Before deployment:
  1. edit the seeded JSON profile(s) and replace *.example.invalid placeholders;
  2. install matching TLS certificate/key files under $root/tls/...;
  3. add private CA certificates to $root/ca only when required;
  4. run: bash $prod_dir/scripts/doctor.sh $mode
  5. run: bash $prod_dir/scripts/validate.sh $mode
EOF2
