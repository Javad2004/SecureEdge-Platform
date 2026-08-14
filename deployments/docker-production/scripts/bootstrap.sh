#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bootstrap.sh edgeproxy|securityedge|platform

Creates the production .env file when absent, imports existing systemd Admin
credentials when possible, generates missing secrets for fresh deployments, and
seeds missing mutable JSON state from the checked-in systemd production
profiles. Existing state, TLS material, and secrets are never overwritten.
USAGE
}

mode=${1:-}
case "$mode" in
  edgeproxy|securityedge|platform) ;;
  *) usage >&2; exit 64 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prod_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_root=$(CDPATH= cd -- "$prod_dir/../.." && pwd)
env_file="$prod_dir/.env"

if [[ ! -f "$env_file" ]]; then
  cp "$prod_dir/.env.example" "$env_file"
  chmod 0644 "$env_file"
  echo "created $env_file"
fi

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

read_env_value() {
  local key=$1
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$env_file"
}

if getent passwd edgeproxy >/dev/null 2>&1; then
  replace_env EDGEPROXY_UID "$(id -u edgeproxy)"
  replace_env EDGEPROXY_GID "$(id -g edgeproxy)"
fi
if getent passwd securityedge >/dev/null 2>&1; then
  replace_env SECURITYEDGE_UID "$(id -u securityedge)"
  replace_env SECURITYEDGE_GID "$(id -g securityedge)"
fi

if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  replace_env SECUREEDGE_COMMIT "$(git -C "$repo_root" rev-parse --short=12 HEAD)"
  version=$(git -C "$repo_root" describe --tags --always --dirty 2>/dev/null || true)
  [[ -n "$version" ]] && replace_env SECUREEDGE_VERSION "$version"
fi
replace_env SECUREEDGE_BUILD_TIME "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

edge_uid=$(read_env_value EDGEPROXY_UID)
edge_gid=$(read_env_value EDGEPROXY_GID)
security_uid=$(read_env_value SECURITYEDGE_UID)
security_gid=$(read_env_value SECURITYEDGE_GID)
edge_state=$(read_env_value EDGEPROXY_STATE_DIR)
security_state=$(read_env_value SECURITYEDGE_STATE_DIR)
security_logs=$(read_env_value SECURITYEDGE_LOG_DIR)
edge_tls=$(read_env_value EDGEPROXY_TLS_DIR)
security_tls=$(read_env_value SECURITYEDGE_TLS_DIR)
ca_dir=$(read_env_value SECUREEDGE_CA_DIR)

for n in "$edge_uid" "$edge_gid" "$security_uid" "$security_gid"; do
  [[ "$n" =~ ^[0-9]+$ ]] || { echo "numeric UID/GID required in $env_file" >&2; exit 78; }
done

sudo_cmd=()
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || {
    echo "bootstrap needs root privileges for production state directories; run as root or install sudo" >&2
    exit 77
  }
  sudo_cmd=(sudo)
fi

install_state() {
  local dir=$1 uid=$2 gid=$3 source=$4 target=$5
  if [[ ! -d "$dir" ]]; then
    "${sudo_cmd[@]}" install -d -o "$uid" -g "$gid" -m 0750 "$dir"
    echo "created $dir"
  fi
  if [[ ! -f "$target" ]]; then
    "${sudo_cmd[@]}" install -o "$uid" -g "$gid" -m 0640 "$source" "$target"
    echo "seeded $target"
  else
    echo "preserved existing $target"
  fi
}

if [[ ! -d "$ca_dir" ]]; then
  "${sudo_cmd[@]}" install -d -o 0 -g 0 -m 0755 "$ca_dir"
  echo "created $ca_dir"
fi

if [[ "$mode" == edgeproxy || "$mode" == platform ]]; then
  install_state \
    "$edge_state" "$edge_uid" "$edge_gid" \
    "$repo_root/apps/edgeproxy/deploy/systemd/edgeproxy.json" \
    "$edge_state/config.json"
  if [[ ! -d "$edge_tls" ]]; then
    "${sudo_cmd[@]}" install -d -o 0 -g "$edge_gid" -m 0750 "$edge_tls"
    echo "created $edge_tls"
  fi
fi

if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  install_state \
    "$security_state" "$security_uid" "$security_gid" \
    "$repo_root/apps/securityedge/deploy/systemd/securityedge.json" \
    "$security_state/securityedge.json"
  if [[ ! -d "$security_logs" ]]; then
    "${sudo_cmd[@]}" install -d -o "$security_uid" -g "$security_gid" -m 0750 "$security_logs"
    echo "created $security_logs"
  fi
  if [[ ! -d "$security_tls" ]]; then
    "${sudo_cmd[@]}" install -d -o 0 -g "$security_gid" -m 0750 "$security_tls"
    echo "created $security_tls"
  fi
fi

mkdir -p "$prod_dir/secrets"
chmod 0700 "$prod_dir/secrets"

extract_token() {
  local file=$1 key=$2 value=""
  if [[ -r "$file" ]]; then
    value=$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file")
  elif [[ ${#sudo_cmd[@]} -gt 0 ]] && "${sudo_cmd[@]}" test -r "$file" 2>/dev/null; then
    value=$("${sudo_cmd[@]}" awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file")
  else
    return 1
  fi
  [[ -n "$value" ]] || return 1
  case "$value" in
    \"*\") value=${value#\"}; value=${value%\"} ;;
    \'*\') value=${value#\'}; value=${value%\'} ;;
  esac
  [[ -n "$value" ]] || return 1
  printf '%s' "$value"
}

generate_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
  fi
}

write_secret_if_missing() {
  local path=$1 value=$2 label=$3 service_gid=$4
  if [[ -e "$path" ]]; then
    if ! [[ -s "$path" ]] && ! "${sudo_cmd[@]}" test -s "$path" 2>/dev/null; then
      echo "$label secret exists but is empty: $path" >&2
      exit 78
    fi
    "${sudo_cmd[@]}" chown 0:"$service_gid" "$path"
    "${sudo_cmd[@]}" chmod 0440 "$path"
    echo "preserved existing $label secret and normalized read-only service-group permissions"
    return
  fi
  local tmp
  tmp=$(mktemp "$prod_dir/secrets/.secret.XXXXXX")
  trap 'rm -f "$tmp"' RETURN
  umask 077
  printf '%s\n' "$value" > "$tmp"
  "${sudo_cmd[@]}" install -o 0 -g "$service_gid" -m 0440 "$tmp" "$path"
  rm -f "$tmp"
  trap - RETURN
  echo "created $label secret"
}

edge_secret="$prod_dir/secrets/edgeproxy_admin_token"
security_secret="$prod_dir/secrets/securityedge_admin_token"

need_edge=false
need_security=false
[[ "$mode" == edgeproxy || "$mode" == securityedge || "$mode" == platform ]] && need_edge=true
[[ "$mode" == securityedge || "$mode" == platform ]] && need_security=true

if [[ "$need_edge" == true && ! -e "$edge_secret" ]]; then
  edge_token=""
  edge_token=$(extract_token /etc/edgeproxy/edgeproxy.env EDGEPROXY_ADMIN_TOKEN || true)
  if [[ -z "$edge_token" ]]; then
    edge_token=$(extract_token /etc/securityedge/securityedge.env EDGEPROXY_ADMIN_TOKEN || true)
  fi
  if [[ -z "$edge_token" ]]; then
    if [[ "$mode" == securityedge ]]; then
      echo "cannot infer the EdgeProxy Admin token for SecurityEdge-only mode" >&2
      echo "create $edge_secret with the exact token used by the existing EdgeProxy, then rerun" >&2
      exit 78
    fi
    edge_token=$(generate_token)
  fi
  write_secret_if_missing "$edge_secret" "$edge_token" "EdgeProxy Admin" "$edge_gid"
fi

if [[ "$need_security" == true && ! -e "$security_secret" ]]; then
  security_token=""
  security_token=$(extract_token /etc/securityedge/securityedge.env SECURITYEDGE_ADMIN_TOKEN || true)
  [[ -n "$security_token" ]] || security_token=$(generate_token)
  write_secret_if_missing "$security_secret" "$security_token" "SecurityEdge Admin" "$security_gid"
fi

cat <<EOF2

Bootstrap complete for: $mode
Environment: $env_file

Next:
  bash $prod_dir/scripts/doctor.sh $mode
  bash $prod_dir/scripts/validate.sh $mode

Review the mutable JSON profile(s) before starting containers, especially real
Origin URLs, hostnames, TLS certificate paths, and route policies.
EOF2
