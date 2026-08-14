#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: import-systemd.sh edgeproxy|securityedge|platform

OPTIONAL migration helper for hosts that already run SecureEdge through the
repository's systemd deployment. The standalone Docker deployment does not call
or require this script. Stop the relevant systemd service(s) first; this helper
refuses to copy mutable state from an active service.
USAGE
}
mode=${1:-}
case "$mode" in edgeproxy|securityedge|platform) ;; *) usage >&2; exit 64;; esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prod_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
env_file="$prod_dir/.env"
[[ -f "$env_file" ]] || { echo "missing $env_file; run bootstrap.sh first" >&2; exit 78; }

getv() { awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$env_file"; }
root=$(getv SECUREEDGE_DATA_ROOT)
edge_uid=$(getv EDGEPROXY_UID); edge_gid=$(getv EDGEPROXY_GID)
security_uid=$(getv SECURITYEDGE_UID); security_gid=$(getv SECURITYEDGE_GID)
[[ "$root" == /* ]] || { echo "SECUREEDGE_DATA_ROOT must be absolute" >&2; exit 78; }

# Defaults match the repository systemd deployment. Environment overrides make
# the importer testable and usable for an equivalent installation rooted at a
# different host path without changing standalone Docker defaults.
src_edge_state=${SYSTEMD_EDGEPROXY_STATE_DIR:-/var/lib/edgeproxy}
src_security_state=${SYSTEMD_SECURITYEDGE_STATE_DIR:-/var/lib/securityedge}
src_security_logs=${SYSTEMD_SECURITYEDGE_LOG_DIR:-/var/log/securityedge}
src_edge_tls=${SYSTEMD_EDGEPROXY_TLS_DIR:-/etc/edgeproxy/tls}
src_security_tls=${SYSTEMD_SECURITYEDGE_TLS_DIR:-/etc/securityedge/tls}
src_edge_env=${SYSTEMD_EDGEPROXY_ENV_FILE:-/etc/edgeproxy/edgeproxy.env}
src_security_env=${SYSTEMD_SECURITYEDGE_ENV_FILE:-/etc/securityedge/securityedge.env}

sudo_cmd=()
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || { echo "sudo/root required for migration" >&2; exit 77; }
  sudo_cmd=(sudo)
fi

require_inactive() {
  local unit=$1
  command -v systemctl >/dev/null 2>&1 || { echo "systemctl not found; this optional importer is only for systemd migrations" >&2; exit 69; }
  if systemctl is-active --quiet "$unit" 2>/dev/null; then
    echo "$unit is active; stop it before importing mutable state" >&2
    exit 75
  fi
}
require_inactive edgeproxy.service
if [[ "$mode" == securityedge || "$mode" == platform ]]; then require_inactive securityedge.service; fi

# Ensure the independent target tree exists without importing anything itself.
bash "$script_dir/bootstrap.sh" "$mode" >/dev/null || {
  if [[ "$mode" == securityedge ]]; then
    # bootstrap may intentionally wait for the real EdgeProxy token; migration
    # below supplies it, so create only the target directories here.
    "${sudo_cmd[@]}" install -d -o 0 -g 0 -m 0755 "$root"
    "${sudo_cmd[@]}" install -d -o "$edge_uid" -g "$edge_gid" -m 0750 "$root/edgeproxy"
    "${sudo_cmd[@]}" install -d -o "$security_uid" -g "$security_gid" -m 0750 "$root/securityedge" "$root/logs/securityedge"
    "${sudo_cmd[@]}" install -d -o 0 -g "$edge_gid" -m 0750 "$root/tls/edgeproxy"
    "${sudo_cmd[@]}" install -d -o 0 -g "$security_gid" -m 0750 "$root/tls/securityedge"
    "${sudo_cmd[@]}" install -d -o 0 -g 0 -m 0755 "$root/ca"
    "${sudo_cmd[@]}" install -d -o 0 -g 0 -m 0700 "$root/secrets"
  else
    exit 1
  fi
}

ts=$(date -u +%Y%m%dT%H%M%SZ)
backup="$root/migration-backups/$ts"
"${sudo_cmd[@]}" install -d -o 0 -g 0 -m 0700 "$backup"
for dir in edgeproxy securityedge logs tls; do
  if "${sudo_cmd[@]}" test -e "$root/$dir"; then
    "${sudo_cmd[@]}" cp -a "$root/$dir" "$backup/" 2>/dev/null || true
  fi
done

echo "pre-import Docker-state backup: $backup"

copy_tree_if_present() {
  local src=$1 dst=$2
  if "${sudo_cmd[@]}" test -d "$src"; then
    "${sudo_cmd[@]}" mkdir -p "$dst"
    "${sudo_cmd[@]}" cp -a "$src/." "$dst/"
    echo "imported $src -> $dst"
  fi
}

# SecurityEdge always needs the EdgeProxy route/config mirror.
copy_tree_if_present "$src_edge_state" "$root/edgeproxy"
copy_tree_if_present "$src_edge_tls" "$root/tls/edgeproxy"
if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  copy_tree_if_present "$src_security_state" "$root/securityedge"
  copy_tree_if_present "$src_security_logs" "$root/logs/securityedge"
  copy_tree_if_present "$src_security_tls" "$root/tls/securityedge"
fi

extract_env_token() {
  local path=$1 key=$2 value=""
  if [[ ${#sudo_cmd[@]} -gt 0 ]]; then
    value=$("${sudo_cmd[@]}" awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$path" 2>/dev/null || true)
  else
    value=$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$path" 2>/dev/null || true)
  fi
  value=${value%$'\r'}
  if (( ${#value} >= 2 )); then
    local first=${value:0:1} last=${value: -1}
    if [[ ( "$first" == '"' && "$last" == '"' ) || ( "$first" == "'" && "$last" == "'" ) ]]; then
      value=${value:1:${#value}-2}
    fi
  fi
  printf '%s' "$value"
}
write_token() {
  local value=$1 path=$2 gid=$3 label=$4
  [[ -n "$value" ]] || { echo "missing $label token in source systemd environment" >&2; exit 78; }
  local tmp
  tmp=$(mktemp); chmod 0600 "$tmp"; printf '%s\n' "$value" > "$tmp"
  "${sudo_cmd[@]}" install -o 0 -g "$gid" -m 0440 "$tmp" "$path"
  rm -f "$tmp"
}

edge_token=$(extract_env_token "$src_edge_env" EDGEPROXY_ADMIN_TOKEN)
[[ -n "$edge_token" ]] || edge_token=$(extract_env_token "$src_security_env" EDGEPROXY_ADMIN_TOKEN)
write_token "$edge_token" "$root/secrets/edgeproxy_admin_token" "$edge_gid" "EdgeProxy Admin"
if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  security_token=$(extract_env_token "$src_security_env" SECURITYEDGE_ADMIN_TOKEN)
  write_token "$security_token" "$root/secrets/securityedge_admin_token" "$security_gid" "SecurityEdge Admin"
fi

"${sudo_cmd[@]}" chown -R "$edge_uid:$edge_gid" "$root/edgeproxy"
"${sudo_cmd[@]}" chmod 0750 "$root/edgeproxy"
if [[ ${#sudo_cmd[@]} -gt 0 ]]; then
  "${sudo_cmd[@]}" find "$root/edgeproxy" -type f -exec chmod 0640 '{}' +
else
  find "$root/edgeproxy" -type f -exec chmod 0640 '{}' +
fi

if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  "${sudo_cmd[@]}" chown -R "$security_uid:$security_gid" "$root/securityedge" "$root/logs/securityedge"
  "${sudo_cmd[@]}" chmod 0750 "$root/securityedge" "$root/logs/securityedge"
  if [[ ${#sudo_cmd[@]} -gt 0 ]]; then
    "${sudo_cmd[@]}" find "$root/securityedge" "$root/logs/securityedge" -type f -exec chmod 0640 '{}' +
  else
    find "$root/securityedge" "$root/logs/securityedge" -type f -exec chmod 0640 '{}' +
  fi
fi

# TLS private material remains root-owned but readable by the matching
# container group. Do not weaken permissions if a stricter source is already
# valid; doctor.sh performs the final path/key validation.
"${sudo_cmd[@]}" chown -R 0:"$edge_gid" "$root/tls/edgeproxy" 2>/dev/null || true
"${sudo_cmd[@]}" chmod 0750 "$root/tls/edgeproxy" 2>/dev/null || true
if [[ ${#sudo_cmd[@]} -gt 0 ]]; then
  "${sudo_cmd[@]}" find "$root/tls/edgeproxy" -type f -exec chmod 0640 '{}' + 2>/dev/null || true
else
  find "$root/tls/edgeproxy" -type f -exec chmod 0640 '{}' + 2>/dev/null || true
fi
if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  "${sudo_cmd[@]}" chown -R 0:"$security_gid" "$root/tls/securityedge" 2>/dev/null || true
  "${sudo_cmd[@]}" chmod 0750 "$root/tls/securityedge" 2>/dev/null || true
  if [[ ${#sudo_cmd[@]} -gt 0 ]]; then
    "${sudo_cmd[@]}" find "$root/tls/securityedge" -type f -exec chmod 0640 '{}' + 2>/dev/null || true
  else
    find "$root/tls/securityedge" -type f -exec chmod 0640 '{}' + 2>/dev/null || true
  fi
fi

echo "systemd state import complete; systemd remains stopped and unchanged"
echo "next: review $prod_dir/.env, then run doctor.sh and validate.sh"
