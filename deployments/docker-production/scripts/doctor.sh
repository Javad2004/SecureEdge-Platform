#!/usr/bin/env bash
set -euo pipefail

usage() { echo "Usage: doctor.sh edgeproxy|securityedge|platform" >&2; }
mode=${1:-}
case "$mode" in edgeproxy|securityedge|platform) ;; *) usage; exit 64;; esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prod_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
env_file="$prod_dir/.env"
[[ -f "$env_file" ]] || { echo "missing $env_file; run scripts/bootstrap.sh $mode" >&2; exit 78; }

sudo_cmd=()
if [[ ${EUID:-$(id -u)} -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
  sudo_cmd=(sudo)
fi

getv() { awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$env_file"; }

require_file() {
  [[ -f "$1" ]] || { [[ ${#sudo_cmd[@]} -gt 0 ]] && "${sudo_cmd[@]}" test -f "$1" 2>/dev/null; } || {
    echo "missing or inaccessible required file: $1" >&2
    return 1
  }
}
require_dir() {
  [[ -d "$1" ]] || { [[ ${#sudo_cmd[@]} -gt 0 ]] && "${sudo_cmd[@]}" test -d "$1" 2>/dev/null; } || {
    echo "missing or inaccessible required directory: $1" >&2
    return 1
  }
}
protected_cat() {
  if [[ -r "$1" ]]; then
    cat "$1"
  elif [[ ${#sudo_cmd[@]} -gt 0 ]]; then
    "${sudo_cmd[@]}" cat "$1"
  else
    echo "cannot read protected file $1 and sudo is unavailable" >&2
    return 1
  fi
}
json_valid() {
  protected_cat "$1" | python3 -m json.tool >/dev/null
}
secret_ok() {
  local f=$1 expected_gid=$2 label=$3
  require_file "$f" || return 1
  if ! [[ -s "$f" ]] && ! { [[ ${#sudo_cmd[@]} -gt 0 ]] && "${sudo_cmd[@]}" test -s "$f" 2>/dev/null; }; then
    echo "$label secret is empty: $f" >&2
    return 1
  fi
  local metadata owner group mode_bits
  if metadata=$(stat -c '%u %g %a' "$f" 2>/dev/null); then
    :
  elif [[ ${#sudo_cmd[@]} -gt 0 ]]; then
    metadata=$("${sudo_cmd[@]}" stat -c '%u %g %a' "$f")
  else
    echo "cannot inspect secret ownership: $f" >&2
    return 1
  fi
  read -r owner group mode_bits <<<"$metadata"
  if [[ "$owner" != 0 || "$group" != "$expected_gid" || "$mode_bits" != 440 ]]; then
    echo "$label secret must be root:${expected_gid} mode 0440, got ${owner}:${group} mode ${mode_bits}: $f" >&2
    return 1
  fi
}

edge_state=$(getv EDGEPROXY_STATE_DIR)
security_state=$(getv SECURITYEDGE_STATE_DIR)
security_logs=$(getv SECURITYEDGE_LOG_DIR)
edge_tls=$(getv EDGEPROXY_TLS_DIR)
security_tls=$(getv SECURITYEDGE_TLS_DIR)
ca_dir=$(getv SECUREEDGE_CA_DIR)
edge_secret=$(getv EDGEPROXY_ADMIN_TOKEN_FILE)
security_secret=$(getv SECURITYEDGE_ADMIN_TOKEN_FILE)
edge_uid=$(getv EDGEPROXY_UID)
edge_gid=$(getv EDGEPROXY_GID)
security_uid=$(getv SECURITYEDGE_UID)
security_gid=$(getv SECURITYEDGE_GID)

# Resolve relative secret paths against the production directory.
[[ "$edge_secret" = /* ]] || edge_secret="$prod_dir/${edge_secret#./}"
[[ "$security_secret" = /* ]] || security_secret="$prod_dir/${security_secret#./}"

fail=0

validate_positive_integer() {
  local key=$1 value
  value=$(getv "$key")
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "$key must be a positive non-zero integer, got: ${value:-<empty>}" >&2
    fail=1
  fi
}
validate_port() {
  local key=$1 value
  value=$(getv "$key")
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < 1 || value > 65535 )); then
    echo "$key must be a TCP port in 1..65535, got: ${value:-<empty>}" >&2
    fail=1
  fi
}
validate_positive_decimal() {
  local key=$1 value
  value=$(getv "$key")
  if [[ ! "$value" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] || ! python3 - "$value" <<'PYCPU' >/dev/null 2>&1
import math, sys
value = float(sys.argv[1])
raise SystemExit(0 if math.isfinite(value) and value > 0 else 1)
PYCPU
  then
    echo "$key must be a finite positive number, got: ${value:-<empty>}" >&2
    fail=1
  fi
}
validate_memory_limit() {
  local key=$1 value
  value=$(getv "$key")
  if [[ ! "$value" =~ ^[1-9][0-9]*([bBkKmMgGtTpP][bB]?)?$ ]]; then
    echo "$key must be a positive Docker memory value such as 512m or 1g, got: ${value:-<empty>}" >&2
    fail=1
  fi
}

validate_bool() {
  local key=$1 value
  value=$(getv "$key")
  if [[ "$value" != true && "$value" != false ]]; then
    echo "$key must be exactly true or false, got: ${value:-<empty>}" >&2
    fail=1
  fi
}
validate_hostname_value() {
  local key=$1 value
  value=$(getv "$key")
  if [[ -z "$value" || "$value" == *://* || "$value" == */* || "$value" =~ [[:space:]] ]]; then
    echo "$key must be a hostname only (no scheme/path/whitespace), got: ${value:-<empty>}" >&2
    fail=1
  fi
}

for key in EDGEPROXY_UID EDGEPROXY_GID SECURITYEDGE_UID SECURITYEDGE_GID EDGEPROXY_PIDS_LIMIT SECURITYEDGE_PIDS_LIMIT; do
  validate_positive_integer "$key"
done
for key in SECURITYEDGE_HTTPS_PORT SECURITYEDGE_ADMIN_PORT EDGEPROXY_ADMIN_PORT SECURITYEDGE_CONTAINER_HTTPS_PORT EDGEPROXY_INTERNAL_PORT; do
  validate_port "$key"
done
for key in EDGEPROXY_INTERNAL_TLS_ENABLED EDGEPROXY_REQUIRE_HTTPS_ORIGINS EDGEPROXY_ALLOW_INSECURE_ORIGIN_TLS; do
  validate_bool "$key"
done
for key in EDGEPROXY_CPUS SECURITYEDGE_CPUS; do
  validate_positive_decimal "$key"
done
for key in EDGEPROXY_MEMORY_LIMIT SECURITYEDGE_MEMORY_LIMIT; do
  validate_memory_limit "$key"
done
validate_hostname_value SECURITYEDGE_PUBLIC_HOSTNAME
validate_hostname_value EDGEPROXY_INTERNAL_HOSTNAME

json_field() {
  local file=$1 path=$2
  protected_cat "$file" | python3 -c '''import json,sys
value=json.load(sys.stdin)
for part in sys.argv[1].split("."):
    value=value[part]
print("true" if value is True else "false" if value is False else value)''' "$path"
}

is_loopback_listener() {
  case "$1" in
    127.*:*|localhost:*|\[::1\]:*) return 0 ;;
    *) return 1 ;;
  esac
}

listener_port() {
  python3 - "$1" <<'PYPORT'
import sys
value = sys.argv[1].strip()
try:
    if value.startswith("["):
        port = value.rsplit("]:", 1)[1]
    else:
        port = value.rsplit(":", 1)[1]
    number = int(port)
    if not (1 <= number <= 65535):
        raise ValueError
except (IndexError, ValueError):
    raise SystemExit(1)
print(number)
PYPORT
}

protected_stat() {
  local format=$1 path=$2
  if stat -L -c "$format" "$path" >/dev/null 2>&1; then
    stat -L -c "$format" "$path"
  elif [[ ${#sudo_cmd[@]} -gt 0 ]]; then
    "${sudo_cmd[@]}" stat -L -c "$format" "$path"
  else
    return 1
  fi
}

protected_realpath() {
  if readlink -f -- "$1" >/dev/null 2>&1; then
    readlink -f -- "$1"
  elif [[ ${#sudo_cmd[@]} -gt 0 ]]; then
    "${sudo_cmd[@]}" readlink -f -- "$1"
  else
    return 1
  fi
}

runtime_mode_allows() {
  local path=$1 runtime_uid=$2 runtime_gid=$3 access=$4 label=$5 metadata owner group mode_bits perm mask
  metadata=$(protected_stat '%u %g %a' "$path") || { echo "cannot inspect $label permissions: $path" >&2; return 1; }
  read -r owner group mode_bits <<<"$metadata"
  perm=$((8#$mode_bits))
  case "$access" in
    read)
      if [[ "$owner" == "$runtime_uid" ]]; then mask=$((0400)); elif [[ "$group" == "$runtime_gid" ]]; then mask=$((0040)); else mask=$((0004)); fi
      ;;
    write)
      if [[ "$owner" == "$runtime_uid" ]]; then mask=$((0200)); elif [[ "$group" == "$runtime_gid" ]]; then mask=$((0020)); else mask=$((0002)); fi
      ;;
    execute)
      if [[ "$owner" == "$runtime_uid" ]]; then mask=$((0100)); elif [[ "$group" == "$runtime_gid" ]]; then mask=$((0010)); else mask=$((0001)); fi
      ;;
    *) return 2 ;;
  esac
  if (( (perm & mask) == 0 )); then
    echo "$label is not $access-accessible by container identity ${runtime_uid}:${runtime_gid}: $path (${owner}:${group} mode ${mode_bits})" >&2
    return 1
  fi
}

reject_world_writable() {
  local path=$1 label=$2 metadata mode_bits perm
  metadata=$(protected_stat '%a' "$path") || { echo "cannot inspect $label permissions: $path" >&2; return 1; }
  mode_bits=$metadata
  perm=$((8#$mode_bits))
  if (( (perm & 0002) != 0 )); then
    echo "$label must not be world-writable: $path (mode $mode_bits)" >&2
    return 1
  fi
}

validate_private_key_mode() {
  local path=$1 runtime_uid=$2 runtime_gid=$3 label=$4 metadata owner group mode_bits perm
  metadata=$(protected_stat '%u %g %a' "$path") || { echo "cannot inspect $label private-key permissions: $path" >&2; return 1; }
  read -r owner group mode_bits <<<"$metadata"
  perm=$((8#$mode_bits))
  if (( (perm & 0007) != 0 || (perm & 0030) != 0 )); then
    echo "$label private key permissions are too broad: $path (${owner}:${group} mode ${mode_bits}); use owner read/write and, when needed, service-group read only" >&2
    return 1
  fi
  if [[ "$owner" != 0 && "$owner" != "$runtime_uid" ]]; then
    echo "$label private key owner must be root or runtime UID $runtime_uid, got UID $owner: $path" >&2
    return 1
  fi
  if [[ "$owner" != "$runtime_uid" && "$group" != "$runtime_gid" ]]; then
    echo "$label private key must be group-readable by runtime GID $runtime_gid when not owned by runtime UID $runtime_uid: $path" >&2
    return 1
  fi
}

runtime_path_traversable() {
  local root=$1 target=$2 runtime_uid=$3 runtime_gid=$4 label=$5 current
  current=$(dirname -- "$target")
  while :; do
    runtime_mode_allows "$current" "$runtime_uid" "$runtime_gid" execute "$label directory" || return 1
    [[ "$current" == "$root" ]] && break
    [[ "$current" == "$root"/* ]] || {
      echo "$label path escaped its expected root while checking traversal: $current" >&2
      return 1
    }
    current=$(dirname -- "$current")
  done
}

verify_certificate_chain() {
  local cert_host=$1 label=$2 system_ca="" candidate tmp custom
  for candidate in \
    /etc/ssl/certs/ca-certificates.crt \
    /etc/pki/tls/certs/ca-bundle.crt \
    /etc/ssl/ca-bundle.pem \
    /etc/pki/tls/cacert.pem \
    /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem; do
    if [[ -r "$candidate" ]]; then system_ca=$candidate; break; fi
  done
  [[ -n "$system_ca" ]] || {
    echo "cannot locate a host system CA bundle for $label certificate-chain validation" >&2
    return 1
  }
  tmp=$(mktemp -d)
  protected_cat "$cert_host" > "$tmp/fullchain.pem" || { rm -rf "$tmp"; return 1; }
  python3 - "$tmp/fullchain.pem" "$tmp/leaf.pem" "$tmp/intermediates.pem" <<'PYSPLIT' || { rm -rf "$tmp"; return 1; }
from pathlib import Path
import re, sys
text = Path(sys.argv[1]).read_text()
blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, flags=re.S)
if not blocks:
    raise SystemExit("certificate file contains no PEM certificate")
Path(sys.argv[2]).write_text(blocks[0] + "\n")
Path(sys.argv[3]).write_text("\n".join(blocks[1:]) + ("\n" if len(blocks) > 1 else ""))
PYSPLIT
  cat "$system_ca" > "$tmp/roots.pem"
  while IFS= read -r -d '' custom; do
    protected_cat "$custom" >> "$tmp/roots.pem" || { rm -rf "$tmp"; return 1; }
    printf '\n' >> "$tmp/roots.pem"
  done < <(find "$ca_dir" -maxdepth 1 -type f \( -name '*.crt' -o -name '*.pem' \) -print0 2>/dev/null)
  local -a args=(verify -purpose sslserver -CAfile "$tmp/roots.pem")
  [[ -s "$tmp/intermediates.pem" ]] && args+=(-untrusted "$tmp/intermediates.pem")
  args+=("$tmp/leaf.pem")
  if ! openssl "${args[@]}" >/dev/null 2>&1; then
    echo "$label certificate chain is not trusted by the host system roots plus SECUREEDGE_CA_DIR; include the issuing private CA in $ca_dir or use a publicly trusted chain" >&2
    rm -rf "$tmp"
    return 1
  fi
  rm -rf "$tmp"
}

validate_tls_material() {
  local host_dir=$1 cert_container=$2 key_container=$3 mount_target=$4 label=$5 expected_host=${6:-} runtime_uid=${7:-} runtime_gid=${8:-}
  [[ -n "$cert_container" && -n "$key_container" ]] || {
    echo "$label TLS is enabled but certificate/key paths are empty" >&2
    return 1
  }
  case "$cert_container" in "$mount_target"/*) ;; *) echo "$label certificate path is outside mounted TLS directory $mount_target: $cert_container" >&2; return 1;; esac
  case "$key_container" in "$mount_target"/*) ;; *) echo "$label private-key path is outside mounted TLS directory $mount_target: $key_container" >&2; return 1;; esac
  local cert_rel=${cert_container#"$mount_target"/}
  local key_rel=${key_container#"$mount_target"/}
  local cert_host="$host_dir/$cert_rel"
  local key_host="$host_dir/$key_rel"
  require_file "$cert_host" || { echo "$label certificate expected from container path $cert_container" >&2; return 1; }
  require_file "$key_host" || { echo "$label private key expected from container path $key_container" >&2; return 1; }
  local host_real cert_real key_real
  host_real=$(protected_realpath "$host_dir") || { echo "cannot resolve $label TLS directory: $host_dir" >&2; return 1; }
  cert_real=$(protected_realpath "$cert_host") || { echo "cannot resolve $label certificate: $cert_host" >&2; return 1; }
  key_real=$(protected_realpath "$key_host") || { echo "cannot resolve $label private key: $key_host" >&2; return 1; }
  case "$cert_real" in "$host_real"/*) ;; *) echo "$label certificate resolves outside the mounted TLS directory: $cert_host -> $cert_real" >&2; return 1;; esac
  case "$key_real" in "$host_real"/*) ;; *) echo "$label private key resolves outside the mounted TLS directory: $key_host -> $key_real" >&2; return 1;; esac
  if [[ -n "$runtime_uid" && -n "$runtime_gid" ]]; then
    runtime_path_traversable "$host_real" "$cert_real" "$runtime_uid" "$runtime_gid" "$label certificate" || return 1
    runtime_path_traversable "$host_real" "$key_real" "$runtime_uid" "$runtime_gid" "$label private key" || return 1
    runtime_mode_allows "$cert_real" "$runtime_uid" "$runtime_gid" read "$label certificate" || return 1
    runtime_mode_allows "$key_real" "$runtime_uid" "$runtime_gid" read "$label private key" || return 1
    validate_private_key_mode "$key_real" "$runtime_uid" "$runtime_gid" "$label" || return 1
  fi
  command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required to validate production TLS material" >&2
    return 1
  }
  local -a tls_read_cmd=()
  if [[ ! -r "$cert_host" || ! -r "$key_host" ]]; then
    if [[ ${#sudo_cmd[@]} -gt 0 ]]; then
      tls_read_cmd=("${sudo_cmd[@]}")
    else
      echo "$label TLS material is not readable by the operator and sudo is unavailable" >&2
      return 1
    fi
  fi
  "${tls_read_cmd[@]}" openssl x509 -in "$cert_host" -noout >/dev/null 2>&1 || {
    echo "$label certificate is not valid PEM/X.509: $cert_host" >&2
    return 1
  }
  "${tls_read_cmd[@]}" openssl pkey -in "$key_host" -noout >/dev/null 2>&1 || {
    echo "$label private key is not readable/valid: $key_host" >&2
    return 1
  }
  verify_certificate_chain "$cert_host" "$label" || return 1
  local cert_pub key_pub
  cert_pub=$("${tls_read_cmd[@]}" openssl x509 -in "$cert_host" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  key_pub=$("${tls_read_cmd[@]}" openssl pkey -in "$key_host" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || {
    echo "$label certificate and private key do not match" >&2
    return 1
  }
  if [[ -n "$expected_host" ]]; then
    if python3 - "$expected_host" <<'PYIP' >/dev/null 2>&1
import ipaddress, sys
ipaddress.ip_address(sys.argv[1])
PYIP
    then
      "${tls_read_cmd[@]}" openssl x509 -in "$cert_host" -noout -checkip "$expected_host" >/dev/null 2>&1 || {
        echo "$label certificate does not cover IP address: $expected_host" >&2
        return 1
      }
    else
      "${tls_read_cmd[@]}" openssl x509 -in "$cert_host" -noout -checkhost "$expected_host" >/dev/null 2>&1 || {
        echo "$label certificate does not cover hostname: $expected_host" >&2
        return 1
      }
    fi
  fi
  "${tls_read_cmd[@]}" openssl x509 -in "$cert_host" -checkend 0 -noout >/dev/null 2>&1 || {
    echo "$label certificate is expired" >&2
    return 1
  }
  if ! "${tls_read_cmd[@]}" openssl x509 -in "$cert_host" -checkend 604800 -noout >/dev/null 2>&1; then
    echo "WARNING: $label certificate expires within 7 days" >&2
  fi
}


validate_custom_ca_dir() {
  local dir=$1 file real_dir real_file found=0
  require_dir "$dir" || return 1
  reject_world_writable "$dir" "custom CA directory" || return 1
  real_dir=$(protected_realpath "$dir") || { echo "cannot resolve custom CA directory: $dir" >&2; return 1; }
  while IFS= read -r -d '' file; do
    found=1
    real_file=$(protected_realpath "$file") || { echo "cannot resolve custom CA certificate: $file" >&2; return 1; }
    case "$real_file" in "$real_dir"/*) ;; *) echo "custom CA certificate resolves outside mounted CA directory: $file -> $real_file" >&2; return 1;; esac
    # CA certificates are public material; both non-root services must be able to
    # traverse the directory and read any configured custom CA file.
    runtime_path_traversable "$real_dir" "$real_file" "$edge_uid" "$edge_gid" "custom CA" || return 1
    runtime_path_traversable "$real_dir" "$real_file" "$security_uid" "$security_gid" "custom CA" || return 1
    runtime_mode_allows "$real_file" "$edge_uid" "$edge_gid" read "custom CA certificate" || return 1
    runtime_mode_allows "$real_file" "$security_uid" "$security_gid" read "custom CA certificate" || return 1
    protected_cat "$file" | openssl x509 -noout >/dev/null 2>&1 || {
      echo "invalid PEM/X.509 custom CA certificate: $file" >&2
      return 1
    }
  done < <(find "$dir" -maxdepth 1 -type f \( -name '*.crt' -o -name '*.pem' \) -print0 2>/dev/null)
  if [[ $found -eq 0 ]]; then
    echo "custom CA directory is empty; system CA roots only" >&2
  fi
}

validate_origin_policy() {
  local config_file=$1 require_https=$2 allow_insecure=$3 require_real_hosts=${4:-false} reject_loopback=${5:-false}
  protected_cat "$config_file" | python3 "$script_dir/check-edgeproxy-profile.py" \
    --require-https "$require_https" \
    --allow-insecure "$allow_insecure" \
    --require-real-hosts "$require_real_hosts" \
    --reject-loopback "$reject_loopback"
}
if [[ "$mode" == edgeproxy || "$mode" == platform ]]; then
  require_dir "$edge_state" || fail=1
  require_file "$edge_state/config.json" || fail=1
  require_dir "$edge_tls" || fail=1
  secret_ok "$edge_secret" "$edge_gid" "EdgeProxy Admin" || fail=1
  if [[ -f "$edge_state/config.json" ]]; then
    json_valid "$edge_state/config.json" || fail=1
  fi
fi
if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  require_dir "$security_state" || fail=1
  require_file "$security_state/securityedge.json" || fail=1
  require_dir "$security_logs" || fail=1
  require_dir "$security_tls" || fail=1
  secret_ok "$security_secret" "$security_gid" "SecurityEdge Admin" || fail=1
  secret_ok "$edge_secret" "$edge_gid" "EdgeProxy Admin" || fail=1
  require_dir "$edge_state" || fail=1
  require_file "$edge_state/config.json" || fail=1
  if [[ -f "$security_state/securityedge.json" ]]; then
    json_valid "$security_state/securityedge.json" || fail=1
  fi
fi

validate_custom_ca_dir "$ca_dir" || fail=1

# Validate host-side permissions required by the non-root container identities.
# Directory write permission is required because both applications use atomic
# file replacement rather than in-place mutation.
for guarded_dir in "$edge_state" "$security_state" "$security_logs" "$edge_tls" "$security_tls"; do
  if [[ -d "$guarded_dir" ]] || { [[ ${#sudo_cmd[@]} -gt 0 ]] && "${sudo_cmd[@]}" test -d "$guarded_dir" 2>/dev/null; }; then
    reject_world_writable "$guarded_dir" "production runtime directory" || fail=1
  fi
done
if [[ "$mode" == edgeproxy || "$mode" == platform ]]; then
  runtime_mode_allows "$edge_state" "$edge_uid" "$edge_gid" execute "EdgeProxy state directory" || fail=1
  runtime_mode_allows "$edge_state" "$edge_uid" "$edge_gid" write "EdgeProxy state directory" || fail=1
  if [[ -f "$edge_state/config.json" ]]; then
    runtime_mode_allows "$edge_state/config.json" "$edge_uid" "$edge_gid" read "EdgeProxy config" || fail=1
  fi
fi
if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  runtime_mode_allows "$security_state" "$security_uid" "$security_gid" execute "SecurityEdge state directory" || fail=1
  runtime_mode_allows "$security_state" "$security_uid" "$security_gid" write "SecurityEdge state directory" || fail=1
  runtime_mode_allows "$security_logs" "$security_uid" "$security_gid" execute "SecurityEdge log directory" || fail=1
  runtime_mode_allows "$security_logs" "$security_uid" "$security_gid" write "SecurityEdge log directory" || fail=1
  if [[ -f "$security_state/securityedge.json" ]]; then
    runtime_mode_allows "$security_state/securityedge.json" "$security_uid" "$security_gid" read "SecurityEdge config" || fail=1
  fi
  # SecurityEdge reads EdgeProxy state through a read-only bind and the
  # supplementary EdgeProxy group.
  runtime_mode_allows "$edge_state" "$security_uid" "$edge_gid" execute "SecurityEdge EdgeProxy-state view" || fail=1
  if [[ -f "$edge_state/config.json" ]]; then
    runtime_mode_allows "$edge_state/config.json" "$security_uid" "$edge_gid" read "SecurityEdge EdgeProxy config view" || fail=1
  fi
fi

if [[ "$mode" == edgeproxy || "$mode" == securityedge ]]; then
  [[ "$(uname -s)" == Linux ]] || {
    echo "$mode mode uses Docker host networking and requires a Linux Docker Engine host" >&2
    fail=1
  }
fi

if [[ "$mode" == edgeproxy && -f "$edge_state/config.json" ]]; then
  edge_admin_listen=$(json_field "$edge_state/config.json" admin.listen_addr)
  edge_server_listen=$(json_field "$edge_state/config.json" server.listen_addr)
  if ! is_loopback_listener "$edge_admin_listen"; then
    echo "EdgeProxy-only Admin listener must remain loopback-only, got: $edge_admin_listen" >&2
    fail=1
  elif edge_admin_config_port=$(listener_port "$edge_admin_listen" 2>/dev/null); then
    if [[ "$edge_admin_config_port" != "$(getv EDGEPROXY_ADMIN_PORT)" ]]; then
      echo "EDGEPROXY_ADMIN_PORT must match the EdgeProxy-only config Admin port ($edge_admin_config_port) so the Docker health check targets the real listener" >&2
      fail=1
    fi
  else
    echo "cannot parse EdgeProxy-only Admin listener port: $edge_admin_listen" >&2
    fail=1
  fi
  if ! is_loopback_listener "$edge_server_listen"; then
    echo "WARNING: EdgeProxy-only data listener is not loopback-only ($edge_server_listen); this can bypass SecurityEdge in a hybrid deployment" >&2
  fi
  if [[ "$(json_field "$edge_state/config.json" server.tls.enabled)" == true ]]; then
    validate_tls_material "$edge_tls" \
      "$(json_field "$edge_state/config.json" server.tls.cert_file)" \
      "$(json_field "$edge_state/config.json" server.tls.key_file)" \
      /etc/edgeproxy/tls EdgeProxy "$(getv EDGEPROXY_INTERNAL_HOSTNAME)" "$edge_uid" "$edge_gid" || fail=1
  fi
fi

if [[ ( "$mode" == edgeproxy || "$mode" == platform ) && -f "$edge_state/config.json" ]]; then
  require_real_hosts=false
  reject_loopback=false
  if [[ "$mode" == platform ]]; then
    require_real_hosts=true
    reject_loopback=true
  fi
  validate_origin_policy "$edge_state/config.json" \
    "$(getv EDGEPROXY_REQUIRE_HTTPS_ORIGINS)" \
    "$(getv EDGEPROXY_ALLOW_INSECURE_ORIGIN_TLS)" \
    "$require_real_hosts" "$reject_loopback" || fail=1
fi

if [[ "$mode" == securityedge && -f "$security_state/securityedge.json" ]]; then
  security_admin_listen=$(json_field "$security_state/securityedge.json" admin.listen_addr)
  if ! is_loopback_listener "$security_admin_listen"; then
    echo "SecurityEdge-only Admin listener must remain loopback-only, got: $security_admin_listen" >&2
    fail=1
  elif security_admin_config_port=$(listener_port "$security_admin_listen" 2>/dev/null); then
    if [[ "$security_admin_config_port" != "$(getv SECURITYEDGE_ADMIN_PORT)" ]]; then
      echo "SECURITYEDGE_ADMIN_PORT must match the SecurityEdge-only config Admin port ($security_admin_config_port) so the Docker health check targets the real listener" >&2
      fail=1
    fi
  else
    echo "cannot parse SecurityEdge-only Admin listener port: $security_admin_listen" >&2
    fail=1
  fi
  if [[ "$(json_field "$security_state/securityedge.json" server.tls.enabled)" == true ]]; then
    validate_tls_material "$security_tls" \
      "$(json_field "$security_state/securityedge.json" server.tls.cert_file)" \
      "$(json_field "$security_state/securityedge.json" server.tls.key_file)" \
      /etc/securityedge/tls SecurityEdge "$(getv SECURITYEDGE_PUBLIC_HOSTNAME)" "$security_uid" "$security_gid" || fail=1
  else
    echo "WARNING: SecurityEdge-only profile has native TLS disabled; ensure a trusted external TLS terminator is intentionally in front of it" >&2
  fi
fi

if [[ "$mode" == platform ]]; then
  validate_tls_material "$security_tls" \
    "$(getv SECURITYEDGE_TLS_CERT_FILE_CONTAINER)" \
    "$(getv SECURITYEDGE_TLS_KEY_FILE_CONTAINER)" \
    /etc/securityedge/tls SecurityEdge "$(getv SECURITYEDGE_PUBLIC_HOSTNAME)" "$security_uid" "$security_gid" || fail=1
  if [[ "$(getv EDGEPROXY_INTERNAL_TLS_ENABLED)" == true ]]; then
    validate_tls_material "$edge_tls" \
      "$(getv EDGEPROXY_TLS_CERT_FILE_CONTAINER)" \
      "$(getv EDGEPROXY_TLS_KEY_FILE_CONTAINER)" \
      /etc/edgeproxy/tls EdgeProxy "$(getv EDGEPROXY_INTERNAL_HOSTNAME)" "$edge_uid" "$edge_gid" || fail=1
    [[ "$(getv EDGEPROXY_INTERNAL_SCHEME)" == https ]] || {
      echo "EDGEPROXY_INTERNAL_TLS_ENABLED=true requires EDGEPROXY_INTERNAL_SCHEME=https" >&2
      fail=1
    }
  else
    [[ "$(getv EDGEPROXY_INTERNAL_SCHEME)" == http ]] || {
      echo "EDGEPROXY_INTERNAL_TLS_ENABLED=false requires EDGEPROXY_INTERNAL_SCHEME=http" >&2
      fail=1
    }
  fi
fi


if [[ "$mode" == platform ]]; then
  subnet=$(getv SECUREEDGE_PROD_SUBNET)
  ip=$(getv SECURITYEDGE_CONTAINER_IPV4)
  cidr=$(getv SECURITYEDGE_TRUSTED_PROXY_CIDR)
  python3 - "$subnet" "$ip" "$cidr" <<'PY' || fail=1
import ipaddress, sys
subnet = ipaddress.ip_network(sys.argv[1], strict=True)
ip = ipaddress.ip_address(sys.argv[2])
trusted = ipaddress.ip_network(sys.argv[3], strict=False)
if ip not in subnet:
    raise SystemExit(f"SecurityEdge IP {ip} is outside production subnet {subnet}")
if trusted.prefixlen != trusted.max_prefixlen or trusted.network_address != ip:
    raise SystemExit(f"trusted CIDR {trusted} must be exactly {ip}/{ip.max_prefixlen}")
print(f"network contract: {ip} in {subnet}, trusted peer {trusted}")
PY

  if command -v ip >/dev/null 2>&1; then
    python3 - "$subnet" <<'PY'
import ipaddress, subprocess, sys
candidate = ipaddress.ip_network(sys.argv[1])
text = subprocess.run(["ip", "-o", "route", "show"], text=True, capture_output=True).stdout
for line in text.splitlines():
    first = line.split()[0] if line.split() else ""
    try:
        route = ipaddress.ip_network(first, strict=False)
    except ValueError:
        continue
    if candidate.overlaps(route):
        print(f"WARNING: production Docker subnet {candidate} overlaps host route {route}: {line}", file=sys.stderr)
PY
  fi
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  if ! docker info >/dev/null 2>&1; then
    echo "Docker CLI is installed but the Docker daemon is unavailable or inaccessible" >&2
    fail=1
  else
    docker_security=$(docker info --format '{{json .SecurityOptions}}' 2>/dev/null || true)
    if [[ "$docker_security" == *rootless* ]]; then
      echo "rootless Docker is not supported by these production manifests; protected systemd-compatible bind mounts and host-network migration modes require a standard rootful Docker Engine" >&2
      fail=1
    fi
    if [[ "$mode" == platform ]]; then
      existing_subnets=$(docker network ls -q 2>/dev/null | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' 2>/dev/null || true)
      if [[ -n "$existing_subnets" ]]; then
        python3 - "$subnet" "$existing_subnets" <<'PYNET' || fail=1
import ipaddress, sys
candidate = ipaddress.ip_network(sys.argv[1], strict=True)
overlaps = []
for raw in sys.argv[2].splitlines():
    raw = raw.strip()
    if not raw:
        continue
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        continue
    if candidate.overlaps(network):
        overlaps.append(str(network))
if overlaps:
    print(f"production Docker subnet {candidate} overlaps existing Docker network(s): {', '.join(overlaps)}", file=sys.stderr)
    raise SystemExit(1)
PYNET
      fi
    fi
  fi
  case "$mode" in
    edgeproxy) compose=compose.edgeproxy.yml ;;
    securityedge) compose=compose.securityedge.yml ;;
    platform) compose=compose.platform.yml ;;
  esac
  (cd "$prod_dir" && docker compose --env-file .env -f "$compose" config -q) || fail=1
  echo "Docker Compose render: OK ($compose)"
else
  echo "WARNING: Docker Compose is not installed; skipped compose render check" >&2
fi

if [[ $fail -ne 0 ]]; then
  echo "production Docker preflight failed" >&2
  exit 1
fi

echo "production Docker preflight passed for: $mode"
