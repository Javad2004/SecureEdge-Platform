#!/usr/bin/env bash
set -euo pipefail

usage() { echo "Usage: doctor.sh edgeproxy|securityedge|platform" >&2; }
mode=${1:-}
case "$mode" in edgeproxy|securityedge|platform) ;; *) usage; exit 64;; esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prod_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
env_file="$prod_dir/.env"
[[ -f "$env_file" ]] || { echo "missing $env_file; run scripts/bootstrap.sh $mode" >&2; exit 78; }

validate_env_file() {
  python3 - "$env_file" <<'PYENV'
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
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        raise SystemExit(f"{path}:{lineno}: invalid environment key {key!r}")
    if key in seen:
        raise SystemExit(f"{path}:{lineno}: duplicate environment key {key}")
    seen.add(key)
    if value != value.strip():
        raise SystemExit(f"{path}:{lineno}: surrounding whitespace in {key} is not allowed")
    if value.startswith(("'", '"')) or value.endswith(("'", '"')):
        raise SystemExit(f"{path}:{lineno}: use unquoted KEY=value syntax for {key}")
    if " #" in value or "\t#" in value:
        raise SystemExit(f"{path}:{lineno}: inline comments are not allowed after {key}")
    if "$" in value:
        raise SystemExit(f"{path}:{lineno}: variable interpolation is not allowed in {key}; write the resolved value")
PYENV
}
validate_env_file

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
secret_value_ok() {
  local f=$1 label=$2
  protected_cat "$f" | python3 -c '
import sys, unicodedata
label = sys.argv[1]
raw = sys.stdin.buffer.read()
try:
    value = raw.decode("utf-8")
except UnicodeDecodeError:
    raise SystemExit(f"{label} secret must be valid UTF-8")
token = value.strip()
if not token:
    raise SystemExit(f"{label} secret is empty after whitespace normalization")
if token == "[REDACTED]":
    raise SystemExit(f"{label} secret cannot use the reserved [REDACTED] secret marker")
if len(token.encode("utf-8")) > 8192:
    raise SystemExit(f"{label} secret cannot exceed 8192 UTF-8 bytes")
if any(ch.isspace() or unicodedata.category(ch) == "Cc" for ch in token):
    raise SystemExit(f"{label} secret cannot contain embedded whitespace or control characters")
' "$label"
}

secret_ok() {
  local f=$1 expected_gid=$2 label=$3
  require_file "$f" || return 1
  if ! [[ -s "$f" ]] && ! { [[ ${#sudo_cmd[@]} -gt 0 ]] && "${sudo_cmd[@]}" test -s "$f" 2>/dev/null; }; then
    echo "$label secret is empty: $f" >&2
    return 1
  fi
  secret_value_ok "$f" "$label" || return 1
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

data_root=$(getv SECUREEDGE_DATA_ROOT)
edge_uid=$(getv EDGEPROXY_UID)
edge_gid=$(getv EDGEPROXY_GID)
security_uid=$(getv SECURITYEDGE_UID)
security_gid=$(getv SECURITYEDGE_GID)

[[ "$data_root" == /* ]] || {
  echo "SECUREEDGE_DATA_ROOT must be an absolute path, got: ${data_root:-<empty>}" >&2
  exit 78
}
[[ "$data_root" != / ]] || {
  echo "SECUREEDGE_DATA_ROOT must not be the filesystem root" >&2
  exit 78
}

edge_state="$data_root/edgeproxy"
security_state="$data_root/securityedge"
security_logs="$data_root/logs/securityedge"
edge_tls="$data_root/tls/edgeproxy"
security_tls="$data_root/tls/securityedge"
ca_dir="$data_root/ca"
secret_dir="$data_root/secrets"
edge_secret="$secret_dir/edgeproxy_admin_token"
security_secret="$data_root/secrets/securityedge_admin_token"

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
  python3 - "$key" "$value" <<'PYHOST' || fail=1
import ipaddress, re, sys
key, raw = sys.argv[1:]
host = raw.strip().rstrip(".").lower()
if not host or "://" in raw or "/" in raw or any(ch.isspace() for ch in raw):
    raise SystemExit(f"{key} must be a hostname/IP only (no scheme/path/whitespace), got: {raw or '<empty>'}")
if host in {"localhost", "localhost.localdomain", "example.com", "example.net", "example.org", "example.invalid"} or host.endswith((".localhost", ".local", ".test", ".invalid", ".example.com", ".example.net", ".example.org")):
    raise SystemExit(f"{key} still contains a non-production placeholder/local hostname: {raw}")
try:
    ip = ipaddress.ip_address(host)
except ValueError:
    if len(host) > 253:
        raise SystemExit(f"{key} hostname is too long: {raw}")
    labels = host.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        raise SystemExit(f"{key} is not a valid DNS hostname: {raw}")
else:
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise SystemExit(f"{key} must not use loopback/unspecified/multicast address: {ip}")
PYHOST
}


case "$mode" in
  edgeproxy)
    for key in EDGEPROXY_UID EDGEPROXY_GID EDGEPROXY_PIDS_LIMIT; do validate_positive_integer "$key"; done
    for key in EDGEPROXY_HTTPS_PORT EDGEPROXY_CONTAINER_HTTPS_PORT EDGEPROXY_ADMIN_PORT; do validate_port "$key"; done
    validate_positive_decimal EDGEPROXY_CPUS
    validate_memory_limit EDGEPROXY_MEMORY_LIMIT
    ;;
  securityedge)
    for key in EDGEPROXY_GID SECURITYEDGE_UID SECURITYEDGE_GID SECURITYEDGE_PIDS_LIMIT; do validate_positive_integer "$key"; done
    for key in SECURITYEDGE_HTTPS_PORT SECURITYEDGE_CONTAINER_HTTPS_PORT SECURITYEDGE_ADMIN_PORT; do validate_port "$key"; done
    validate_positive_decimal SECURITYEDGE_CPUS
    validate_memory_limit SECURITYEDGE_MEMORY_LIMIT
    validate_bool SECURITYEDGE_REQUIRE_HTTPS_EDGEPROXY
    validate_bool SECURITYEDGE_DNS_ENABLED
    validate_bool SECURITYEDGE_DNS_CRITICAL
    ;;
  platform)
    for key in EDGEPROXY_UID EDGEPROXY_GID SECURITYEDGE_UID SECURITYEDGE_GID EDGEPROXY_PIDS_LIMIT SECURITYEDGE_PIDS_LIMIT; do validate_positive_integer "$key"; done
    for key in EDGEPROXY_INTERNAL_PORT EDGEPROXY_ADMIN_PORT SECURITYEDGE_HTTPS_PORT SECURITYEDGE_CONTAINER_HTTPS_PORT SECURITYEDGE_ADMIN_PORT; do validate_port "$key"; done
    validate_positive_decimal EDGEPROXY_CPUS
    validate_positive_decimal SECURITYEDGE_CPUS
    validate_memory_limit EDGEPROXY_MEMORY_LIMIT
    validate_memory_limit SECURITYEDGE_MEMORY_LIMIT
    validate_bool EDGEPROXY_INTERNAL_TLS_ENABLED
    validate_bool SECURITYEDGE_DNS_ENABLED
    validate_bool SECURITYEDGE_DNS_CRITICAL
    ;;
esac
validate_bool EDGEPROXY_REQUIRE_HTTPS_ORIGINS
validate_bool EDGEPROXY_ALLOW_INSECURE_ORIGIN_TLS

# Numeric container identities map directly onto bind-mounted host ownership.
# Keep the two services isolated from each other and reject host account/group
# collisions that would silently grant a local principal access to production
# state or group-readable Docker secrets.
identity_collision=0
if [[ "$mode" == platform ]]; then
  if [[ "$edge_uid" == "$security_uid" ]]; then
    echo "EDGEPROXY_UID and SECURITYEDGE_UID must be different" >&2
    identity_collision=1
  fi
  if [[ "$edge_gid" == "$security_gid" ]]; then
    echo "EDGEPROXY_GID and SECURITYEDGE_GID must be different so Admin secrets remain service-isolated" >&2
    identity_collision=1
  fi
elif [[ "$mode" == securityedge && "$edge_gid" == "$security_gid" ]]; then
  echo "EDGEPROXY_GID and SECURITYEDGE_GID must be different so the external EdgeProxy token is not shared with SecurityEdge's primary group" >&2
  identity_collision=1
fi
(( identity_collision == 0 )) || fail=1

check_host_uid_free() {
  local uid=$1 label=$2
  if command -v getent >/dev/null 2>&1 && entry=$(getent passwd "$uid" 2>/dev/null) && [[ -n "$entry" ]]; then
    echo "$label UID $uid is already assigned to a host account (${entry%%:*}); choose an unused numeric UID in .env" >&2
    fail=1
  fi
}
check_host_gid_free() {
  local gid=$1 label=$2
  if command -v getent >/dev/null 2>&1 && entry=$(getent group "$gid" 2>/dev/null) && [[ -n "$entry" ]]; then
    echo "$label GID $gid is already assigned to a host group (${entry%%:*}); choose an unused numeric GID in .env" >&2
    fail=1
  fi
}
case "$mode" in
  edgeproxy)
    check_host_uid_free "$edge_uid" EdgeProxy
    check_host_gid_free "$edge_gid" EdgeProxy
    ;;
  securityedge)
    check_host_uid_free "$security_uid" SecurityEdge
    check_host_gid_free "$security_gid" SecurityEdge
    check_host_gid_free "$edge_gid" "external EdgeProxy supplementary"
    ;;
  platform)
    check_host_uid_free "$edge_uid" EdgeProxy
    check_host_gid_free "$edge_gid" EdgeProxy
    check_host_uid_free "$security_uid" SecurityEdge
    check_host_gid_free "$security_gid" SecurityEdge
    ;;
esac

case "$mode" in
  edgeproxy) validate_hostname_value EDGEPROXY_PUBLIC_HOSTNAME ;;
  securityedge) validate_hostname_value SECURITYEDGE_PUBLIC_HOSTNAME ;;
  platform)
    validate_hostname_value SECURITYEDGE_PUBLIC_HOSTNAME
    validate_hostname_value EDGEPROXY_INTERNAL_HOSTNAME
    internal_host=$(getv EDGEPROXY_INTERNAL_HOSTNAME)
    if python3 - "$internal_host" <<'PYINTERNAL' >/dev/null 2>&1
import ipaddress, sys
ipaddress.ip_address(sys.argv[1].strip().rstrip('.'))
PYINTERNAL
    then
      echo "EDGEPROXY_INTERNAL_HOSTNAME must be a DNS hostname, not an IP literal, because Full Platform uses it as a Docker network alias and TLS server name" >&2
      fail=1
    fi
    ;;
esac

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

reject_group_world_writable() {
  local path=$1 label=$2 metadata mode_bits perm
  metadata=$(protected_stat '%a' "$path") || { echo "cannot inspect $label permissions: $path" >&2; return 1; }
  mode_bits=$metadata
  perm=$((8#$mode_bits))
  if (( (perm & 0022) != 0 )); then
    echo "$label must not be group/world-writable: $path (mode $mode_bits)" >&2
    return 1
  fi
}

require_owner_group() {
  local path=$1 expected_uid=$2 expected_gid=$3 label=$4 metadata owner group
  metadata=$(protected_stat '%u %g' "$path") || { echo "cannot inspect $label ownership: $path" >&2; return 1; }
  read -r owner group <<<"$metadata"
  if [[ "$owner" != "$expected_uid" || "$group" != "$expected_gid" ]]; then
    echo "$label must be owned by ${expected_uid}:${expected_gid}, got ${owner}:${group}: $path" >&2
    return 1
  fi
}

require_root_owner() {
  local path=$1 label=$2 metadata owner
  metadata=$(protected_stat '%u' "$path") || { echo "cannot inspect $label ownership: $path" >&2; return 1; }
  owner=$metadata
  if [[ "$owner" != 0 ]]; then
    echo "$label must be root-owned, got UID $owner: $path" >&2
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
    # CA material only needs to be readable by identities that actually run in
    # the selected deployment mode. This keeps EdgeProxy-only and
    # SecurityEdge-only genuinely independent while Full Platform checks both.
    if [[ "$mode" == edgeproxy || "$mode" == platform ]]; then
      runtime_path_traversable "$real_dir" "$real_file" "$edge_uid" "$edge_gid" "custom CA" || return 1
      runtime_mode_allows "$real_file" "$edge_uid" "$edge_gid" read "custom CA certificate" || return 1
    fi
    if [[ "$mode" == securityedge || "$mode" == platform ]]; then
      runtime_path_traversable "$real_dir" "$real_file" "$security_uid" "$security_gid" "custom CA" || return 1
      runtime_mode_allows "$real_file" "$security_uid" "$security_gid" read "custom CA certificate" || return 1
    fi
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

validate_bind_ip() {
  local key=$1 scope=${2:-public} value
  value=$(getv "$key")
  python3 - "$key" "$value" "$scope" <<'PY' || fail=1
import ipaddress, sys
key, raw, scope = sys.argv[1:]
try:
    ip = ipaddress.ip_address(raw)
except ValueError:
    raise SystemExit(f"{key} must be an IP literal, got: {raw or '<empty>'}")
if ip.is_multicast:
    raise SystemExit(f"{key} must not be multicast: {ip}")
if scope == "admin":
    if ip.is_unspecified:
        raise SystemExit(f"{key} must not expose an Admin API on an unspecified address: {ip}")
    # Global Admin exposure is never accepted by the production baseline. A
    # loopback, RFC1918/ULA, link-local, or CGNAT/Tailscale-style address is OK.
    if ip.is_global:
        raise SystemExit(f"{key} must be loopback/private/VPN scoped, not globally routable: {ip}")
PY
}

validate_external_url() {
  local key=$1 required_scheme=${2:-} network_scope=${3:-any} value
  value=$(getv "$key")
  local -a args=(--key "$key" --value "$value" --scope "$network_scope")
  if [[ -n "$required_scheme" ]]; then
    args+=(--required-scheme "$required_scheme")
  fi
  python3 "$script_dir/check-production-endpoint.py" "${args[@]}" || fail=1
}



# Production Docker is intentionally Linux-first. No host service users or
# systemd state are required, but fixed numeric bind-mount ownership and the
# documented rootful Docker baseline are Linux host contracts.
[[ "$(uname -s)" == Linux ]] || {
  echo "production Docker deployment currently requires a Linux host" >&2
  fail=1
}

case "$mode" in
  edgeproxy)
    validate_bind_ip EDGEPROXY_ADMIN_BIND_IP admin
    validate_bind_ip EDGEPROXY_HTTPS_BIND_IP public
    ;;
  securityedge)
    validate_bind_ip SECURITYEDGE_ADMIN_BIND_IP admin
    validate_bind_ip SECURITYEDGE_HTTPS_BIND_IP public
    ;;
  platform)
    validate_bind_ip EDGEPROXY_ADMIN_BIND_IP admin
    validate_bind_ip SECURITYEDGE_ADMIN_BIND_IP admin
    validate_bind_ip SECURITYEDGE_HTTPS_BIND_IP public
    ;;
esac

# Common EdgeProxy config mirror/state is required in every mode. In
# SecurityEdge-only mode it is a read-only local mirror of the independently
# operated EdgeProxy route table.
require_dir "$edge_state" || fail=1
require_dir "$secret_dir" || fail=1
require_file "$edge_state/config.json" || fail=1
if [[ -f "$edge_state/config.json" ]]; then json_valid "$edge_state/config.json" || fail=1; fi
secret_ok "$edge_secret" "$edge_gid" "EdgeProxy Admin" || fail=1

if [[ "$mode" == edgeproxy || "$mode" == platform ]]; then
  require_dir "$edge_tls" || fail=1
fi
if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  require_dir "$security_state" || fail=1
  require_file "$security_state/securityedge.json" || fail=1
  require_dir "$security_logs" || fail=1
  require_dir "$security_tls" || fail=1
  secret_ok "$security_secret" "$security_gid" "SecurityEdge Admin" || fail=1
  if [[ -f "$security_state/securityedge.json" ]]; then json_valid "$security_state/securityedge.json" || fail=1; fi
fi

validate_custom_ca_dir "$ca_dir" || fail=1
require_owner_group "$data_root" 0 0 "production data root" || fail=1
reject_group_world_writable "$data_root" "production data root" || fail=1
require_owner_group "$secret_dir" 0 0 "production secret directory" || fail=1
reject_group_world_writable "$secret_dir" "production secret directory" || fail=1
require_owner_group "$ca_dir" 0 0 "custom CA directory" || fail=1
reject_group_world_writable "$ca_dir" "custom CA directory" || fail=1

# Mutable state ownership is part of the isolation contract. EdgeProxy state is
# shared read-only with SecurityEdge in full-platform mode, so group write must
# never be enabled on the directory/config mirror.
require_owner_group "$edge_state" "$edge_uid" "$edge_gid" "EdgeProxy state directory" || fail=1
reject_group_world_writable "$edge_state" "EdgeProxy state directory" || fail=1
require_owner_group "$edge_state/config.json" "$edge_uid" "$edge_gid" "EdgeProxy config" || fail=1
reject_group_world_writable "$edge_state/config.json" "EdgeProxy config" || fail=1
if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  require_owner_group "$security_state" "$security_uid" "$security_gid" "SecurityEdge state directory" || fail=1
  reject_group_world_writable "$security_state" "SecurityEdge state directory" || fail=1
  require_owner_group "$security_state/securityedge.json" "$security_uid" "$security_gid" "SecurityEdge config" || fail=1
  reject_group_world_writable "$security_state/securityedge.json" "SecurityEdge config" || fail=1
  require_owner_group "$security_logs" "$security_uid" "$security_gid" "SecurityEdge log directory" || fail=1
  reject_group_world_writable "$security_logs" "SecurityEdge log directory" || fail=1
fi
tls_dirs=()
if [[ "$mode" == edgeproxy || "$mode" == platform ]]; then tls_dirs+=("$edge_tls"); fi
if [[ "$mode" == securityedge || "$mode" == platform ]]; then tls_dirs+=("$security_tls"); fi
for guarded_dir in "${tls_dirs[@]}"; do
  require_root_owner "$guarded_dir" "TLS directory" || fail=1
  reject_group_world_writable "$guarded_dir" "TLS directory" || fail=1
done

# EdgeProxy state is writable only when EdgeProxy itself is containerized.
if [[ "$mode" == edgeproxy || "$mode" == platform ]]; then
  runtime_mode_allows "$edge_state" "$edge_uid" "$edge_gid" execute "EdgeProxy state directory" || fail=1
  runtime_mode_allows "$edge_state" "$edge_uid" "$edge_gid" write "EdgeProxy state directory" || fail=1
  runtime_mode_allows "$edge_state/config.json" "$edge_uid" "$edge_gid" read "EdgeProxy config" || fail=1
fi

if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  runtime_mode_allows "$security_state" "$security_uid" "$security_gid" execute "SecurityEdge state directory" || fail=1
  runtime_mode_allows "$security_state" "$security_uid" "$security_gid" write "SecurityEdge state directory" || fail=1
  runtime_mode_allows "$security_logs" "$security_uid" "$security_gid" execute "SecurityEdge log directory" || fail=1
  runtime_mode_allows "$security_logs" "$security_uid" "$security_gid" write "SecurityEdge log directory" || fail=1
  runtime_mode_allows "$security_state/securityedge.json" "$security_uid" "$security_gid" read "SecurityEdge config" || fail=1
  runtime_mode_allows "$edge_state" "$security_uid" "$edge_gid" execute "SecurityEdge EdgeProxy-config mirror" || fail=1
  runtime_mode_allows "$edge_state/config.json" "$security_uid" "$edge_gid" read "SecurityEdge EdgeProxy config mirror" || fail=1
fi

# All production modes reject placeholder route hosts, container-local Origins,
# insecure Origin verification, and HTTP Origins unless the explicit guardrail
# is relaxed in .env.
validate_origin_policy "$edge_state/config.json" \
  "$(getv EDGEPROXY_REQUIRE_HTTPS_ORIGINS)" \
  "$(getv EDGEPROXY_ALLOW_INSECURE_ORIGIN_TLS)" \
  true true || fail=1

case "$mode" in
  edgeproxy)
    validate_tls_material "$edge_tls" \
      "$(getv EDGEPROXY_TLS_CERT_FILE_CONTAINER)" \
      "$(getv EDGEPROXY_TLS_KEY_FILE_CONTAINER)" \
      /etc/edgeproxy/tls EdgeProxy "$(getv EDGEPROXY_PUBLIC_HOSTNAME)" "$edge_uid" "$edge_gid" || fail=1
    ;;
  securityedge)
    validate_tls_material "$security_tls" \
      "$(getv SECURITYEDGE_TLS_CERT_FILE_CONTAINER)" \
      "$(getv SECURITYEDGE_TLS_KEY_FILE_CONTAINER)" \
      /etc/securityedge/tls SecurityEdge "$(getv SECURITYEDGE_PUBLIC_HOSTNAME)" "$security_uid" "$security_gid" || fail=1
    if [[ "$(getv SECURITYEDGE_REQUIRE_HTTPS_EDGEPROXY)" == true ]]; then
      validate_external_url SECURITYEDGE_EXTERNAL_EDGEPROXY_URL https
    else
      validate_external_url SECURITYEDGE_EXTERNAL_EDGEPROXY_URL
    fi
    # EdgeProxy Admin has no native TLS listener. This endpoint must therefore
    # be reachable only through a trusted private/VPN network when remote.
    validate_external_url SECURITYEDGE_EXTERNAL_EDGEPROXY_ADMIN_URL http private
    echo "NOTE: SecurityEdge-only EdgeProxy Admin URL is HTTP; keep that path private/VPN-only." >&2
    ;;
  platform)
    validate_tls_material "$security_tls" \
      "$(getv SECURITYEDGE_TLS_CERT_FILE_CONTAINER)" \
      "$(getv SECURITYEDGE_TLS_KEY_FILE_CONTAINER)" \
      /etc/securityedge/tls SecurityEdge "$(getv SECURITYEDGE_PUBLIC_HOSTNAME)" "$security_uid" "$security_gid" || fail=1
    if [[ "$(getv EDGEPROXY_INTERNAL_TLS_ENABLED)" == true ]]; then
      [[ "$(getv EDGEPROXY_INTERNAL_SCHEME)" == https ]] || {
        echo "EDGEPROXY_INTERNAL_TLS_ENABLED=true requires EDGEPROXY_INTERNAL_SCHEME=https" >&2
        fail=1
      }
      validate_tls_material "$edge_tls" \
        "$(getv EDGEPROXY_TLS_CERT_FILE_CONTAINER)" \
        "$(getv EDGEPROXY_TLS_KEY_FILE_CONTAINER)" \
        /etc/edgeproxy/tls EdgeProxy "$(getv EDGEPROXY_INTERNAL_HOSTNAME)" "$edge_uid" "$edge_gid" || fail=1
    else
      [[ "$(getv EDGEPROXY_INTERNAL_SCHEME)" == http ]] || {
        echo "EDGEPROXY_INTERNAL_TLS_ENABLED=false requires EDGEPROXY_INTERNAL_SCHEME=http" >&2
        fail=1
      }
    fi
    ;;
esac

if [[ "$mode" == platform ]]; then
  network_name=$(getv SECUREEDGE_PROD_NETWORK_NAME)
  subnet=$(getv SECUREEDGE_PROD_SUBNET)
  gateway=$(getv SECUREEDGE_PROD_GATEWAY)
  ip=$(getv SECURITYEDGE_CONTAINER_IPV4)
  cidr=$(getv SECURITYEDGE_TRUSTED_PROXY_CIDR)
  [[ "$network_name" =~ ^[A-Za-z0-9_.-]+$ ]] || {
    echo "SECUREEDGE_PROD_NETWORK_NAME must contain only letters, numbers, dot, underscore or hyphen: ${network_name:-<empty>}" >&2
    fail=1
  }
  python3 - "$subnet" "$gateway" "$ip" "$cidr" <<'PYNETWORK' || fail=1
import ipaddress, sys
subnet = ipaddress.ip_network(sys.argv[1], strict=True)
gateway = ipaddress.ip_address(sys.argv[2])
ip = ipaddress.ip_address(sys.argv[3])
trusted = ipaddress.ip_network(sys.argv[4], strict=False)
if subnet.version != 4 or gateway.version != 4 or ip.version != 4 or trusted.version != 4:
    raise SystemExit("Full Platform Docker network is IPv4-only; use an IPv4 subnet, gateway, SecurityEdge address and /32 trusted peer")
if gateway.version != subnet.version or gateway not in subnet:
    raise SystemExit(f"production gateway {gateway} is outside subnet {subnet}")
if ip.version != subnet.version or ip not in subnet:
    raise SystemExit(f"SecurityEdge IP {ip} is outside production subnet {subnet}")
for label, address in (("gateway", gateway), ("SecurityEdge IP", ip)):
    if address in {subnet.network_address, subnet.broadcast_address}:
        raise SystemExit(f"{label} {address} cannot be the network/broadcast address of {subnet}")
if ip == gateway:
    raise SystemExit(f"SecurityEdge IP {ip} must differ from Docker gateway {gateway}")
if trusted.version != ip.version or trusted.prefixlen != trusted.max_prefixlen or trusted.network_address != ip:
    raise SystemExit(f"trusted CIDR {trusted} must be exactly {ip}/{ip.max_prefixlen}")
print(f"network contract: gateway {gateway}, SecurityEdge {ip} in {subnet}, trusted peer {trusted}")
PYNETWORK

  # A supernet/subnet overlap with a real host route can black-hole cloud/LAN/
  # VPN traffic. An exact route is only safe when it can later be attributed to
  # this deployment's existing Compose-owned Docker bridge.
  host_exact_route=false
  if command -v ip >/dev/null 2>&1; then
    route_rc=0
    route_report=$(python3 - "$subnet" 2>&1 <<'PYROUTES'
import ipaddress, subprocess, sys
candidate = ipaddress.ip_network(sys.argv[1], strict=True)
text = subprocess.run(["ip", "-o", "route", "show"], text=True, capture_output=True).stdout
exact = []
bad = []
for line in text.splitlines():
    first = line.split()[0] if line.split() else ""
    try:
        route = ipaddress.ip_network(first, strict=False)
    except ValueError:
        continue
    if not candidate.overlaps(route):
        continue
    if candidate == route:
        exact.append(line)
    else:
        bad.append((route, line))
if bad:
    for route, line in bad:
        print(f"production Docker subnet {candidate} overlaps host route {route}: {line}")
    raise SystemExit(1)
if exact:
    for line in exact:
        print(f"production Docker subnet {candidate} already has an exact host route: {line}")
    raise SystemExit(3)
PYROUTES
    ) || route_rc=$?
    case "$route_rc" in
      0) ;;
      3) host_exact_route=true; printf 'NOTE: %s\n' "$route_report" >&2 ;;
      *) printf '%s\n' "$route_report" >&2; fail=1 ;;
    esac
  fi
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  if ! docker info >/dev/null 2>&1; then
    echo "Docker CLI is installed but the Docker daemon is unavailable or inaccessible" >&2
    fail=1
  else
    docker_server_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
    python3 - "$docker_server_version" <<'PYDOCKERVER' || fail=1
import re, sys
raw = sys.argv[1].strip()
match = re.match(r"^(\d+)\.(\d+)\.(\d+)", raw)
if not match:
    raise SystemExit(f"cannot determine Docker Engine server version: {raw or '<empty>'}")
version = tuple(map(int, match.groups()))
if version < (28, 0, 0):
    raise SystemExit(
        f"Docker Engine {raw} is too old for this production baseline; require >= 28.0.0 "
        f"for hardened localhost-published Admin ports"
    )
PYDOCKERVER
    docker_security=$(docker info --format '{{json .SecurityOptions}}' 2>/dev/null || true)
    if [[ "$docker_security" == *rootless* ]]; then
      echo "rootless Docker is not supported by this production baseline; use a standard rootful Docker Engine for predictable privileged-port publication and fixed numeric bind-mount ownership" >&2
      fail=1
    fi
    if [[ "$mode" == platform ]]; then
      existing_networks=""
      while IFS= read -r network_id; do
        [[ -n "$network_id" ]] || continue
        rendered=$(docker network inspect --format '{{.Name}}|{{range .IPAM.Config}}{{.Subnet}}@{{.Gateway}},{{end}}|{{with .Labels}}{{index . "com.docker.compose.project"}}{{end}}|{{with .Labels}}{{index . "com.docker.compose.network"}}{{end}}' "$network_id" 2>/dev/null || true)
        [[ -n "$rendered" ]] && existing_networks+="$rendered"$'\n'
      done < <(docker network ls -q 2>/dev/null || true)
      network_rc=0
      network_report=$(python3 - "$subnet" "$gateway" "$network_name" "$host_exact_route" "$existing_networks" 2>&1 <<'PYNET'
import ipaddress, sys
candidate = ipaddress.ip_network(sys.argv[1], strict=True)
expected_gateway = ipaddress.ip_address(sys.argv[2])
owned_name = sys.argv[3]
host_exact = sys.argv[4].lower() == "true"
raw_networks = sys.argv[5]
expected_project = "secureedge-platform-production"
expected_key = "backend"
overlaps = []
owned_ok = False
for raw in raw_networks.splitlines():
    parts = raw.split("|", 3)
    if len(parts) != 4:
        continue
    name, ipam_raw, project_label, network_label = parts
    entries = []
    for item in ipam_raw.split(","):
        item = item.strip()
        if not item or "@" not in item:
            continue
        subnet_raw, gateway_raw = item.split("@", 1)
        try:
            network = ipaddress.ip_network(subnet_raw, strict=False)
            gateway_value = ipaddress.ip_address(gateway_raw) if gateway_raw else None
        except ValueError:
            continue
        entries.append((network, gateway_value))
    if name == owned_name:
        matches = [(network, gw) for network, gw in entries if network == candidate]
        if not matches:
            found = ", ".join(str(network) for network, _ in entries) or "no IPAM subnet"
            raise SystemExit(
                f"existing production network {owned_name!r} does not use configured subnet {candidate}; found {found}"
            )
        if not any(gw == expected_gateway for _, gw in matches):
            found = ", ".join(str(gw) for _, gw in matches)
            raise SystemExit(
                f"existing production network {owned_name!r} does not use configured gateway {expected_gateway}; found {found}"
            )
        if project_label != expected_project or network_label != expected_key:
            raise SystemExit(
                f"existing network {owned_name!r} is not owned by this Compose deployment "
                f"(labels project={project_label!r}, network={network_label!r})"
            )
        owned_ok = True
        continue
    for network, _ in entries:
        if candidate.overlaps(network):
            overlaps.append(f"{name}={network}")
if overlaps:
    raise SystemExit(
        f"production Docker subnet {candidate} overlaps existing Docker network(s): {', '.join(overlaps)}"
    )
if host_exact and not owned_ok:
    raise SystemExit(
        f"production Docker subnet {candidate} already has an exact host route, but no matching "
        f"Compose-owned network {owned_name!r} with the configured subnet/gateway was found"
    )
PYNET
      ) || network_rc=$?
      if [[ "$network_rc" -ne 0 ]]; then
        printf '%s\n' "$network_report" >&2
        fail=1
      fi
    fi
  fi
  case "$mode" in
    edgeproxy) compose=compose.edgeproxy.yml ;;
    securityedge) compose=compose.securityedge.yml ;;
    platform) compose=compose.platform.yml ;;
  esac
  if (cd "$prod_dir" && docker compose --env-file .env -f "$compose" config -q); then
    echo "Docker Compose render: OK ($compose)"
  else
    echo "Docker Compose render: FAILED ($compose)" >&2
    fail=1
  fi
else
  if [[ "${host_exact_route:-false}" == true ]]; then
    echo "production Docker subnet has an exact host route, but Docker Compose is unavailable to prove that the route belongs to this deployment" >&2
    fail=1
  fi
  echo "WARNING: Docker Compose is not installed; skipped compose render check" >&2
fi

if [[ $fail -ne 0 ]]; then
  echo "production Docker preflight failed" >&2
  exit 1
fi

echo "production Docker preflight passed for: $mode"
