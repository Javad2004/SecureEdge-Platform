#!/usr/bin/env bash
set -euo pipefail

usage() { echo "Usage: validate.sh edgeproxy|securityedge|platform" >&2; }
mode=${1:-}
case "$mode" in edgeproxy|securityedge|platform) ;; *) usage; exit 64;; esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prod_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
env_file="$prod_dir/.env"

bash "$script_dir/doctor.sh" "$mode"
command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 69; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 69; }

case "$mode" in
  edgeproxy) compose=compose.edgeproxy.yml ;;
  securityedge) compose=compose.securityedge.yml ;;
  platform) compose=compose.platform.yml ;;
esac

getv() { awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$env_file"; }

platform_validation_ip() {
  local network_name subnet gateway reserved_ip network_json
  network_name=$(getv SECUREEDGE_PROD_NETWORK_NAME)
  subnet=$(getv SECUREEDGE_PROD_SUBNET)
  gateway=$(getv SECUREEDGE_PROD_GATEWAY)
  reserved_ip=$(getv SECURITYEDGE_CONTAINER_IPV4)

  # A running full-platform SecurityEdge already owns its fixed production IP.
  # Compose run inherits that ipv4_address and would otherwise fail with
  # "Address already in use" during an in-place update. Inspect the existing
  # network and choose a free short-lived address for the validation container.
  if ! network_json=$(docker network inspect "$network_name" 2>/dev/null); then
    network_json='[]'
  fi
  printf '%s\n' "$network_json" | python3 "$script_dir/select-validation-ip.py" \
    --subnet "$subnet" --gateway "$gateway" --reserved-ip "$reserved_ip"
}

cd "$prod_dir"
docker compose --env-file .env -f "$compose" build

if [[ "$mode" == edgeproxy || "$mode" == platform ]]; then
  docker compose --env-file .env -f "$compose" run --rm --no-deps edgeproxy -config /app/config/config.json -validate
fi
if [[ "$mode" == securityedge ]]; then
  docker compose --env-file .env -f "$compose" run --rm --no-deps securityedge -config /app/config/securityedge.json -validate
elif [[ "$mode" == platform ]]; then
  validation_ip=$(platform_validation_ip)
  echo "validating SecurityEdge with temporary one-off address $validation_ip (production address remains $(getv SECURITYEDGE_CONTAINER_IPV4))"
  SECURITYEDGE_CONTAINER_IPV4="$validation_ip" \
    docker compose --env-file .env -f "$compose" run --rm --no-deps securityedge -config /app/config/securityedge.json -validate
fi

echo "images built and production configuration validated for: $mode"
