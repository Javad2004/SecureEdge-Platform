#!/usr/bin/env bash
set -euo pipefail

usage() { echo "Usage: validate.sh edgeproxy|securityedge|platform" >&2; }
mode=${1:-}
case "$mode" in edgeproxy|securityedge|platform) ;; *) usage; exit 64;; esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prod_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

bash "$script_dir/doctor.sh" "$mode"
command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 69; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 69; }

case "$mode" in
  edgeproxy) compose=compose.edgeproxy.yml ;;
  securityedge) compose=compose.securityedge.yml ;;
  platform) compose=compose.platform.yml ;;
esac

cd "$prod_dir"
docker compose --env-file .env -f "$compose" build

if [[ "$mode" == edgeproxy || "$mode" == platform ]]; then
  docker compose --env-file .env -f "$compose" run --rm --no-deps edgeproxy -config /app/config/config.json -validate
fi
if [[ "$mode" == securityedge || "$mode" == platform ]]; then
  docker compose --env-file .env -f "$compose" run --rm --no-deps securityedge -config /app/config/securityedge.json -validate
fi

echo "images built and production configuration validated for: $mode"
