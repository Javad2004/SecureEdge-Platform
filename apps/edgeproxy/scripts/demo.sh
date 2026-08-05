#!/usr/bin/env sh
set -eu

PROXY_URL="${PROXY_URL:-http://project.local:8080}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9090}"
TOKEN="${TOKEN:-${EDGEPROXY_ADMIN_TOKEN:-}}"
CURL_BIN="${CURL_BIN:-curl}"

if [ -z "$TOKEN" ]; then
  printf '%s\n' 'EDGEPROXY_ADMIN_TOKEN (or TOKEN) is required.' >&2
  printf '%s\n' 'Export the value from the active EdgeProxy environment before running this script.' >&2
  exit 2
fi

request() {
  "$CURL_BIN" --noproxy '*' -fsS "$@"
}

printf '%s\n' '1) First request should be MISS'
request -i "$PROXY_URL/api/products"

printf '\n%s\n' '2) Second request should be HIT'
request -i "$PROXY_URL/api/products"

printf '\n%s\n' '3) no-store endpoint should be BYPASS'
request -i "$PROXY_URL/api/time"

printf '\n%s\n' '4) metrics'
request -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/metrics"

printf '\n%s\n' '5) route/cache/upstream status'
request -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/status"
printf '\n'
