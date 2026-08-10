#!/usr/bin/env sh
set -eu

BASE_URL="${BASE_URL:-http://project.test:8081}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9191}"
TOKEN="${TOKEN:-${SECURITYEDGE_ADMIN_TOKEN:-}}"
CURL_BIN="${CURL_BIN:-curl}"
INSECURE="${INSECURE:-0}"

if [ -z "$TOKEN" ]; then
  printf '%s\n' 'SECURITYEDGE_ADMIN_TOKEN (or TOKEN) is required.' >&2
  printf '%s\n' 'Export the value from the active SecurityEdge environment before running this script.' >&2
  exit 2
fi

curl_common() {
  if [ "$INSECURE" = "1" ]; then
    "$CURL_BIN" --noproxy '*' -k "$@"
  else
    "$CURL_BIN" --noproxy '*' "$@"
  fi
}
request() {
  curl_common -fsS "$@"
}
status_code() {
  curl_common -sS -o /dev/null -w '%{http_code}' "$@"
}

request -i "$BASE_URL/api/products"
request -i "$BASE_URL/api/products"
[ "$(status_code "$BASE_URL/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")" = 403 ]
[ "$(status_code "$BASE_URL/login?username=admin%27%20OR%201%3D1--")" = 403 ]
request -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/info"
request -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/metrics"
printf '\nLocal smoke test completed.\n'
