#!/usr/bin/env sh
set -eu

BASE_URL="${BASE_URL:-http://project.test:8081}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9191}"
TOKEN="${TOKEN:-${SECURITYEDGE_ADMIN_TOKEN:-}}"
CURL_BIN="${CURL_BIN:-curl}"

if [ -z "$TOKEN" ]; then
  printf '%s\n' 'SECURITYEDGE_ADMIN_TOKEN (or TOKEN) is required.' >&2
  printf '%s\n' 'Export the value from the active SecurityEdge environment before running this script.' >&2
  exit 2
fi

request() {
  "$CURL_BIN" --noproxy '*' -fsS "$@"
}
status_code() {
  "$CURL_BIN" --noproxy '*' -sS -o /dev/null -w '%{http_code}' "$@"
}

for path in \
  '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  '/login?username=admin%27%20OR%201%3D1--' \
  '/fetch?url=http://169.254.169.254/latest/meta-data' \
  '/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D' \
  '/download?file=..%2F..%2Fetc%2Fpasswd'; do
  code="$(status_code "$BASE_URL$path")"
  [ "$code" = 403 ] || { printf 'expected 403, got %s for %s\n' "$code" "$path" >&2; exit 1; }
done

n=1
seen429=0
while [ "$n" -le 60 ]; do
  code="$(status_code "$BASE_URL/flood?i=$n")"
  [ "$code" = 429 ] && seen429=1
  n=$((n + 1))
done
[ "$seen429" = 1 ] || { printf '%s\n' 'rate limiter did not return 429' >&2; exit 1; }

request -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/status"
request -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/bans"
request -X DELETE -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/bans"
printf '\nProtection and auto-ban tests completed.\n'
