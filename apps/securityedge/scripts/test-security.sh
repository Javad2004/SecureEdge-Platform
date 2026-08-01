#!/usr/bin/env sh
set -eu
BASE_URL="${BASE_URL:-http://project.test:8081}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9191}"
TOKEN="${TOKEN:-dev-security-token}"

curl -fsS -i "$BASE_URL/api/products"
curl -fsS -i "$BASE_URL/api/products"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")" = 403 ]
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/login?username=admin%27%20OR%201%3D1--")" = 403 ]
curl -fsS -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/info"
curl -fsS -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/metrics"
printf '\nLocal smoke test completed.\n'
