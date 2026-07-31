#!/usr/bin/env sh
set -eu
BASE_URL="${BASE_URL:-http://project.test:8081}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9191}"
TOKEN="${TOKEN:-dev-security-token}"

curl -i "$BASE_URL/api/products"
curl -i "$BASE_URL/api/products"
curl -i "$BASE_URL/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
curl -i "$BASE_URL/login?username=admin%27%20OR%201%3D1--"
curl -sS -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/metrics"
printf '\n'
curl -sS -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/dashboard/overview"
printf '\n'
