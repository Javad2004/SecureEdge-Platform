#!/usr/bin/env sh
set -eu
PROXY_URL="${PROXY_URL:-http://project.local:8080}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9090}"
TOKEN="${TOKEN:-dev-token}"

echo "1) First request should be MISS"
curl -i "$PROXY_URL/api/products"

echo "\n2) Second request should be HIT"
curl -i "$PROXY_URL/api/products"

echo "\n3) no-store endpoint should be BYPASS"
curl -i "$PROXY_URL/api/time"

echo "\n4) metrics"
curl -s -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/metrics"

echo "\n5) route/cache/upstream status"
curl -s -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/v1/status"
