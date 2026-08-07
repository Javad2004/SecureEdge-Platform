# Cache Behavior

This example demonstrates EdgeProxy caching while all application traffic still enters through SecurityEdge.

Start the standard local stack from the [examples index](../README.md), then run [`requests.http`](./requests.http) in order.

## Expected sequence

1. Purge the `demo-app` Route cache through the authenticated SecurityEdge Admin API.
2. Request `/api/products`: expect `X-Cache: MISS`.
3. Repeat the same request before the Origin TTL expires: expect `X-Cache: HIT` and the same cached `generated_at` value.
4. Request `/api/private`: the Origin returns `Cache-Control: private, no-store` and `Set-Cookie`, so the response must not become a shared cache hit.
5. Request `/api/products` with an `Authorization` header: the local Route has `cache_authorized_requests: false`, so expect `X-Cache: BYPASS`.
6. Inspect the Route cache settings through the read-only Control Plane endpoint.

The purge changes only runtime cache contents; it does **not** modify JSON configuration.

## PowerShell / curl.exe equivalents

```powershell
$Headers = @{ Authorization = "Bearer dev-security-token" }

Invoke-RestMethod `
  -Method Post `
  -Headers $Headers `
  -Uri http://127.0.0.1:9191/api/v1/edgeproxy/routes/demo-app/cache/purge

curl.exe -i http://127.0.0.1:8081/api/products
curl.exe -i http://127.0.0.1:8081/api/products
curl.exe -i http://127.0.0.1:8081/api/private
curl.exe -i -H "Authorization: Bearer example-user-token" http://127.0.0.1:8081/api/products

Invoke-RestMethod `
  -Method Get `
  -Headers $Headers `
  -Uri http://127.0.0.1:9191/api/v1/edgeproxy/routes/demo-app/cache |
  ConvertTo-Json -Depth 8
```

If more than 30 seconds elapse between the first two `/api/products` requests, the Origin's cache TTL may expire and the second request can legitimately become another `MISS`.
