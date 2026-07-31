param(
    [string]$ProxyUrl = "http://project.local:8080",
    [string]$AdminUrl = "http://127.0.0.1:9090",
    [string]$Token = "dev-token"
)

$ErrorActionPreference = "Stop"

Write-Host "1) First request: expected MISS"
curl.exe -i "$ProxyUrl/api/products"

Write-Host "`n2) Second request: expected HIT"
curl.exe -i "$ProxyUrl/api/products"

Write-Host "`n3) Dynamic endpoint: expected BYPASS"
curl.exe -i "$ProxyUrl/api/time"

Write-Host "`n4) Metrics"
curl.exe -s -H "Authorization: Bearer $Token" "$AdminUrl/api/v1/metrics"

Write-Host "`n5) Status"
curl.exe -s -H "Authorization: Bearer $Token" "$AdminUrl/api/v1/status"
