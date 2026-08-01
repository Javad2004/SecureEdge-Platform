param(
    [string]$ProxyUrl = "http://project.test",
    [string]$AdminUrl = "http://127.0.0.1:9090",
    [string]$Token = "EdgeProxyDemo2026"
)

$ErrorActionPreference = "Stop"
$Auth = "Authorization: Bearer $Token"

Write-Host "1) Admin liveness"
curl.exe -i "$AdminUrl/healthz"

Write-Host "`n2) Route readiness"
curl.exe -i "$AdminUrl/readyz"

Write-Host "`n3) First products request: expected MISS"
curl.exe -i "$ProxyUrl/api/products"

Write-Host "`n4) Second products request: expected HIT"
curl.exe -i "$ProxyUrl/api/products"

Write-Host "`n5) Dynamic endpoint: expected BYPASS"
curl.exe -i "$ProxyUrl/api/time"

Write-Host "`n6) Metrics"
curl.exe -s -H $Auth "$AdminUrl/api/v1/metrics" |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 30

Write-Host "`n7) Status"
curl.exe -s -H $Auth "$AdminUrl/api/v1/status" |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 20

Write-Host "`n8) Latest structured logs"
curl.exe -s -H $Auth "$AdminUrl/api/v1/logs?limit=20" |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 20
