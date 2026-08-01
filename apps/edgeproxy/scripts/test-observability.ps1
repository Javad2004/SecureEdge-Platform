param(
    [string]$ProxyUrl = "http://project.test",
    [string]$AdminUrl = "http://127.0.0.1:9090",
    [string]$Token = "EdgeProxyDemo2026",
    [string]$OriginUrl = "http://10.36.74.43:9000"
)

$ErrorActionPreference = "Stop"
$Headers = @("Authorization: Bearer $Token")

Write-Host "1) Generate one MISS, one HIT, and two BYPASS requests"
curl.exe -s -o NUL "$ProxyUrl/api/products"
curl.exe -s -o NUL "$ProxyUrl/api/products"
curl.exe -s -o NUL "$ProxyUrl/api/time"
curl.exe -s -o NUL "$ProxyUrl/api/time"

Write-Host "`n2) Professional metrics"
curl.exe -s -H $Headers[0] "$AdminUrl/api/v1/metrics" |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 30

Write-Host "`n3) Latest request-completion logs"
curl.exe -s -H $Headers[0] "$AdminUrl/api/v1/logs?event=request_completed&limit=20" |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 20

Write-Host "`n4) Logs for one origin"
$EncodedOrigin = [uri]::EscapeDataString($OriginUrl)
curl.exe -s -H $Headers[0] "$AdminUrl/api/v1/logs?event=upstream_attempt&upstream=$EncodedOrigin&limit=20" |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 20

Write-Host "`n5) Health and log-store status"
curl.exe -s -H $Headers[0] "$AdminUrl/api/v1/status" |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 20
