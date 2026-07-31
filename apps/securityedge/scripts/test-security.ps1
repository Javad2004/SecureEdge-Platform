param(
    [string]$BaseUrl = "http://project.test:8081",
    [string]$AdminUrl = "http://127.0.0.1:9191",
    [string]$Token = "dev-security-token"
)

$ErrorActionPreference = "Stop"
$Auth = "Authorization: Bearer $Token"

Write-Host "1. Clean request (expected ALLOW/MISS)" -ForegroundColor Cyan
curl.exe -i "$BaseUrl/api/products"

Write-Host "2. Repeated request (expected ALLOW/HIT)" -ForegroundColor Cyan
curl.exe -i "$BaseUrl/api/products"

Write-Host "3. XSS (expected 403)" -ForegroundColor Cyan
curl.exe -i "$BaseUrl/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

Write-Host "4. SQL injection (expected 403)" -ForegroundColor Cyan
curl.exe -i "$BaseUrl/login?username=admin%27%20OR%201%3D1--"

Write-Host "5. Security metrics" -ForegroundColor Cyan
curl.exe -s -H $Auth "$AdminUrl/api/v1/metrics" | ConvertFrom-Json | ConvertTo-Json -Depth 20

Write-Host "6. Aggregated dashboard overview" -ForegroundColor Cyan
curl.exe -s -H $Auth "$AdminUrl/api/v1/dashboard/overview" | ConvertFrom-Json | ConvertTo-Json -Depth 20
