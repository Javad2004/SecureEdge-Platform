param(
    [string]$BaseUrl = "http://project.test:8081",
    [string]$AdminUrl = "http://127.0.0.1:9191",
    [string]$Token = $(if ($env:SECURITYEDGE_ADMIN_TOKEN) { $env:SECURITYEDGE_ADMIN_TOKEN } else { "dev-security-token" })
)

$ErrorActionPreference = "Stop"
$Auth = "Authorization: Bearer $Token"

Write-Host "Local-development smoke test: $BaseUrl" -ForegroundColor Cyan
curl.exe -i "$BaseUrl/api/products"
curl.exe -i "$BaseUrl/api/products"
curl.exe -i "$BaseUrl/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
curl.exe -i "$BaseUrl/login?username=admin%27%20OR%201%3D1--"
curl.exe -sS -H $Auth "$AdminUrl/api/v1/info"
curl.exe -sS -H $Auth "$AdminUrl/api/v1/metrics"
curl.exe -sS -H $Auth "$AdminUrl/api/v1/dashboard/overview"
