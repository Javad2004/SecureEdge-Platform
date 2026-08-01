param(
    [string]$Config = ".\configs\securityedge.json",
    [ValidateSet("debug", "info", "warn", "error")]
    [string]$LogLevel = "info"
)

$ErrorActionPreference = "Stop"

Write-Host "Validating SecurityEdge configuration: $Config" -ForegroundColor Cyan
go run ./cmd/securityedge -config $Config -validate
if ($LASTEXITCODE -ne 0) { throw "Configuration validation failed." }

Write-Host "Starting SecurityEdge gateway" -ForegroundColor Green
Write-Host "Public HTTP: 0.0.0.0:80" -ForegroundColor DarkGray
Write-Host "Dashboard:   http://127.0.0.1:9191" -ForegroundColor DarkGray
Write-Host "Use environment variables SECURITYEDGE_ADMIN_TOKEN and EDGEPROXY_ADMIN_TOKEN to override file tokens." -ForegroundColor DarkGray
go run ./cmd/securityedge -config $Config -pretty-logs -log-level $LogLevel
