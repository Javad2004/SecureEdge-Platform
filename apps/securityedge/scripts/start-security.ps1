param(
    [string]$Config = ".\configs\local-dev.json"
)

$ErrorActionPreference = "Stop"
Write-Host "Validating SecurityEdge configuration..." -ForegroundColor Cyan
go run ./cmd/securityedge -config $Config -validate
Write-Host "Starting SecurityEdge..." -ForegroundColor Green
go run ./cmd/securityedge -config $Config -pretty-logs
