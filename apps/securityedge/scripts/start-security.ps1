param(
    [string]$Config = ".\configs\securityedge.json",
    [ValidateSet("debug", "info", "warn", "error")]
    [string]$LogLevel = "info"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Config)) {
    throw "Configuration file not found: $Config"
}

Write-Host "Validating SecurityEdge configuration: $Config" -ForegroundColor Cyan
go run ./cmd/securityedge -config $Config -validate
if ($LASTEXITCODE -ne 0) { throw "Configuration validation failed." }

$resolvedConfig = (Resolve-Path $Config).Path
$configObject = Get-Content $resolvedConfig -Raw | ConvertFrom-Json

Write-Host "Starting SecurityEdge" -ForegroundColor Green
Write-Host "Mode:          $($configObject.server.mode)" -ForegroundColor DarkGray
Write-Host "Ingress:       $($configObject.server.listen_addr)" -ForegroundColor DarkGray
Write-Host "EdgeProxy:     $($configObject.server.upstream_proxy_url)" -ForegroundColor DarkGray
if ($configObject.admin.enabled) {
    Write-Host "Operations UI: $($configObject.admin.listen_addr)" -ForegroundColor DarkGray
}
Write-Host "Environment variables SECURITYEDGE_ADMIN_TOKEN and EDGEPROXY_ADMIN_TOKEN override file tokens." -ForegroundColor DarkGray

go run ./cmd/securityedge -config $Config -pretty-logs -log-level $LogLevel
