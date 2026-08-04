param(
    [string]$Config = "",
    [string]$EnvFile = "",
    [switch]$NoEnv,
    [ValidateSet("debug", "info", "warn", "error")]
    [string]$LogLevel = "info"
)

$ErrorActionPreference = "Stop"

$commonArgs = @("run", "./cmd/securityedge")
if ($Config -ne "") { $commonArgs += @("-config", $Config) }
if ($EnvFile -ne "") { $commonArgs += @("-env", $EnvFile) }
if ($NoEnv) { $commonArgs += "-no-env" }

Write-Host "Validating SecurityEdge configuration" -ForegroundColor Cyan
go @commonArgs -validate
if ($LASTEXITCODE -ne 0) { throw "Configuration validation failed." }

Write-Host "Starting SecurityEdge" -ForegroundColor Green
Write-Host "CLI values override process variables; process variables override .env; .env overrides JSON." -ForegroundColor DarkGray
go @commonArgs -pretty-logs -log-level $LogLevel
if ($LASTEXITCODE -ne 0) { throw "SecurityEdge exited with code $LASTEXITCODE." }
