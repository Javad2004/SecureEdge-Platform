param(
    [string]$Config = "",
    [string]$EnvFile = "",
    [switch]$NoEnv
)

$ErrorActionPreference = "Stop"

$commonArgs = @("run", "./cmd/edgeproxy")
if ($Config -ne "") { $commonArgs += @("-config", $Config) }
if ($EnvFile -ne "") { $commonArgs += @("-env", $EnvFile) }
if ($NoEnv) { $commonArgs += "-no-env" }

Write-Host "Validating EdgeProxy configuration" -ForegroundColor Cyan
go @commonArgs -validate
if ($LASTEXITCODE -ne 0) { throw "Configuration validation failed." }

Write-Host "Starting EdgeProxy" -ForegroundColor Green
go @commonArgs -pretty-logs
if ($LASTEXITCODE -ne 0) { throw "EdgeProxy exited with code $LASTEXITCODE." }
