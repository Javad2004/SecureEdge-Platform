param(
    [string]$Config = "",
    [string]$ProxyUrl = "",
    [string]$AdminUrl = "",
    [string]$Token = "",
    [string]$EnvFile = "",
    [switch]$NoEnv
)

$ErrorActionPreference = "Stop"
if ($NoEnv -and $EnvFile) { throw "-EnvFile and -NoEnv cannot be used together." }
. "$PSScriptRoot\dotenv.ps1"

$configEnvironmentPreexisting = $null -ne (Get-Item -LiteralPath Env:EDGEPROXY_CONFIG -ErrorAction SilentlyContinue)
$loadedEnv = $null
if (-not $NoEnv) {
    $explicitEnv = if ($EnvFile) { $EnvFile } else { Get-NonEmptyEnvironmentValue EDGEPROXY_ENV_FILE }
    $loadedEnv = Import-ApplicationDotEnv -ExplicitPath $explicitEnv -Candidates @((Join-Path $PSScriptRoot "..\.env"))
    if ($loadedEnv) { Write-Host "Loaded environment: $loadedEnv" -ForegroundColor DarkGray }
}

$configPath = Resolve-EffectiveConfigPath -ExplicitValue $Config -EnvironmentVariable EDGEPROXY_CONFIG `
    -EnvironmentWasPreexisting $configEnvironmentPreexisting -LoadedEnvPath $loadedEnv `
    -Candidates @((Join-Path $PSScriptRoot "..\configs\edgeproxy.json"))
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Configuration file not found: $configPath" }
$configObject = Get-Content (Resolve-Path -LiteralPath $configPath) -Raw | ConvertFrom-Json
$configObject = Apply-EdgeProxyEnvironmentOverrides -ConfigObject $configObject

if (-not $ProxyUrl) { $ProxyUrl = "http://project.test" }
if (-not $AdminUrl) {
    $AdminUrl = Get-LocalHttpUrlFromListenAddress -ListenAddress ([string]$configObject.admin.listen_addr)
}
if (-not $Token) { $Token = [string]$configObject.admin.auth_token }
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
