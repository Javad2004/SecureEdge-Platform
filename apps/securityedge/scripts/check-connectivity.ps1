param(
    [string]$Config = "",
    [string]$AdminUrl = "",
    [string]$Token = "",
    [string]$EnvFile = "",
    [switch]$NoEnv,
    [ValidateSet("", "healthy", "degraded", "down")]
    [string]$ExpectedOverall = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
if ($NoEnv -and $EnvFile) { throw "-EnvFile and -NoEnv cannot be used together." }
. "$PSScriptRoot\dotenv.ps1"

$configEnvironmentPreexisting = $null -ne (Get-Item -LiteralPath Env:SECURITYEDGE_CONFIG -ErrorAction SilentlyContinue)
$loadedEnv = $null
if (-not $NoEnv) {
    $explicitEnv = if ($EnvFile) { $EnvFile } else { Get-NonEmptyEnvironmentValue SECURITYEDGE_ENV_FILE }
    $loadedEnv = Import-ApplicationDotEnv -ExplicitPath $explicitEnv -Candidates @((Join-Path $PSScriptRoot "..\.env"))
    if ($loadedEnv) { Write-Host "Loaded environment: $loadedEnv" -ForegroundColor DarkGray }
}

$configPath = Resolve-EffectiveConfigPath -ExplicitValue $Config -EnvironmentVariable SECURITYEDGE_CONFIG `
    -EnvironmentWasPreexisting $configEnvironmentPreexisting -LoadedEnvPath $loadedEnv `
    -Candidates @((Join-Path $PSScriptRoot "..\configs\securityedge.json"))
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Configuration file not found: $configPath" }
$configObject = Get-Content (Resolve-Path -LiteralPath $configPath) -Raw | ConvertFrom-Json
$configObject = Apply-SecurityEdgeEnvironmentOverrides -ConfigObject $configObject
if (-not $AdminUrl) {
    $AdminUrl = Get-LocalHttpUrlFromListenAddress -ListenAddress ([string]$configObject.admin.listen_addr)
}
if (-not $Token) { $Token = [string]$configObject.admin.auth_token }

$headers = @{ Authorization = "Bearer $Token" }
$method = if ($Force) { "Post" } else { "Get" }
$path = if ($Force) { "/api/v1/connectivity/check" } else { "/api/v1/connectivity" }
$result = Invoke-RestMethod "$AdminUrl$path" -Headers $headers -Method $method

Write-Host "Overall:       $($result.overall_status)" -ForegroundColor Cyan
Write-Host "Traffic path:  $($result.traffic_path_status)"
Write-Host "EdgeProxy:     $($result.edgeproxy_connection_status)"
Write-Host "Observability: $($result.observability_status)"
Write-Host "Checked:       $($result.generated_at)"
Write-Host "Summary:       $($result.summary)"

$result.components |
    Select-Object name, status, latency_ms, http_status, consecutive_failures, last_success_at, last_failure_at, endpoint |
    Format-Table -AutoSize

Write-Host "Routes: $($result.counts.ready_routes)/$($result.counts.total_routes) ready" -ForegroundColor Cyan
Write-Host "Origins: $($result.counts.healthy_origins)/$($result.counts.total_origins) healthy" -ForegroundColor Cyan

if ($ExpectedOverall -and $result.overall_status -ne $ExpectedOverall) {
    throw "Expected overall status '$ExpectedOverall', got '$($result.overall_status)'."
}

$result
