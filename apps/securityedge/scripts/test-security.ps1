param(
    [string]$Config = "",
    [string]$BaseUrl = "",
    [string]$AdminUrl = "",
    [string]$Token = "",
    [string]$EnvFile = "",
    [switch]$NoEnv,
    [switch]$Insecure
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
if (-not $BaseUrl) { $BaseUrl = Get-SecurityEdgePublicBaseUrlFromConfig -ConfigObject $configObject }
if (-not $AdminUrl) {
    $AdminUrl = Get-LocalHttpUrlFromListenAddress -ListenAddress ([string]$configObject.admin.listen_addr)
}
if (-not $Token) { $Token = [string]$configObject.admin.auth_token }
$Auth = "Authorization: Bearer $Token"
$CurlArgs = if ($Insecure) { @("-k") } else { @() }

Write-Host "Smoke test: $BaseUrl" -ForegroundColor Cyan
& curl.exe @CurlArgs -i "$BaseUrl/api/products"
& curl.exe @CurlArgs -i "$BaseUrl/api/products"
& curl.exe @CurlArgs -i "$BaseUrl/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
& curl.exe @CurlArgs -i "$BaseUrl/login?username=admin%27%20OR%201%3D1--"
curl.exe -sS -H $Auth "$AdminUrl/api/v1/info"
curl.exe -sS -H $Auth "$AdminUrl/api/v1/metrics"
curl.exe -sS -H $Auth "$AdminUrl/api/v1/dashboard/overview"
