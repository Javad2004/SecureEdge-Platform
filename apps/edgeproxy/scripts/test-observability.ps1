param(
    [string]$Config = "",
    [string]$ProxyUrl = "",
    [string]$AdminUrl = "",
    [string]$Token = "",
    [string]$OriginUrl = "",
    [string]$EnvFile = "",
    [switch]$NoEnv,
    [switch]$Insecure
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

$routeCurlArguments = @()
$selectedRoute = $configObject.routes[0]
if (-not $ProxyUrl) {
    $target = Get-EdgeProxyTestTargetFromConfig -ConfigObject $configObject
    $ProxyUrl = $target.BaseUrl
    $routeCurlArguments = @($target.CurlArguments)
    $selectedRoute = $target.Route
}
if (-not $AdminUrl) {
    $AdminUrl = Get-LocalHttpUrlFromListenAddress -ListenAddress ([string]$configObject.admin.listen_addr)
}
if (-not $Token) { $Token = [string]$configObject.admin.auth_token }
if (-not $OriginUrl) {
    $OriginUrl = [string]$selectedRoute.upstreams[0].url
}
$Headers = @("Authorization: Bearer $Token")
$commonCurlArguments = @('--noproxy', '*')
if ($Insecure) { $commonCurlArguments += '--insecure' }

Write-Host "Data-plane target: $ProxyUrl" -ForegroundColor DarkGray
Write-Host "1) Generate one MISS, one HIT, and two BYPASS requests"
Invoke-CurlChecked -Arguments ($commonCurlArguments + $routeCurlArguments + @('-sS', '-o', 'NUL', "$ProxyUrl/api/products"))
Invoke-CurlChecked -Arguments ($commonCurlArguments + $routeCurlArguments + @('-sS', '-o', 'NUL', "$ProxyUrl/api/products"))
Invoke-CurlChecked -Arguments ($commonCurlArguments + $routeCurlArguments + @('-sS', '-o', 'NUL', "$ProxyUrl/api/time"))
Invoke-CurlChecked -Arguments ($commonCurlArguments + $routeCurlArguments + @('-sS', '-o', 'NUL', "$ProxyUrl/api/time"))

Write-Host "`n2) Professional metrics"
Invoke-CurlChecked -Arguments ($commonCurlArguments + @('-sS', '-H', $Headers[0], "$AdminUrl/api/v1/metrics")) |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 30

Write-Host "`n3) Latest request-completion logs"
Invoke-CurlChecked -Arguments ($commonCurlArguments + @('-sS', '-H', $Headers[0], "$AdminUrl/api/v1/logs?event=request_completed&limit=20")) |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 20

Write-Host "`n4) Logs for one origin"
$EncodedOrigin = [uri]::EscapeDataString($OriginUrl)
Invoke-CurlChecked -Arguments ($commonCurlArguments + @('-sS', '-H', $Headers[0], "$AdminUrl/api/v1/logs?event=upstream_attempt&upstream=$EncodedOrigin&limit=20")) |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 20

Write-Host "`n5) Health and log-store status"
Invoke-CurlChecked -Arguments ($commonCurlArguments + @('-sS', '-H', $Headers[0], "$AdminUrl/api/v1/status")) |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 20
