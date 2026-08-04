param(
    [string]$Config = "",
    [string]$EnvFile = "",
    [switch]$NoEnv,
    [int]$IngressPort = 0,
    [int]$EdgeProxyDataPort = 0,
    [int]$EdgeProxyAdminPort = 0,
    [int]$SecurityEdgeAdminPort = 0
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

if ($IngressPort -eq 0) { $IngressPort = Get-PortFromEndpoint -Endpoint ([string]$configObject.server.listen_addr) }
if ($EdgeProxyDataPort -eq 0) { $EdgeProxyDataPort = ([Uri]$configObject.server.upstream_proxy_url).Port }
if ($EdgeProxyAdminPort -eq 0) { $EdgeProxyAdminPort = ([Uri]$configObject.edgeproxy.admin_url).Port }
if ($SecurityEdgeAdminPort -eq 0) { $SecurityEdgeAdminPort = Get-PortFromEndpoint -Endpoint ([string]$configObject.admin.listen_addr) }

$expected = @(
    @{ Port = $IngressPort; AddressClass = "network"; Name = "SecurityEdge public ingress" },
    @{ Port = $EdgeProxyDataPort; AddressClass = "loopback"; Name = "EdgeProxy internal data plane" },
    @{ Port = $EdgeProxyAdminPort; AddressClass = "loopback"; Name = "EdgeProxy Admin API" },
    @{ Port = $SecurityEdgeAdminPort; AddressClass = "loopback"; Name = "SecurityEdge operations API and console" }
)

$ports = @($expected | Select-Object -ExpandProperty Port -Unique)
$listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in $ports } |
    Select-Object LocalAddress, LocalPort, OwningProcess)

function Is-Loopback([string]$Address) {
    return $Address -in @("127.0.0.1", "::1")
}

function Is-NetworkListener([string]$Address) {
    return $Address -in @("0.0.0.0", "::") -or -not (Is-Loopback $Address)
}

Write-Host "Current listener exposure" -ForegroundColor Cyan
$listeners | Sort-Object LocalPort | Format-Table -AutoSize

Write-Host "Expected security boundaries" -ForegroundColor Cyan
$missing = $false
foreach ($item in $expected) {
    $matches = @($listeners | Where-Object { $_.LocalPort -eq $item.Port })
    $valid = if ($item.AddressClass -eq "loopback") {
        @($matches | Where-Object { Is-Loopback $_.LocalAddress }).Count -gt 0
    }
    else {
        @($matches | Where-Object { Is-NetworkListener $_.LocalAddress }).Count -gt 0
    }

    if ($valid) {
        Write-Host "[OK] $($item.Name) uses the expected $($item.AddressClass) exposure on port $($item.Port)." -ForegroundColor Green
    }
    else {
        Write-Host "[MISSING] $($item.Name) is not listening with the expected $($item.AddressClass) exposure on port $($item.Port)." -ForegroundColor Yellow
        $missing = $true
    }
}

$internalPorts = @($EdgeProxyDataPort, $EdgeProxyAdminPort, $SecurityEdgeAdminPort)
$unsafe = @($listeners | Where-Object {
    $_.LocalPort -in $internalPorts -and -not (Is-Loopback $_.LocalAddress)
})

if ($unsafe.Count -gt 0) {
    Write-Host "Internal listeners are exposed beyond loopback:" -ForegroundColor Red
    $unsafe | Format-Table -AutoSize
    exit 1
}

if ($missing) { exit 2 }
Write-Host "Listener exposure matches the effective JSON and environment configuration." -ForegroundColor Green
