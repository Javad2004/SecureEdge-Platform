param(
    [string]$Config = ".\configs\securityedge.json",
    [int]$IngressPort = 0,
    [int]$EdgeProxyDataPort = 0,
    [int]$EdgeProxyAdminPort = 0,
    [int]$SecurityEdgeAdminPort = 0
)

$ErrorActionPreference = "Stop"

function Get-PortFromListenAddress([string]$Address) {
    if ($Address -notmatch ':(\d+)$') { throw "Invalid listen address: $Address" }
    return [int]$Matches[1]
}

function Get-PortFromUrl([string]$Address) {
    return ([Uri]$Address).Port
}

if (Test-Path $Config) {
    $configObject = Get-Content (Resolve-Path $Config) -Raw | ConvertFrom-Json
    if ($IngressPort -eq 0) { $IngressPort = Get-PortFromListenAddress $configObject.server.listen_addr }
    if ($EdgeProxyDataPort -eq 0) { $EdgeProxyDataPort = Get-PortFromUrl $configObject.server.upstream_proxy_url }
    if ($EdgeProxyAdminPort -eq 0) { $EdgeProxyAdminPort = Get-PortFromUrl $configObject.edgeproxy.admin_url }
    if ($SecurityEdgeAdminPort -eq 0) { $SecurityEdgeAdminPort = Get-PortFromListenAddress $configObject.admin.listen_addr }
}

if ($IngressPort -eq 0) { $IngressPort = 80 }
if ($EdgeProxyDataPort -eq 0) { $EdgeProxyDataPort = 8080 }
if ($EdgeProxyAdminPort -eq 0) { $EdgeProxyAdminPort = 9090 }
if ($SecurityEdgeAdminPort -eq 0) { $SecurityEdgeAdminPort = 9191 }

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
Write-Host "Listener exposure matches the configured security boundary." -ForegroundColor Green
