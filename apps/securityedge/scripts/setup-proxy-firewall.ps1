param(
    [string]$Config = "",
    [string]$EnvFile = "",
    [switch]$NoEnv,
    [switch]$Apply,
    [string]$RemoteAddress = "LocalSubnet",
    [switch]$ExposeDnsResolver
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

$ingressPort = Get-PortFromEndpoint -Endpoint ([string]$configObject.server.listen_addr)
$rules = @(
    @{ Name = "SecurityEdge HTTP Ingress $ingressPort"; Protocol = "TCP"; Port = $ingressPort }
)

if ($ExposeDnsResolver) {
    if (-not $configObject.admin.connectivity.dns.enabled) {
        Write-Warning "DNS probing is disabled in the effective SecurityEdge configuration. Firewall exposure is still possible, but verify that a DNS service is intentionally running on this host."
    }
    $dnsPort = Get-PortFromEndpoint -Endpoint ([string]$configObject.admin.connectivity.dns.server)
    $rules += @(
        @{ Name = "DNS Resolver UDP $dnsPort"; Protocol = "UDP"; Port = $dnsPort },
        @{ Name = "DNS Resolver TCP $dnsPort"; Protocol = "TCP"; Port = $dnsPort }
    )
}

if (-not $Apply) {
    Write-Host "Dry run. Re-run with -Apply from an elevated PowerShell to create or replace these rules:" -ForegroundColor Yellow
    $rules | Format-Table Name, Protocol, Port -AutoSize
    Write-Host "Remote scope: $RemoteAddress"
    if (-not $ExposeDnsResolver) {
        Write-Host "DNS exposure is omitted by default. Add -ExposeDnsResolver only when this host intentionally serves DNS to the selected remote scope." -ForegroundColor Cyan
    }
    exit 0
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}

foreach ($rule in $rules) {
    Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow `
        -Protocol $rule.Protocol -LocalPort $rule.Port -RemoteAddress $RemoteAddress -Profile Any | Out-Null
    Write-Host "[OK] $($rule.Name)" -ForegroundColor Green
}

Write-Host "EdgeProxy data-plane, EdgeProxy Admin, and SecurityEdge Admin ports are intentionally not opened by this script." -ForegroundColor Cyan
