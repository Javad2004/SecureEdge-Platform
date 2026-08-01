param(
    [switch]$Apply,
    [string]$RemoteAddress = "LocalSubnet"
)

$rules = @(
    @{ Name = "SecurityEdge HTTP 80"; Protocol = "TCP"; Port = 80 },
    @{ Name = "Technitium DNS UDP 53"; Protocol = "UDP"; Port = 53 },
    @{ Name = "Technitium DNS TCP 53"; Protocol = "TCP"; Port = 53 }
)

if (-not $Apply) {
    Write-Host "Dry run only. Re-run with -Apply from an elevated PowerShell to create/update:" -ForegroundColor Yellow
    $rules | Format-Table Name, Protocol, Port -AutoSize
    Write-Host "Remote scope: $RemoteAddress"
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

Write-Host "Internal ports 8080, 9090, and 9191 remain protected by loopback binding and are not opened here." -ForegroundColor Cyan
