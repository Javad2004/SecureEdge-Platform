$ErrorActionPreference = "Stop"

$expected = @(
    @{ Port = 80;   Address = "0.0.0.0";   Name = "SecurityEdge public HTTP" },
    @{ Port = 8080; Address = "127.0.0.1"; Name = "EdgeProxy internal HTTP" },
    @{ Port = 9090; Address = "127.0.0.1"; Name = "EdgeProxy Admin API" },
    @{ Port = 9191; Address = "127.0.0.1"; Name = "SecurityEdge Admin/Dashboard" }
)

$listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in 80, 8080, 9090, 9191 } |
    Select-Object LocalAddress, LocalPort, OwningProcess

Write-Host "Current listeners" -ForegroundColor Cyan
$listeners | Sort-Object LocalPort | Format-Table -AutoSize

Write-Host "Expected exposure checks" -ForegroundColor Cyan
foreach ($item in $expected) {
    $matches = @($listeners | Where-Object {
        $_.LocalPort -eq $item.Port -and $_.LocalAddress -eq $item.Address
    })

    if ($matches.Count -gt 0) {
        Write-Host "[OK] $($item.Name): $($item.Address):$($item.Port)" -ForegroundColor Green
    }
    else {
        Write-Host "[MISSING] $($item.Name): expected $($item.Address):$($item.Port)" -ForegroundColor Yellow
    }
}

$unsafe = @($listeners | Where-Object {
    $_.LocalPort -in 8080, 9090, 9191 -and $_.LocalAddress -notin "127.0.0.1", "::1"
})

if ($unsafe.Count -gt 0) {
    Write-Host "WARNING: Internal listeners are exposed beyond loopback:" -ForegroundColor Red
    $unsafe | Format-Table -AutoSize
    exit 1
}

Write-Host "Internal listener exposure is correct." -ForegroundColor Green
