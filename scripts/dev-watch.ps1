[CmdletBinding()]
param(
    [string]$EdgeProxyConfig = 'apps/edgeproxy/configs/local-dev.json',
    [string]$SecurityEdgeConfig = 'apps/securityedge/configs/local-dev.json',
    [string]$EdgeProxyEnv = 'apps/edgeproxy/.env',
    [string]$SecurityEdgeEnv = 'apps/securityedge/.env',
    [ValidateRange(200, 10000)]
    [int]$PollMilliseconds = 500,
    [ValidateRange(200, 10000)]
    [int]$DebounceMilliseconds = 750,
    [switch]$PrettyLogs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$DevDirectory = Join-Path $Root '.dev'
$BinDirectory = Join-Path $DevDirectory 'bin'
$IsWindowsHost = $env:OS -eq 'Windows_NT'
$ExecutableSuffix = if ($IsWindowsHost) { '.exe' } else { '' }
New-Item -ItemType Directory -Force -Path $BinDirectory | Out-Null

$services = @{
    edgeproxy = [pscustomobject]@{
        Key = 'edgeproxy'; Name = 'EdgeProxy'; App = Join-Path $Root 'apps/edgeproxy'; Package = './cmd/edgeproxy';
        Config = [IO.Path]::GetFullPath((Join-Path $Root $EdgeProxyConfig));
        Env = [IO.Path]::GetFullPath((Join-Path $Root $EdgeProxyEnv)); Process = $null; ActiveBinary = ''
    }
    securityedge = [pscustomobject]@{
        Key = 'securityedge'; Name = 'SecurityEdge'; App = Join-Path $Root 'apps/securityedge'; Package = './cmd/securityedge';
        Config = [IO.Path]::GetFullPath((Join-Path $Root $SecurityEdgeConfig));
        Env = [IO.Path]::GetFullPath((Join-Path $Root $SecurityEdgeEnv)); Process = $null; ActiveBinary = ''
    }
}

function Write-DevLog([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    $stamp = Get-Date -Format 'HH:mm:ss.fff'
    Write-Host "[$stamp] $Message" -ForegroundColor $Color
}

function Stop-ServiceProcess([object]$Service) {
    if ($null -eq $Service.Process) { return }
    if (-not $Service.Process.HasExited) {
        Write-DevLog "Stopping $($Service.Name) generation $($Service.Process.Id)..." DarkYellow
        if ($IsWindowsHost) {
            & taskkill.exe /PID $Service.Process.Id /T /F *> $null
        } else {
            Stop-Process -Id $Service.Process.Id -Force -ErrorAction SilentlyContinue
        }
        try { $Service.Process.WaitForExit(5000) | Out-Null } catch {}
    }
    $Service.Process.Dispose()
    $Service.Process = $null
}

function New-ServiceBinary([object]$Service) {
    $generation = '{0}-{1}-{2}{3}' -f $Service.Key, (Get-Date -Format 'yyyyMMddHHmmssfff'), ([Guid]::NewGuid().ToString('N').Substring(0,8)), $ExecutableSuffix
    $candidate = Join-Path $BinDirectory $generation
    Write-DevLog "Building $($Service.Name) candidate..." Cyan
    Push-Location $Service.App
    try {
        & go build -trimpath -o $candidate $Service.Package
        if ($LASTEXITCODE -ne 0) {
            Write-DevLog "$($Service.Name) build failed; the last healthy generation remains running." Red
            Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
            return $null
        }
    }
    finally { Pop-Location }
    return $candidate
}

function Start-ServiceGeneration([object]$Service, [string]$Binary) {
    $arguments = @('-config', $Service.Config)
    if (Test-Path -LiteralPath $Service.Env -PathType Leaf) { $arguments += @('-env', $Service.Env) }
    if ($PrettyLogs) { $arguments += '-pretty-logs' }
    $Service.Process = Start-Process -FilePath $Binary -ArgumentList $arguments -WorkingDirectory $Service.App -PassThru -NoNewWindow
    Start-Sleep -Milliseconds 750
    $Service.Process.Refresh()
    if ($Service.Process.HasExited) {
        $exitCode = $Service.Process.ExitCode
        $Service.Process.Dispose()
        $Service.Process = $null
        throw "$($Service.Name) candidate exited during startup verification with code $exitCode."
    }
    $Service.ActiveBinary = $Binary
    Write-DevLog "$($Service.Name) generation started with PID $($Service.Process.Id)." Green
}

function Remove-InactiveBinary([string]$Path, [string]$ActivePath) {
    if (-not [string]::IsNullOrWhiteSpace($Path) -and $Path -ne $ActivePath) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
}

function Rebuild-And-Restart([object]$Service) {
    $candidate = New-ServiceBinary $Service
    if ([string]::IsNullOrWhiteSpace($candidate)) { return }

    $previousBinary = $Service.ActiveBinary
    Stop-ServiceProcess $Service
    try {
        Start-ServiceGeneration $Service $candidate
        Remove-InactiveBinary $previousBinary $Service.ActiveBinary
    }
    catch {
        Write-DevLog "$($Service.Name) candidate failed to start: $($_.Exception.Message)" Red
        Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        $restored = $false
        if (-not [string]::IsNullOrWhiteSpace($previousBinary) -and (Test-Path -LiteralPath $previousBinary -PathType Leaf)) {
            Write-DevLog "Restoring the previous $($Service.Name) generation." DarkYellow
            try {
                Start-ServiceGeneration $Service $previousBinary
                $restored = $true
                Write-DevLog "Previous $($Service.Name) generation restored; watcher remains active." Green
            }
            catch {
                Write-DevLog "$($Service.Name) rollback failed: $($_.Exception.Message)" Red
            }
        }
        if (-not $restored) {
            Write-DevLog "$($Service.Name) has no healthy generation; the watcher will retry on the next poll." Red
        }
        return
    }
}

function Get-RepositorySnapshot {
    $snapshot = @{}
    Get-ChildItem -LiteralPath $Root -Recurse -File -Force | ForEach-Object {
        $relative = [IO.Path]::GetRelativePath($Root, $_.FullName).Replace('\\','/')
        if ($relative -match '(^|/)(\.git|\.dev|logs|node_modules|vendor)(/|$)' -or
            $relative -match '\.(log|tmp|bak|zip|exe)$' -or $relative -match '~$') { return }
        $snapshot[$relative] = "$($_.LastWriteTimeUtc.Ticks):$($_.Length)"
    }
    return $snapshot
}

function Compare-Snapshot([hashtable]$Before, [hashtable]$After) {
    $changed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($key in $Before.Keys) {
        if (-not $After.ContainsKey($key) -or $Before[$key] -ne $After[$key]) { $null = $changed.Add($key) }
    }
    foreach ($key in $After.Keys) {
        if (-not $Before.ContainsKey($key)) { $null = $changed.Add($key) }
    }
    return @($changed)
}

function Classify-Changes([string[]]$Paths) {
    $edge = $false; $security = $false; $runtimeOnly = @(); $informational = @()
    $edgeConfigRelative = [IO.Path]::GetRelativePath($Root, $services.edgeproxy.Config).Replace('\\','/')
    $edgeEnvRelative = [IO.Path]::GetRelativePath($Root, $services.edgeproxy.Env).Replace('\\','/')
    $securityConfigRelative = [IO.Path]::GetRelativePath($Root, $services.securityedge.Config).Replace('\\','/')
    $securityEnvRelative = [IO.Path]::GetRelativePath($Root, $services.securityedge.Env).Replace('\\','/')
    foreach ($path in $Paths) {
        if ($path -in @($edgeConfigRelative,$edgeEnvRelative,$securityConfigRelative,$securityEnvRelative)) {
            $runtimeOnly += $path
            continue
        }
        switch -Regex ($path) {
            '^apps/edgeproxy/' { $edge = $true; continue }
            '^apps/securityedge/' { $security = $true; continue }
            '^integration/.*\.json$' { $edge = $true; $security = $true; continue }
            '^(go\.work|go\.work\.sum|scripts/|deployments/)' { $edge = $true; $security = $true; continue }
            default { $informational += $path }
        }
    }
    return [pscustomobject]@{ Edge = $edge; Security = $security; RuntimeOnly = $runtimeOnly; Informational = $informational }
}

Write-DevLog 'Building initial development generations...' Cyan
foreach ($service in @($services.edgeproxy, $services.securityedge)) {
    $candidate = New-ServiceBinary $service
    if ([string]::IsNullOrWhiteSpace($candidate)) { throw "Initial $($service.Name) build failed." }
    Start-ServiceGeneration $service $candidate
}
Write-DevLog 'Repository watcher is active. Source and embedded-dashboard changes are rebuilt before replacement; active JSON/.env files use the applications’ transactional runtime watchers.' Green

$snapshot = Get-RepositorySnapshot
try {
    while ($true) {
        Start-Sleep -Milliseconds $PollMilliseconds
        $next = Get-RepositorySnapshot
        $changes = Compare-Snapshot $snapshot $next
        if ($changes.Count -eq 0) {
            foreach ($service in $services.Values) {
                if ($null -ne $service.Process -and $service.Process.HasExited) {
                    Write-DevLog "$($service.Name) exited unexpectedly with code $($service.Process.ExitCode); rebuilding and restarting." Red
                    Rebuild-And-Restart $service
                }
            }
            continue
        }

        Start-Sleep -Milliseconds $DebounceMilliseconds
        $settled = Get-RepositorySnapshot
        $changes = @(Compare-Snapshot $snapshot $settled | Sort-Object -Unique)
        $snapshot = $settled
        Write-DevLog ("Detected {0} changed file(s): {1}" -f $changes.Count, ($changes -join ', ')) DarkCyan
        $classification = Classify-Changes $changes
        if ($classification.RuntimeOnly.Count -gt 0) {
            Write-DevLog ("Transactional runtime watcher will apply: " + ($classification.RuntimeOnly -join ', ')) DarkGreen
        }
        if ($classification.Informational.Count -gt 0) {
            Write-DevLog ("No executable runtime impact: " + ($classification.Informational -join ', ')) DarkGray
        }
        if ($classification.Edge) { Rebuild-And-Restart $services.edgeproxy }
        if ($classification.Security) { Rebuild-And-Restart $services.securityedge }
    }
}
finally {
    Stop-ServiceProcess $services.securityedge
    Stop-ServiceProcess $services.edgeproxy
    foreach ($service in $services.Values) { Remove-InactiveBinary $service.ActiveBinary '' }
    Write-DevLog 'Development watcher stopped.' DarkYellow
}
