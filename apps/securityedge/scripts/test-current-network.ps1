param(
    [string]$Domain = "project.test",
    [string]$ProxyIP = "10.36.74.241",
    [string]$OriginIP = "10.36.74.43",
    [int]$OriginPort = 9000,
    [string]$AdminUrl = "http://127.0.0.1:9191",
    [string]$Token = $(if ($env:SECURITYEDGE_ADMIN_TOKEN) { $env:SECURITYEDGE_ADMIN_TOKEN } else { "SecurityEdgeDemo2026" })
)

$ErrorActionPreference = "Stop"

function Section([string]$Text) {
    Write-Host "`n=== $Text ===" -ForegroundColor Cyan
}

function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Invoke-Probe([string]$Url, [string[]]$ExtraArgs = @()) {
    $headerFile = [IO.Path]::GetTempFileName()
    $bodyFile = [IO.Path]::GetTempFileName()
    try {
        $status = & curl.exe -sS -D $headerFile -o $bodyFile -w "%{http_code}" @ExtraArgs $Url
        if ($LASTEXITCODE -ne 0) { throw "curl failed for $Url" }
        [pscustomobject]@{
            Status  = [int]$status
            Headers = Get-Content $headerFile -Raw
            Body    = Get-Content $bodyFile -Raw
        }
    }
    finally {
        Remove-Item $headerFile, $bodyFile -Force -ErrorAction SilentlyContinue
    }
}

Section "Technitium DNS resolution"
$addresses = @(Resolve-DnsName -Name $Domain -Server $ProxyIP -Type A -ErrorAction Stop |
    Where-Object Type -eq "A" |
    Select-Object -ExpandProperty IPAddress)
$addresses | ForEach-Object { Write-Host "$Domain -> $_" }
Assert ($addresses -contains $ProxyIP) "Technitium returns the Proxy IP $ProxyIP"

Section "Proxy-to-Origin access"
$origin = Test-NetConnection -ComputerName $OriginIP -Port $OriginPort -WarningAction SilentlyContinue
Assert $origin.TcpTestSucceeded "Proxy can reach Origin at ${OriginIP}:$OriginPort"

Section "Listener exposure"
& "$PSScriptRoot\check-listeners.ps1"

Section "EdgeProxy internal health"
$edgeHealth = Invoke-Probe "http://127.0.0.1:8080/healthz" @("-H", "Host: $Domain")
Assert ($edgeHealth.Status -eq 200) "EdgeProxy loopback health returns HTTP 200"

Section "Clean request and cache"
$nonce = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$url = "http://$Domain/verification?run=$nonce"
$first = Invoke-Probe $url
$second = Invoke-Probe $url
Assert ($first.Status -eq 200) "First clean request returns HTTP 200"
Assert ($first.Headers -match '(?im)^X-Security-Action:\s*ALLOW\s*$') "First request is allowed by SecurityEdge"
Assert ($first.Headers -match '(?im)^X-Cache:\s*MISS\s*$') "First request is an EdgeProxy cache MISS"
Assert ($second.Status -eq 200) "Second clean request returns HTTP 200"
Assert ($second.Headers -match '(?im)^X-Cache:\s*HIT\s*$') "Second request is an EdgeProxy cache HIT"
Assert (([regex]::Matches($second.Headers, '(?im)^X-Request-ID:')).Count -eq 1) "Response contains exactly one X-Request-ID"

Section "Representative WAF categories"
$attacks = @(
    @{ Name = "XSS"; Url = "http://$Domain/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" },
    @{ Name = "SQL injection"; Url = "http://$Domain/login?username=admin%27%20OR%201%3D1--" },
    @{ Name = "SSRF"; Url = "http://$Domain/fetch?url=http://169.254.169.254/latest/meta-data" },
    @{ Name = "Log4Shell/JNDI"; Url = "http://$Domain/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D" },
    @{ Name = "Path traversal"; Url = "http://$Domain/download?file=..%2F..%2Fetc%2Fpasswd" }
)
foreach ($attack in $attacks) {
    $response = Invoke-Probe $attack.Url
    Assert ($response.Status -eq 403) "$($attack.Name) is blocked with HTTP 403"
}

Section "Admin, version, metrics, and privacy"
$headers = @{ Authorization = "Bearer $Token" }
$info = Invoke-RestMethod "$AdminUrl/api/v1/info" -Headers $headers
Assert ($info.build.name -eq "SecurityEdge") "Admin API exposes build identity"
$status = Invoke-RestMethod "$AdminUrl/api/v1/status" -Headers $headers
Assert ($status.edgeproxy.reachable -eq $true) "Dashboard backend can reach EdgeProxy Admin API"
$metrics = Invoke-RestMethod "$AdminUrl/api/v1/metrics" -Headers $headers
Assert ($metrics.schema_version -eq "2.0") "Security metrics schema is 2.0"
$prometheus = Invoke-RestMethod "$AdminUrl/api/v1/metrics/prometheus" -Headers $headers
Assert ($prometheus -match 'securityedge_requests_total') "Prometheus exposition is available"
$logs = Invoke-RestMethod "$AdminUrl/api/v1/logs?limit=100" -Headers $headers | ConvertTo-Json -Depth 30
Assert ($logs -notmatch '<script>') "Raw XSS payload is absent from SecurityEdge logs"
Assert ($logs -notmatch '169\.254\.169\.254') "Raw SSRF target is absent from SecurityEdge logs"

Write-Host "`nAll proxy-side verification assertions passed." -ForegroundColor Green
Write-Host "Phone check still required: project.test must work; Proxy ports 8080/9090/9191 and Origin:9000 must fail directly." -ForegroundColor Yellow
