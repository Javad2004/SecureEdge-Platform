[CmdletBinding()]
param(
    [ValidateSet(
        'Status','Metrics','Telemetry','Watch','GetConfig','SetConfig','Reload',
        'GetServer','SetServer','GetAdmin','SetAdmin',
        'ListRoutes','GetRoute','CreateRoute','UpdateRoute','DeleteRoute','GetRouteSettings','RouteTelemetry',
        'ListOrigins','GetOrigin','CreateOrigin','UpdateOrigin','DeleteOrigin','OriginTelemetry',
        'GetRouteCache','SetRouteCache','EnableCache','DisableCache','SetCacheTTL','PurgeRouteCache',
        'GetLoadBalancing','SetLoadBalancing','GetRouteProxy','SetRouteProxy','GetHealthCheck','SetHealthCheck'
    )]
    [string]$Action = 'Status',
    [string]$BaseUrl = '',
    [string]$Token = '',
    [string]$EnvFile = '',
    [string]$Route = '',
    [string]$Origin = '',
    [string]$BodyFile = '',
    [string]$BodyJson = '',
    [string]$Algorithm = '',
    [Nullable[double]]$LatencySensitivity = $null,
    [Nullable[double]]$EWMAAlpha = $null,
    [string]$DefaultTTL = '',
    [string]$StaleIfError = '',
    [string]$Host = '',
    [string]$PathPrefix = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
. (Join-Path $PSScriptRoot 'dotenv.ps1')

$defaultEnv = Join-Path $PSScriptRoot '..\.env'
$null = Import-ApplicationDotEnv -ExplicitPath $EnvFile -Candidates @($defaultEnv)

function Get-RequestBody {
    if (-not [string]::IsNullOrWhiteSpace($BodyJson)) {
        try { $null = $BodyJson | ConvertFrom-Json } catch { throw "BodyJson is not valid JSON: $($_.Exception.Message)" }
        return $BodyJson
    }
    if ([string]::IsNullOrWhiteSpace($BodyFile)) { throw 'This action requires -BodyFile or -BodyJson.' }
    if (-not (Test-Path -LiteralPath $BodyFile -PathType Leaf)) { throw "Body file not found: $BodyFile" }
    $json = Get-Content -LiteralPath $BodyFile -Raw
    try { $null = $json | ConvertFrom-Json } catch { throw "BodyFile is not valid JSON: $($_.Exception.Message)" }
    return $json
}

function Has-RequestBody {
    return -not [string]::IsNullOrWhiteSpace($BodyJson) -or -not [string]::IsNullOrWhiteSpace($BodyFile)
}

function Require-Value([string]$Value, [string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$Name is required for action $Action." }
}

function ConvertTo-ControlJson([object]$Value) {
    return $Value | ConvertTo-Json -Depth 100 -Compress
}

function Add-QueryValue([System.Collections.Generic.List[string]]$Parts, [string]$Name, [string]$Value) {
    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        $Parts.Add(([Uri]::EscapeDataString($Name) + '=' + [Uri]::EscapeDataString($Value)))
    }
}

if ([string]::IsNullOrWhiteSpace($Token)) { $Token = Get-NonEmptyEnvironmentValue -Name 'SECURITYEDGE_ADMIN_TOKEN' }
if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
    $listen = Get-NonEmptyEnvironmentValue -Name 'SECURITYEDGE_ADMIN_LISTEN_ADDR'
    if (-not $listen) { $listen = '127.0.0.1:9191' }
    $BaseUrl = (Get-LocalHttpUrlFromListenAddress -ListenAddress $listen) + '/api/v1/edgeproxy'
}
$BaseUrl = $BaseUrl.TrimEnd('/')

$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.UseProxy = $false
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(30)
if (-not [string]::IsNullOrWhiteSpace($Token)) {
    $client.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Token)
}

function Invoke-ControlRequest {
    param([string]$Method, [string]$Path, [string]$Json = '')
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), "$BaseUrl$Path")
    if (-not [string]::IsNullOrWhiteSpace($Json)) {
        $request.Content = [System.Net.Http.StringContent]::new($Json, [Text.Encoding]::UTF8, 'application/json')
    }
    try {
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if (-not $response.IsSuccessStatusCode) {
                $detail = $content
                try { $detail = (($content | ConvertFrom-Json).error.message) } catch {}
                throw "HTTP $([int]$response.StatusCode) $($response.ReasonPhrase): $detail"
            }
            if ([string]::IsNullOrWhiteSpace($content)) {
                return [pscustomobject]@{ status = [int]$response.StatusCode }
            }
            try { return $content | ConvertFrom-Json } catch { throw "Control API returned invalid JSON: $content" }
        }
        finally { $response.Dispose() }
    }
    finally { $request.Dispose() }
}

try {
    $routePath = if ($Route) { '/routes/' + [Uri]::EscapeDataString($Route) } else { '' }
    $originPath = if ($Origin) { $routePath + '/origins/' + [Uri]::EscapeDataString($Origin) } else { '' }
    switch ($Action) {
        'Status'             { $result = Invoke-ControlRequest GET '/status' }
        'Metrics'            { $result = Invoke-ControlRequest GET '/metrics' }
        'Telemetry'          { $result = Invoke-ControlRequest GET '/telemetry' }
        'Watch'              { $result = Invoke-ControlRequest GET '/config/watch' }
        'GetConfig'          { $result = Invoke-ControlRequest GET '/config' }
        'SetConfig'          { $result = Invoke-ControlRequest PUT '/config' (Get-RequestBody) }
        'Reload'             { $result = Invoke-ControlRequest POST '/config/reload' }
        'GetServer'          { $result = Invoke-ControlRequest GET '/server' }
        'SetServer'          { $result = Invoke-ControlRequest PUT '/server' (Get-RequestBody) }
        'GetAdmin'           { $result = Invoke-ControlRequest GET '/admin' }
        'SetAdmin'           { $result = Invoke-ControlRequest PUT '/admin' (Get-RequestBody) }
        'ListRoutes'         { $result = Invoke-ControlRequest GET '/routes' }
        'GetRoute'           { Require-Value $Route 'Route'; $result = Invoke-ControlRequest GET $routePath }
        'CreateRoute'        { $result = Invoke-ControlRequest POST '/routes' (Get-RequestBody) }
        'UpdateRoute'        { Require-Value $Route 'Route'; $result = Invoke-ControlRequest PUT $routePath (Get-RequestBody) }
        'DeleteRoute'        { Require-Value $Route 'Route'; $result = Invoke-ControlRequest DELETE $routePath }
        'GetRouteSettings'   {
            Require-Value $Route 'Route'
            $result = [pscustomobject]@{
                route = Invoke-ControlRequest GET $routePath
                load_balancing = Invoke-ControlRequest GET ($routePath + '/load-balancing')
                proxy = Invoke-ControlRequest GET ($routePath + '/proxy')
                cache = Invoke-ControlRequest GET ($routePath + '/cache')
                health_check = Invoke-ControlRequest GET ($routePath + '/health-check')
            }
        }
        'RouteTelemetry'     { Require-Value $Route 'Route'; $result = Invoke-ControlRequest GET ($routePath + '/telemetry') }
        'ListOrigins'        { Require-Value $Route 'Route'; $result = Invoke-ControlRequest GET ($routePath + '/origins') }
        'GetOrigin'          { Require-Value $Route 'Route'; Require-Value $Origin 'Origin'; $result = Invoke-ControlRequest GET $originPath }
        'CreateOrigin'       { Require-Value $Route 'Route'; $result = Invoke-ControlRequest POST ($routePath + '/origins') (Get-RequestBody) }
        'UpdateOrigin'       { Require-Value $Route 'Route'; Require-Value $Origin 'Origin'; $result = Invoke-ControlRequest PUT $originPath (Get-RequestBody) }
        'DeleteOrigin'       { Require-Value $Route 'Route'; Require-Value $Origin 'Origin'; $result = Invoke-ControlRequest DELETE $originPath }
        'OriginTelemetry'    { Require-Value $Route 'Route'; Require-Value $Origin 'Origin'; $result = Invoke-ControlRequest GET ($originPath + '/telemetry') }
        'GetRouteCache'      { Require-Value $Route 'Route'; $result = Invoke-ControlRequest GET ($routePath + '/cache') }
        'SetRouteCache'      { Require-Value $Route 'Route'; $result = Invoke-ControlRequest PUT ($routePath + '/cache') (Get-RequestBody) }
        'EnableCache'        {
            Require-Value $Route 'Route'
            $cache = Invoke-ControlRequest GET ($routePath + '/cache')
            $cache.enabled = $true
            $result = Invoke-ControlRequest PUT ($routePath + '/cache') (ConvertTo-ControlJson $cache)
        }
        'DisableCache'       {
            Require-Value $Route 'Route'
            $cache = Invoke-ControlRequest GET ($routePath + '/cache')
            $cache.enabled = $false
            $result = Invoke-ControlRequest PUT ($routePath + '/cache') (ConvertTo-ControlJson $cache)
        }
        'SetCacheTTL'        {
            Require-Value $Route 'Route'; Require-Value $DefaultTTL 'DefaultTTL'
            $cache = Invoke-ControlRequest GET ($routePath + '/cache')
            $cache.default_ttl = $DefaultTTL
            if (-not [string]::IsNullOrWhiteSpace($StaleIfError)) { $cache.stale_if_error = $StaleIfError }
            $result = Invoke-ControlRequest PUT ($routePath + '/cache') (ConvertTo-ControlJson $cache)
        }
        'PurgeRouteCache'    {
            Require-Value $Route 'Route'
            $parts = [System.Collections.Generic.List[string]]::new()
            Add-QueryValue $parts 'host' $Host
            Add-QueryValue $parts 'path_prefix' $PathPrefix
            $query = if ($parts.Count -gt 0) { '?' + ($parts -join '&') } else { '' }
            $result = Invoke-ControlRequest POST ($routePath + '/cache/purge' + $query)
        }
        'GetLoadBalancing'   { Require-Value $Route 'Route'; $result = Invoke-ControlRequest GET ($routePath + '/load-balancing') }
        'SetLoadBalancing'   {
            Require-Value $Route 'Route'
            if (Has-RequestBody) {
                $body = Get-RequestBody
            } else {
                Require-Value $Algorithm 'Algorithm'
                $settings = Invoke-ControlRequest GET ($routePath + '/load-balancing')
                $settings.algorithm = $Algorithm
                if ($null -ne $LatencySensitivity) { $settings.latency_sensitivity = [double]$LatencySensitivity }
                if ($null -ne $EWMAAlpha) { $settings.ewma_alpha = [double]$EWMAAlpha }
                $body = ConvertTo-ControlJson $settings
            }
            $result = Invoke-ControlRequest PUT ($routePath + '/load-balancing') $body
        }
        'GetRouteProxy'      { Require-Value $Route 'Route'; $result = Invoke-ControlRequest GET ($routePath + '/proxy') }
        'SetRouteProxy'      { Require-Value $Route 'Route'; $result = Invoke-ControlRequest PUT ($routePath + '/proxy') (Get-RequestBody) }
        'GetHealthCheck'     { Require-Value $Route 'Route'; $result = Invoke-ControlRequest GET ($routePath + '/health-check') }
        'SetHealthCheck'     { Require-Value $Route 'Route'; $result = Invoke-ControlRequest PUT ($routePath + '/health-check') (Get-RequestBody) }
    }
    $result | ConvertTo-Json -Depth 100
}
finally {
    $client.Dispose()
    $handler.Dispose()
}
