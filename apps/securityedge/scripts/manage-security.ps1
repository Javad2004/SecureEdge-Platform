[CmdletBinding()]
param(
    [ValidateSet('Status','Metrics','Watch','GetConfig','SetConfig','Reload','Policies','SetDefaultPolicy','SetRoutePolicy','DeleteRoutePolicy','Bans','DeleteBan','ClearBans','Logs')]
    [string]$Action = 'Status',
    [string]$BaseUrl = '',
    [string]$Token = '',
    [string]$EnvFile = '',
    [string]$Route = '',
    [string]$Client = '',
    [string]$BodyFile = '',
    [string]$BodyJson = '',
    [ValidateRange(1, 100000)]
    [int]$Limit = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
. (Join-Path $PSScriptRoot 'dotenv.ps1')

$defaultEnv = Join-Path $PSScriptRoot '..\.env'
$null = Import-ApplicationDotEnv -ExplicitPath $EnvFile -Candidates @($defaultEnv)

function Get-RequestBody {
    if (-not [string]::IsNullOrWhiteSpace($BodyJson)) { $json = $BodyJson }
    elseif (-not [string]::IsNullOrWhiteSpace($BodyFile)) {
        if (-not (Test-Path -LiteralPath $BodyFile -PathType Leaf)) { throw "Body file not found: $BodyFile" }
        $json = Get-Content -LiteralPath $BodyFile -Raw
    }
    else { throw 'This action requires -BodyFile or -BodyJson.' }
    try { $null = $json | ConvertFrom-Json } catch { throw "Request body is not valid JSON: $($_.Exception.Message)" }
    return $json
}
function Require-Value([string]$Value, [string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$Name is required for action $Action." }
}

if ([string]::IsNullOrWhiteSpace($Token)) { $Token = Get-NonEmptyEnvironmentValue -Name 'SECURITYEDGE_ADMIN_TOKEN' }
if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
    $listen = Get-NonEmptyEnvironmentValue -Name 'SECURITYEDGE_ADMIN_LISTEN_ADDR'
    if (-not $listen) { $listen = '127.0.0.1:9191' }
    $BaseUrl = (Get-LocalHttpUrlFromListenAddress -ListenAddress $listen) + '/api/v1'
}
$BaseUrl = $BaseUrl.TrimEnd('/')

$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.UseProxy = $false
$http = [System.Net.Http.HttpClient]::new($handler)
$http.Timeout = [TimeSpan]::FromSeconds(30)
if (-not [string]::IsNullOrWhiteSpace($Token)) {
    $http.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Token)
}

function Invoke-ControlRequest([string]$Method, [string]$Path, [string]$Json = '') {
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), "$BaseUrl$Path")
    if (-not [string]::IsNullOrWhiteSpace($Json)) {
        $request.Content = [System.Net.Http.StringContent]::new($Json, [Text.Encoding]::UTF8, 'application/json')
    }
    try {
        $response = $http.SendAsync($request).GetAwaiter().GetResult()
        try {
            $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if (-not $response.IsSuccessStatusCode) {
                $detail = $content
                try { $detail = (($content | ConvertFrom-Json).error.message) } catch {}
                throw "HTTP $([int]$response.StatusCode) $($response.ReasonPhrase): $detail"
            }
            if ([string]::IsNullOrWhiteSpace($content)) { return [pscustomobject]@{ status = [int]$response.StatusCode } }
            try { return $content | ConvertFrom-Json } catch { throw "Control API returned invalid JSON: $content" }
        }
        finally { $response.Dispose() }
    }
    finally { $request.Dispose() }
}

try {
    switch ($Action) {
        'Status'            { $result = Invoke-ControlRequest GET '/status' }
        'Metrics'           { $result = Invoke-ControlRequest GET '/metrics' }
        'Watch'             { $result = Invoke-ControlRequest GET '/config/watch' }
        'GetConfig'         { $result = Invoke-ControlRequest GET '/config' }
        'SetConfig'         { $result = Invoke-ControlRequest PUT '/config' (Get-RequestBody) }
        'Reload'            { $result = Invoke-ControlRequest POST '/reload' }
        'Policies'          { $result = Invoke-ControlRequest GET '/policies' }
        'SetDefaultPolicy'  { $result = Invoke-ControlRequest PUT '/policies/default' (Get-RequestBody) }
        'SetRoutePolicy'    { Require-Value $Route 'Route'; $result = Invoke-ControlRequest PUT ('/policies/' + [Uri]::EscapeDataString($Route)) (Get-RequestBody) }
        'DeleteRoutePolicy' { Require-Value $Route 'Route'; $result = Invoke-ControlRequest DELETE ('/policies/' + [Uri]::EscapeDataString($Route)) }
        'Bans'              { $result = Invoke-ControlRequest GET '/bans' }
        'DeleteBan'         { Require-Value $Client 'Client'; $result = Invoke-ControlRequest DELETE ('/bans/' + [Uri]::EscapeDataString($Client)) }
        'ClearBans'         { $result = Invoke-ControlRequest DELETE '/bans' }
        'Logs'              { $result = Invoke-ControlRequest GET (('/logs?limit={0}' -f $Limit)) }
    }
    $result | ConvertTo-Json -Depth 100
}
finally {
    $http.Dispose()
    $handler.Dispose()
}
