param(
    [string]$AdminUrl = "http://127.0.0.1:9191",
    [string]$Token = $(if ($env:SECURITYEDGE_ADMIN_TOKEN) { $env:SECURITYEDGE_ADMIN_TOKEN } else { "SecurityEdgeDemo2026" }),
    [ValidateSet("", "healthy", "degraded", "down")]
    [string]$ExpectedOverall = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$headers = @{ Authorization = "Bearer $Token" }
$method = if ($Force) { "Post" } else { "Get" }
$path = if ($Force) { "/api/v1/connectivity/check" } else { "/api/v1/connectivity" }
$result = Invoke-RestMethod "$AdminUrl$path" -Headers $headers -Method $method

Write-Host "Overall:       $($result.overall_status)" -ForegroundColor Cyan
Write-Host "Traffic path:  $($result.traffic_path_status)"
Write-Host "EdgeProxy:     $($result.edgeproxy_connection_status)"
Write-Host "Observability: $($result.observability_status)"
Write-Host "Checked:       $($result.generated_at)"
Write-Host "Summary:       $($result.summary)"

$result.components |
    Select-Object name, status, latency_ms, http_status, consecutive_failures, last_success_at, last_failure_at, endpoint |
    Format-Table -AutoSize

Write-Host "Routes: $($result.counts.ready_routes)/$($result.counts.total_routes) ready" -ForegroundColor Cyan
Write-Host "Origins: $($result.counts.healthy_origins)/$($result.counts.total_origins) healthy" -ForegroundColor Cyan

if ($ExpectedOverall -and $result.overall_status -ne $ExpectedOverall) {
    throw "Expected overall status '$ExpectedOverall', got '$($result.overall_status)'."
}

$result
