# Load-Balancing and Failover

This example demonstrates EdgeProxy Origin management and per-Route scheduling **through the complete SecurityEdge Platform**. Unlike the other examples, it intentionally changes EdgeProxy configuration through the Control Plane.

To keep the repository pristine, run this scenario against a **disposable copy** of the local EdgeProxy profile.

## 1. Prepare a disposable profile

From the repository root in PowerShell:

```powershell
$DemoDir = Join-Path $env:TEMP "secureedge-lb-demo"
$EdgeConfig = Join-Path $DemoDir "edgeproxy.json"
New-Item -ItemType Directory -Force $DemoDir | Out-Null
Copy-Item ./integration/edgeproxy-local-behind-waf.json $EdgeConfig -Force
Write-Host "Disposable EdgeProxy config: $EdgeConfig"
```

Do not use the checked-in `integration/edgeproxy-local-behind-waf.json` directly for this scenario; Control Plane mutations are persisted atomically to the selected file.

## 2. Start two Origins

Terminal 1:

```powershell
go run ./apps/edgeproxy/cmd/origin-demo `
  -no-env `
  -listen 127.0.0.1:9000 `
  -name origin-1
```

Terminal 2:

```powershell
go run ./apps/edgeproxy/cmd/origin-demo `
  -no-env `
  -listen 127.0.0.1:9001 `
  -name origin-2
```

## 3. Start EdgeProxy with the disposable profile

In a new PowerShell terminal:

```powershell
$EdgeConfig = Join-Path $env:TEMP "secureedge-lb-demo\edgeproxy.json"
go run ./apps/edgeproxy/cmd/edgeproxy `
  -no-env `
  -config $EdgeConfig `
  -pretty-logs
```

## 4. Start SecurityEdge against the same Route table

In another PowerShell terminal:

```powershell
$EdgeConfig = Join-Path $env:TEMP "secureedge-lb-demo\edgeproxy.json"
$env:SECURITYEDGE_EDGEPROXY_CONFIG_PATH = $EdgeConfig

go run ./apps/securityedge/cmd/securityedge `
  -no-env `
  -config ./apps/securityedge/configs/local-dev.json `
  -pretty-logs
```

`SECURITYEDGE_EDGEPROXY_CONFIG_PATH` overrides only the shared EdgeProxy Route-table path for this process. The local SecurityEdge JSON remains unchanged.

## 5. Run the HTTP collection

Open [`requests.http`](./requests.http) and execute the setup requests in order:

1. List the current Origins.
2. Add `origin-2` at `127.0.0.1:9001`.
3. Set `round_robin`.
4. Before sampling traffic, inspect `/api/v1/edgeproxy/status` and wait until both Origins report healthy. Then send several `/api/time` requests. Because that Origin endpoint uses `Cache-Control: no-store`, every request reaches the scheduler. The JSON `origin` field should alternate between `origin-1` and `origin-2`.
5. Set `priority_failover`. With both Origins healthy, requests should select `origin-1` because priority `1` is preferred over priority `2`.
6. Stop the `origin-1` process, wait for at least one health-check interval (the local profile uses `5s`), then repeat `/api/time`. Traffic should fail over to `origin-2`.
7. Restart `origin-1`, wait for it to become healthy, and verify that priority failover returns traffic to `origin-1`.

The collection also contains optional cleanup requests that restore `round_robin` and remove `origin-2` from the disposable profile.

### PowerShell / curl.exe equivalent

If you are not using an `.http` client, the same Control Plane workflow can be run from PowerShell. Keep the disposable-profile stack from steps 1-4 running while executing these commands.

```powershell
$Admin = "http://127.0.0.1:9191"
$Gateway = "http://127.0.0.1:8081"
$Route = "demo-app"
$Headers = @{ Authorization = "Bearer dev-security-token" }

# Inspect the initial Origin set.
Invoke-RestMethod `
  -Method Get `
  -Headers $Headers `
  -Uri "$Admin/api/v1/edgeproxy/routes/$Route/origins" |
  ConvertTo-Json -Depth 8

# Add origin-2 to the disposable EdgeProxy profile.
$Origin2 = @{
  url = "http://127.0.0.1:9001"
  insecure_skip_verify = $false
  name = "origin-2"
  weight = 1
  priority = 2
} | ConvertTo-Json -Compress

Invoke-RestMethod `
  -Method Post `
  -Headers $Headers `
  -ContentType "application/json" `
  -Body $Origin2 `
  -Uri "$Admin/api/v1/edgeproxy/routes/$Route/origins"

# Select round robin.
$RoundRobin = @{
  algorithm = "round_robin"
  latency_sensitivity = 1
  ewma_alpha = 0.25
} | ConvertTo-Json -Compress

Invoke-RestMethod `
  -Method Put `
  -Headers $Headers `
  -ContentType "application/json" `
  -Body $RoundRobin `
  -Uri "$Admin/api/v1/edgeproxy/routes/$Route/load-balancing"

# Readiness gate: re-run this until both Origins report healthy.
Invoke-RestMethod `
  -Method Get `
  -Headers $Headers `
  -Uri "$Admin/api/v1/edgeproxy/status" |
  ConvertTo-Json -Depth 12

# Once both Origins are healthy, the JSON origin field should alternate.
1..4 | ForEach-Object {
  curl.exe -sS "$Gateway/api/time"
  Write-Host ""
}

# Select priority failover.
$PriorityFailover = @{
  algorithm = "priority_failover"
  latency_sensitivity = 1
  ewma_alpha = 0.25
} | ConvertTo-Json -Compress

Invoke-RestMethod `
  -Method Put `
  -Headers $Headers `
  -ContentType "application/json" `
  -Body $PriorityFailover `
  -Uri "$Admin/api/v1/edgeproxy/routes/$Route/load-balancing"

# With both Origins healthy, this should report origin-1.
curl.exe -sS "$Gateway/api/time"

# Stop origin-1, wait at least one 5-second health-check interval, then retry.
# The response should report origin-2.
curl.exe -sS "$Gateway/api/time"

# Inspect scheduler and Origin readiness.
Invoke-RestMethod `
  -Method Get `
  -Headers $Headers `
  -Uri "$Admin/api/v1/edgeproxy/status" |
  ConvertTo-Json -Depth 12

# Restart origin-1, wait for health recovery, and verify traffic returns to it.
curl.exe -sS "$Gateway/api/time"

# Optional cleanup inside the disposable profile.
Invoke-RestMethod `
  -Method Put `
  -Headers $Headers `
  -ContentType "application/json" `
  -Body $RoundRobin `
  -Uri "$Admin/api/v1/edgeproxy/routes/$Route/load-balancing"

Invoke-RestMethod `
  -Method Delete `
  -Headers $Headers `
  -Uri "$Admin/api/v1/edgeproxy/routes/$Route/origins/origin-2"
```

The comments that say to stop or restart `origin-1` are manual checkpoints: perform that action in the terminal running the `origin-1` process, then wait for health detection before sending the next request.

## 6. Clean up

Stop the four processes. Then remove the temporary profile:

```powershell
Remove-Item Env:SECURITYEDGE_EDGEPROXY_CONFIG_PATH -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $env:TEMP "secureedge-lb-demo")
```

The checked-in repository files are never modified by this workflow.
