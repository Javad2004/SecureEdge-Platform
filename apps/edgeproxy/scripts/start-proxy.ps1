param(
    [string]$Config = "configs/edgeproxy.json",
    [string]$AdminToken = ""
)

$ErrorActionPreference = "Stop"
if ($AdminToken -ne "") {
    $env:EDGEPROXY_ADMIN_TOKEN = $AdminToken
}

go run ./cmd/edgeproxy -config $Config -validate
if ($LASTEXITCODE -ne 0) { throw "Configuration validation failed." }

go run ./cmd/edgeproxy -config $Config -pretty-logs
if ($LASTEXITCODE -ne 0) { throw "EdgeProxy exited with code $LASTEXITCODE." }
