param(
    [string]$Config = "configs/edgeproxy.json",
    [string]$AdminToken = ""
)

$ErrorActionPreference = "Stop"
if ($AdminToken -ne "") {
    $env:EDGEPROXY_ADMIN_TOKEN = $AdminToken
}

go run ./cmd/edgeproxy -config $Config -validate
go run ./cmd/edgeproxy -config $Config -pretty-logs
