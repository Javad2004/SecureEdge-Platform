param(
    [string]$Config = "configs/edgeproxy.json"
)

$ErrorActionPreference = "Stop"
go run ./cmd/edgeproxy -config $Config -pretty-logs
