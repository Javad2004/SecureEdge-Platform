param(
    [string]$Listen = "127.0.0.1:9000",
    [string]$Name = "origin-local"
)

$ErrorActionPreference = "Stop"
go run ./cmd/origin-demo -listen $Listen -name $Name
