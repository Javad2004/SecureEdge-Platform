param(
    [string]$Listen = "0.0.0.0:9000",
    [string]$Name = "origin-a"
)

$ErrorActionPreference = "Stop"
go run ./cmd/origin-demo -listen $Listen -name $Name
