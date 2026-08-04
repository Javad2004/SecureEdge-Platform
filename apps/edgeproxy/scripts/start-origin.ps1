param(
    [string]$Listen = "",
    [string]$Name = "",
    [string]$EnvFile = "",
    [switch]$NoEnv
)

$ErrorActionPreference = "Stop"

$commandArgs = @("run", "./cmd/origin-demo")
if ($Listen -ne "") { $commandArgs += @("-listen", $Listen) }
if ($Name -ne "") { $commandArgs += @("-name", $Name) }
if ($EnvFile -ne "") { $commandArgs += @("-env", $EnvFile) }
if ($NoEnv) { $commandArgs += "-no-env" }

go @commandArgs
if ($LASTEXITCODE -ne 0) { throw "Origin demo exited with code $LASTEXITCODE." }
