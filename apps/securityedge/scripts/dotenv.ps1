# Shared by the application PowerShell operational scripts.
# Parses dotenv without Invoke-Expression, validates the complete file before
# changing the process environment, and never overwrites existing variables.

function ConvertFrom-DotEnvValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RawValue,
        [Parameter(Mandatory = $true)]
        [int]$LineNumber
    )

    if ($RawValue.Length -eq 0) { return "" }

    if ($RawValue[0] -eq "'") {
        $end = $RawValue.IndexOf("'", 1)
        if ($end -lt 0) { throw "Dotenv line $LineNumber has an unterminated single-quoted value." }
        $trailing = $RawValue.Substring($end + 1).Trim()
        if ($trailing -and -not $trailing.StartsWith("#")) {
            throw "Dotenv line $LineNumber has unexpected characters after a quoted value."
        }
        return $RawValue.Substring(1, $end - 1)
    }

    if ($RawValue[0] -eq '"') {
        $escaped = $false
        $end = -1
        for ($i = 1; $i -lt $RawValue.Length; $i++) {
            $character = $RawValue[$i]
            if ($escaped) {
                $escaped = $false
                continue
            }
            if ($character -eq [char]92) {
                $escaped = $true
                continue
            }
            if ($character -eq '"') {
                $end = $i
                break
            }
        }
        if ($end -lt 0) { throw "Dotenv line $LineNumber has an unterminated double-quoted value." }
        $trailing = $RawValue.Substring($end + 1).Trim()
        if ($trailing -and -not $trailing.StartsWith("#")) {
            throw "Dotenv line $LineNumber has unexpected characters after a quoted value."
        }
        try {
            return ($RawValue.Substring(0, $end + 1) | ConvertFrom-Json)
        }
        catch {
            throw "Dotenv line $LineNumber contains an invalid double-quoted value: $($_.Exception.Message)"
        }
    }

    for ($i = 1; $i -lt $RawValue.Length; $i++) {
        if ($RawValue[$i] -eq '#' -and [char]::IsWhiteSpace($RawValue[$i - 1])) {
            return $RawValue.Substring(0, $i).Trim()
        }
    }
    return $RawValue.Trim()
}

function Import-ApplicationDotEnv {
    [CmdletBinding()]
    param(
        [string]$ExplicitPath = "",
        [string[]]$Candidates = @()
    )

    $selectedPath = $null
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            throw "Environment file not found: $ExplicitPath"
        }
        $selectedPath = (Resolve-Path -LiteralPath $ExplicitPath).Path
    }
    else {
        foreach ($candidate in $Candidates) {
            if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                $selectedPath = (Resolve-Path -LiteralPath $candidate).Path
                break
            }
        }
    }

    if (-not $selectedPath) { return $null }

    $fileInfo = Get-Item -LiteralPath $selectedPath
    if ($fileInfo.Length -gt 1MB) { throw "Environment file exceeds the 1 MiB safety limit: $selectedPath" }

    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    try {
        $content = [IO.File]::ReadAllText($selectedPath, $utf8)
    }
    catch {
        throw "Unable to read UTF-8 environment file '$selectedPath': $($_.Exception.Message)"
    }

    $values = [ordered]@{}
    $lines = [regex]::Split($content, "\r\n|\n|\r")
    for ($lineIndex = 0; $lineIndex -lt $lines.Count; $lineIndex++) {
        $lineNumber = $lineIndex + 1
        $line = $lines[$lineIndex]
        if ($lineIndex -eq 0) { $line = $line.TrimStart([char]0xFEFF) }
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith("#")) { continue }
        if ($line.StartsWith("export ")) { $line = $line.Substring(7).Trim() }

        $separator = $line.IndexOf('=')
        if ($separator -lt 0) { throw "Dotenv line $lineNumber must use KEY=VALUE syntax." }
        $key = $line.Substring(0, $separator).Trim()
        if ($key -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
            throw "Dotenv line $lineNumber contains an invalid variable name '$key'."
        }
        $rawValue = $line.Substring($separator + 1).Trim()
        $value = ConvertFrom-DotEnvValue -RawValue $rawValue -LineNumber $lineNumber
        if ($value.IndexOf([char]0) -ge 0) { throw "Dotenv line $lineNumber contains a NUL byte." }
        $values[$key] = $value
    }

    foreach ($entry in $values.GetEnumerator()) {
        if ($null -eq (Get-Item -LiteralPath "Env:$($entry.Key)" -ErrorAction SilentlyContinue)) {
            [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, "Process")
        }
    }
    return $selectedPath
}

function Get-NonEmptyEnvironmentValue {
    param([Parameter(Mandatory = $true)][string]$Name)
    $value = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }
    return $value.Trim()
}


function Get-PortFromEndpoint {
    param([Parameter(Mandatory = $true)][string]$Endpoint)
    if ($Endpoint -notmatch ':(\d+)$') { throw "Endpoint does not contain a numeric port: $Endpoint" }
    return [int]$Matches[1]
}

function Get-LocalHttpUrlFromListenAddress {
    param([Parameter(Mandatory = $true)][string]$ListenAddress)
    return "http://127.0.0.1:$(Get-PortFromEndpoint -Endpoint $ListenAddress)"
}

function Resolve-EffectiveConfigPath {
    param(
        [string]$ExplicitValue = "",
        [Parameter(Mandatory = $true)][string]$EnvironmentVariable,
        [bool]$EnvironmentWasPreexisting = $false,
        [string]$LoadedEnvPath = "",
        [string[]]$Candidates = @()
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitValue)) { return $ExplicitValue.Trim() }
    $environmentValue = Get-NonEmptyEnvironmentValue -Name $EnvironmentVariable
    if ($environmentValue) {
        if (-not $EnvironmentWasPreexisting -and $LoadedEnvPath -and -not [IO.Path]::IsPathRooted($environmentValue)) {
            return [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $LoadedEnvPath) $environmentValue))
        }
        return $environmentValue
    }
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $candidate }
    }
    if ($Candidates.Count -gt 0) { return $Candidates[0] }
    return ""
}

function Get-EnvironmentList {
    param([Parameter(Mandatory = $true)][string]$Name)
    $value = Get-NonEmptyEnvironmentValue -Name $Name
    if (-not $value) { return $null }
    return @($value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-EnvironmentBoolean {
    param([Parameter(Mandatory = $true)][string]$Name)
    $value = Get-NonEmptyEnvironmentValue -Name $Name
    if (-not $value) { return $null }
    $parsed = $false
    if (-not [bool]::TryParse($value, [ref]$parsed)) { throw "$Name must be true or false." }
    return $parsed
}

function Apply-SecurityEdgeEnvironmentOverrides {
    param([Parameter(Mandatory = $true)]$ConfigObject)

    $value = Get-NonEmptyEnvironmentValue SECURITYEDGE_SERVER_LISTEN_ADDR
    if ($value) { $ConfigObject.server.listen_addr = $value }
    $value = Get-NonEmptyEnvironmentValue SECURITYEDGE_UPSTREAM_PROXY_URL
    if ($value) { $ConfigObject.server.upstream_proxy_url = $value }
    $value = Get-NonEmptyEnvironmentValue SECURITYEDGE_FORWARDED_FOR_HEADER
    if ($value) { $ConfigObject.server.forwarded_for_header = $value }
    $value = Get-NonEmptyEnvironmentValue SECURITYEDGE_ADMIN_LISTEN_ADDR
    if ($value) { $ConfigObject.admin.listen_addr = $value }
    $value = Get-NonEmptyEnvironmentValue SECURITYEDGE_ADMIN_TOKEN
    if ($value) { $ConfigObject.admin.auth_token = $value }
    $value = Get-NonEmptyEnvironmentValue SECURITYEDGE_LOG_FILE_PATH
    if ($value) { $ConfigObject.admin.log_store.file_path = $value }
    $value = Get-NonEmptyEnvironmentValue SECURITYEDGE_DNS_SERVER
    if ($value) { $ConfigObject.admin.connectivity.dns.server = $value }
    $value = Get-NonEmptyEnvironmentValue SECURITYEDGE_EDGEPROXY_CONFIG_PATH
    if ($value) { $ConfigObject.edgeproxy.config_path = $value }
    $value = Get-NonEmptyEnvironmentValue SECURITYEDGE_EDGEPROXY_ADMIN_URL
    if ($value) { $ConfigObject.edgeproxy.admin_url = $value }
    $value = Get-NonEmptyEnvironmentValue EDGEPROXY_ADMIN_TOKEN
    if ($value) { $ConfigObject.edgeproxy.admin_token = $value }

    $list = Get-EnvironmentList SECURITYEDGE_TRUSTED_PROXY_CIDRS
    if ($null -ne $list) { $ConfigObject.server.trusted_proxy_cidrs = @($list) }
    $list = Get-EnvironmentList SECURITYEDGE_DNS_NAMES
    if ($null -ne $list) { $ConfigObject.admin.connectivity.dns.names = @($list) }
    $list = Get-EnvironmentList SECURITYEDGE_DNS_EXPECTED_ADDRESSES
    if ($null -ne $list) { $ConfigObject.admin.connectivity.dns.expected_addresses = @($list) }

    $boolean = Get-EnvironmentBoolean SECURITYEDGE_DNS_ENABLED
    if ($null -ne $boolean) { $ConfigObject.admin.connectivity.dns.enabled = $boolean }
    $boolean = Get-EnvironmentBoolean SECURITYEDGE_DNS_CRITICAL
    if ($null -ne $boolean) { $ConfigObject.admin.connectivity.dns.critical = $boolean }

    return $ConfigObject
}

function ConvertTo-EnvironmentRouteSuffix {
    param([Parameter(Mandatory = $true)][string]$Name)
    return ([regex]::Replace($Name.Trim().ToUpperInvariant(), '[^A-Z0-9]+', '_')).Trim('_')
}

function Apply-EdgeProxyEnvironmentOverrides {
    param([Parameter(Mandatory = $true)]$ConfigObject)

    $value = Get-NonEmptyEnvironmentValue EDGEPROXY_SERVER_LISTEN_ADDR
    if ($value) { $ConfigObject.server.listen_addr = $value }
    $value = Get-NonEmptyEnvironmentValue EDGEPROXY_ADMIN_LISTEN_ADDR
    if ($value) { $ConfigObject.admin.listen_addr = $value }
    $value = Get-NonEmptyEnvironmentValue EDGEPROXY_ADMIN_TOKEN
    if ($value) { $ConfigObject.admin.auth_token = $value }
    $value = Get-NonEmptyEnvironmentValue EDGEPROXY_FORWARDED_FOR_HEADER
    if ($value) { $ConfigObject.server.forwarded_for_header = $value }
    $list = Get-EnvironmentList EDGEPROXY_TRUSTED_PROXY_CIDRS
    if ($null -ne $list) { $ConfigObject.server.trusted_proxy_cidrs = @($list) }

    $tlsEnabled = Get-EnvironmentBoolean EDGEPROXY_TLS_ENABLED
    if ($null -ne $tlsEnabled) { $ConfigObject.server.tls.enabled = $tlsEnabled }
    $value = Get-NonEmptyEnvironmentValue EDGEPROXY_TLS_CERT_FILE
    if ($value) { $ConfigObject.server.tls.cert_file = $value }
    $value = Get-NonEmptyEnvironmentValue EDGEPROXY_TLS_KEY_FILE
    if ($value) { $ConfigObject.server.tls.key_file = $value }

    $seenSuffixes = @{}
    foreach ($route in @($ConfigObject.routes)) {
        $suffix = ConvertTo-EnvironmentRouteSuffix -Name ([string]$route.name)
        if (-not $suffix) { continue }
        $hostsName = "EDGEPROXY_ROUTE_${suffix}_HOSTS"
        $urlsName = "EDGEPROXY_ROUTE_${suffix}_UPSTREAM_URLS"
        if (Get-NonEmptyEnvironmentValue -Name $hostsName) {
            throw "$hostsName is not supported; define route hosts in the shared JSON profile."
        }
        if ($seenSuffixes.ContainsKey($suffix)) {
            if (Get-NonEmptyEnvironmentValue -Name $urlsName) {
                throw "Route names '$($seenSuffixes[$suffix])' and '$($route.name)' map to the same environment suffix '$suffix'."
            }
            continue
        }
        $seenSuffixes[$suffix] = [string]$route.name
        $urls = Get-EnvironmentList -Name $urlsName
        if ($null -ne $urls) {
            $existing = @($route.upstreams)
            $replacement = @()
            for ($i = 0; $i -lt $urls.Count; $i++) {
                $skipVerify = $false
                if ($i -lt $existing.Count -and $null -ne $existing[$i].insecure_skip_verify) {
                    $skipVerify = [bool]$existing[$i].insecure_skip_verify
                }
                $replacement += [pscustomobject]@{
                    url = [string]$urls[$i]
                    insecure_skip_verify = $skipVerify
                }
            }
            $route.upstreams = $replacement
        }
    }

    return $ConfigObject
}

function Get-SecurityEdgePublicBaseUrlFromConfig {
    param([Parameter(Mandatory = $true)]$ConfigObject)
    $hostName = @($ConfigObject.admin.connectivity.dns.names | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })[0]
    if (-not $hostName) { $hostName = "project.test" }
    $port = Get-PortFromEndpoint -Endpoint ([string]$ConfigObject.server.listen_addr)
    if ($port -eq 80) { return "http://$hostName" }
    return "http://${hostName}:$port"
}
