param([int]$Bytes = 32)
if ($Bytes -lt 16) { throw "Use at least 16 random bytes." }

$buffer = New-Object byte[] $Bytes
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($buffer)
}
finally {
    $rng.Dispose()
}

$token = [Convert]::ToBase64String($buffer).TrimEnd('=').Replace('+','-').Replace('/','_')
Write-Output $token
