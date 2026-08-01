param([int]$Bytes = 32)
if ($Bytes -lt 16) { throw "Use at least 16 random bytes." }
$buffer = New-Object byte[] $Bytes
[Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
$token = [Convert]::ToBase64String($buffer).TrimEnd('=').Replace('+','-').Replace('/','_')
Write-Output $token
