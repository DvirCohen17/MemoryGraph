# Tiny JSON writer for the guest scripts (PowerShell 2.0 on Windows 7 has no ConvertTo-Json).
function ConvertTo-LabJson($value) {
    if ($value -eq $null) { return "null" }
    if ($value -is [bool]) { if ($value) { return "true" } else { return "false" } }
    if ($value -is [int] -or $value -is [long] -or $value -is [uint32] -or $value -is [uint64] -or $value -is [double]) {
        return ([string]$value).Replace(",", ".")
    }
    if ($value -is [datetime]) { return ConvertTo-LabJson ($value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) }
    if ($value -is [System.Collections.IDictionary]) {
        $parts = @()
        foreach ($key in $value.Keys) { $parts += ((ConvertTo-LabJson ([string]$key)) + ":" + (ConvertTo-LabJson $value[$key])) }
        return "{" + ($parts -join ",") + "}"
    }
    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        $parts = @()
        foreach ($item in $value) { $parts += (ConvertTo-LabJson $item) }
        return "[" + ($parts -join ",") + "]"
    }
    $s = [string]$value
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($c in $s.ToCharArray()) {
        $code = [int]$c
        if ($c -eq '"') { [void]$sb.Append('\"') }
        elseif ($c -eq '\') { [void]$sb.Append('\\') }
        elseif ($code -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
        else { [void]$sb.Append($c) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Write-LabJson($value, $path) {
    [System.IO.File]::WriteAllText($path, (ConvertTo-LabJson $value), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-LabSha256($path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($path)
    try { $bytes = $sha.ComputeHash($stream) } finally { $stream.Close() }
    return ([System.BitConverter]::ToString($bytes)).Replace("-", "").ToLower()
}

function Get-LabOsInfo {
    $cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $info = @{}
    $info["product"] = [string]$cv.ProductName
    $info["build"] = [string]$cv.CurrentBuild
    $info["ubr"] = [string]$cv.UBR
    $info["display_version"] = [string]$cv.DisplayVersion
    $info["release_id"] = [string]$cv.ReleaseId
    $info["version"] = [string][Environment]::OSVersion.Version
    $info["arch"] = [string]$env:PROCESSOR_ARCHITECTURE
    return $info
}
