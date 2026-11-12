# Runs INSIDE the lab VM, started by the orchestrator through VMware Tools.
# Unpacks the password-protected MalwareBazaar archive (the sample is never unpacked on your computer),
# checks its SHA-256, puts it where a user would have saved it and starts it the way a user would
# (through Explorer, so its parent is explorer.exe). Writes C:\lab\out\detonation.json.
param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [Parameter(Mandatory = $true)][string]$Sha256,
    [string]$Password = "infected",
    [string]$FileName = "",
    [ValidateSet("exe", "dll")][string]$FileType = "exe",
    [string]$DllExport = "DllRegisterServer",
    [string]$DropDir = ""
)
$ErrorActionPreference = "Stop"
. "C:\lab\lab-json.ps1"
$result = @{}
$result["requested_sha256"] = $Sha256.ToLower()
$result["file_type"] = $FileType
$result["started_utc"] = [datetime]::UtcNow
$out = "C:\lab\out\detonation.json"
if (-not (Test-Path "C:\lab\out")) { New-Item -ItemType Directory -Path "C:\lab\out" -Force | Out-Null }

try {
    if ($DropDir -eq "") { $DropDir = Join-Path $env:USERPROFILE "Downloads" }
    if (-not (Test-Path $DropDir)) { New-Item -ItemType Directory -Path $DropDir | Out-Null }
    $work = "C:\lab\in\unpacked"
    if (Test-Path $work) { Remove-Item $work -Recurse -Force }
    & "C:\Program Files\7-Zip\7z.exe" x $Archive ("-p" + $Password) ("-o" + $work) -y | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7-Zip could not unpack the archive (exit $LASTEXITCODE)" }
    $inner = Get-ChildItem -Path $work -Recurse | Where-Object { -not $_.PSIsContainer } | Select-Object -First 1
    if ($inner -eq $null) { throw "The archive is empty" }
    $hash = Get-LabSha256 $inner.FullName
    $result["sha256"] = $hash
    if ($hash -ne $Sha256.ToLower()) { throw "SHA-256 mismatch: archive holds $hash" }

    if ($FileName -eq "") { $FileName = $inner.Name }
    $FileName = ($FileName -replace '[\\/:*?"<>|]', "_")
    $ext = "." + $FileType
    if (-not $FileName.ToLower().EndsWith($ext)) { $FileName = $FileName + $ext }
    $target = Join-Path $DropDir $FileName
    Move-Item -Path $inner.FullName -Destination $target -Force
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $Archive -Force -ErrorAction SilentlyContinue
    $result["path"] = $target

    $launched = [datetime]::UtcNow
    if ($FileType -eq "exe") {
        # Explorer hands the start to the desktop's explorer.exe, like a double-click.
        Start-Process -FilePath "explorer.exe" -ArgumentList ("`"" + $target + "`"")
        $result["launch"] = "explorer.exe `"$target`""
    } else {
        $dllArgs = "`"$target`",$DllExport"
        Start-Process -FilePath "rundll32.exe" -ArgumentList $dllArgs
        $result["launch"] = "rundll32.exe $dllArgs"
    }
    $result["launched_utc"] = $launched

    # Find the process that runs the sample (some samples move or delete themselves at once).
    $pids = @()
    for ($i = 0; $i -lt 30 -and $pids.Count -eq 0; $i++) {
        Start-Sleep -Milliseconds 500
        $escaped = $target.Replace("\", "\\").Replace("'", "\'")
        if ($FileType -eq "exe") {
            $procs = Get-WmiObject Win32_Process -Filter ("ExecutablePath = '" + $escaped + "'")
        } else {
            $procs = Get-WmiObject Win32_Process -Filter "Name = 'rundll32.exe'" | Where-Object { $_.CommandLine -like ("*" + $target + "*") }
        }
        foreach ($p in @($procs)) { if ($p -ne $null) { $pids += [int]$p.ProcessId } }
    }
    $result["pids"] = $pids
    $result["status"] = "launched"
} catch {
    $result["status"] = "error"
    $result["error"] = [string]$_.Exception.Message
}
Write-LabJson $result $out
exit 0
