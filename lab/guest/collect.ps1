# Runs INSIDE the lab VM a few seconds before the memory capture. Records what was really running
# (processes with parents, paths, command lines, start times) and the network connections.
# The orchestrator turns this into the dump's answer key (expected.json).
# Its own powershell.exe is listed as "collector_pid" so the answer key can leave it out.
$ErrorActionPreference = "Continue"
. "C:\lab\lab-json.ps1"
$truth = @{}
$out = "C:\lab\out\groundtruth.json"
if (-not (Test-Path "C:\lab\out")) { New-Item -ItemType Directory -Path "C:\lab\out" -Force | Out-Null }
try {
$truth["taken_utc"] = [datetime]::UtcNow
$truth["collector_pid"] = [int]$PID
$truth["os"] = Get-LabOsInfo
$truth["computer"] = [string]$env:COMPUTERNAME

$processes = @()
foreach ($p in Get-WmiObject Win32_Process) {
    $row = @{}
    $row["pid"] = [int]$p.ProcessId
    $row["ppid"] = [int]$p.ParentProcessId
    $row["name"] = [string]$p.Name
    $row["path"] = [string]$p.ExecutablePath
    $row["command_line"] = [string]$p.CommandLine
    $row["session"] = [int]$p.SessionId
    $row["threads"] = [int]$p.ThreadCount
    if ($p.CreationDate) {
        try { $row["created_utc"] = [System.Management.ManagementDateTimeConverter]::ToDateTime($p.CreationDate) } catch { $row["created_utc"] = $null }
    } else { $row["created_utc"] = $null }
    $processes += $row
}
$truth["processes"] = $processes

$connections = @()
foreach ($line in (netstat.exe -ano)) {
    $parts = ($line.Trim() -split "\s+")
    if ($parts.Count -lt 4) { continue }
    if ($parts[0] -ne "TCP" -and $parts[0] -ne "UDP") { continue }
    $c = @{}
    $c["proto"] = $parts[0]
    $c["local"] = $parts[1]
    $c["remote"] = $parts[2]
    if ($parts[0] -eq "TCP") { $c["state"] = $parts[3]; $c["pid"] = [int]$parts[4] } else { $c["state"] = ""; $c["pid"] = [int]$parts[3] }
    $connections += $c
}
$truth["connections"] = $connections
} catch {
    $truth["fatal"] = [string]$_.Exception.Message
}
$errs = @()
foreach ($e in $Error) { $errs += [string]$e }
$truth["errors"] = $errs
Write-LabJson $truth $out
exit 0
