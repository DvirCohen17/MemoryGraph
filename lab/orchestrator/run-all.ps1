<#
  run-all.ps1  -  one command to build the whole dump set and publish it to GitHub.

  Run it from the folder that holds labctl.py (lab\orchestrator). It chains the labctl steps:
      check  ->  fetch  ->  baseline (once per guest)  ->  run every family
  Each capture is uploaded to the dumps repo as soon as it finishes (unless -NoUpload), so if the
  machine dies halfway through, everything already captured is safely on GitHub.

  Examples:
      .\run-all.ps1                               # everything, every guest, every family
      .\run-all.ps1 -Guest win10                  # only the Win10 victim
      .\run-all.ps1 -Family AgentTesla,RemcosRAT  # only these families
      .\run-all.ps1 -Seconds 300 -Again           # run longer, re-capture samples already done
      .\run-all.ps1 -NoUpload                      # keep packages in work_dir, don't publish

  Needs your MalwareBazaar key in this shell first (once per window):
      $env:MALWAREBAZAAR_AUTH_KEY = "....your key...."
  or pass -AuthKey "...." (less safe: it lands in your PowerShell history).
#>
[CmdletBinding()]
param(
    [string[]]$Guest,                 # default: every guest in lab.toml
    [string[]]$Family,                # default: every family in families.toml
    [int]$Seconds = 0,                # 0 = use lab.toml
    [int]$PerFamily = 0,              # 0 = use lab.toml
    [switch]$SkipCheck,
    [switch]$SkipFetch,
    [switch]$SkipBaseline,
    [switch]$NoUpload,                # keep packages locally instead of publishing
    [switch]$Again,                   # also re-run samples already captured on that guest
    [string]$AuthKey = "",
    [string]$Python = "py",           # the launcher; -3.11 selects Python 3.11 below
    [string]$PyVersion = "-3.11"
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if ($AuthKey) { $env:MALWAREBAZAAR_AUTH_KEY = $AuthKey }

function Invoke-Labctl {
    param([string[]]$LabArgs)
    $full = @()
    if ($PyVersion) { $full += $PyVersion }
    $full += @("labctl.py") + $LabArgs
    Write-Host ""
    Write-Host ">> $Python $($full -join ' ')" -ForegroundColor Cyan
    & $Python @full
    if ($LASTEXITCODE -ne 0) { throw "labctl '$($LabArgs[0])' exited with code $LASTEXITCODE" }
}

$guestArgs = @(); foreach ($g in $Guest)  { $guestArgs  += @("--guest",  $g) }
$famArgs   = @(); foreach ($f in $Family) { $famArgs    += @("--family", $f) }

# 1. Is everything in place? (VMs isolated + snapshot, 7-Zip, Auth-Key, GitHub login, disk space.)
if (-not $SkipCheck) { Invoke-Labctl @("check") }

# 2. Download the samples (still inside MalwareBazaar's password zip).
if (-not $SkipFetch) {
    $a = @("fetch") + $famArgs
    if ($PerFamily) { $a += @("--per-family", "$PerFamily") }
    Invoke-Labctl $a
}

# 3. One clean baseline per guest (the reference for spotting false positives).
if (-not $SkipBaseline) {
    $a = @("baseline") + $guestArgs
    if ($Seconds)  { $a += @("--seconds", "$Seconds") }
    if ($NoUpload) { $a += "--no-upload" }
    Invoke-Labctl $a
}

# 4. Detonate every cached sample on every guest its family lists; publish each as it finishes.
$a = @("run") + $guestArgs + $famArgs
if ($Seconds)   { $a += @("--seconds", "$Seconds") }
if ($PerFamily) { $a += @("--per-family", "$PerFamily") }
if ($NoUpload)  { $a += "--no-upload" }
if ($Again)     { $a += "--again" }
Invoke-Labctl $a

Write-Host ""
Write-Host "All done. Catalog: https://github.com/DvirCohen17/memorygraph-dumps/blob/main/CATALOG.md" -ForegroundColor Green
