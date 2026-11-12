<#
  grab-all.ps1  -  run this ONLINE (on a machine with internet).

  Mirrors the whole dumps repo into one folder you can copy to an offline analysis machine:
    <Dest>\memorygraph-dumps\   the small text repo (CATALOG.md + each dump's README + answer key)
    <Dest>\releases\<id>\       every dump's encrypted 7z parts (<id>.7z.001, .002, ...)

  Example:
    .\grab-all.ps1 -Dest E:\lab-export          # E: is a USB drive

  Already-downloaded dumps are skipped, so you can re-run it to pick up new ones.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Dest,
    [string]$Repo = "DvirCohen17/memorygraph-dumps",
    [string]$Gh = "gh"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

# 1. The small text repo: catalog, per-dump README.md and expected.json (the answer keys).
$repoDir = Join-Path $Dest "memorygraph-dumps"
if (Test-Path (Join-Path $repoDir ".git")) {
    Write-Host "Updating text repo in $repoDir" -ForegroundColor Cyan
    git -C $repoDir pull --ff-only
} else {
    Write-Host "Cloning text repo into $repoDir" -ForegroundColor Cyan
    & $Gh repo clone $Repo $repoDir
}

# 2. Every release's encrypted dump parts.
$releasesDir = Join-Path $Dest "releases"
New-Item -ItemType Directory -Force -Path $releasesDir | Out-Null
$ids = & $Gh release list --repo $Repo --limit 1000 |
    ForEach-Object { ($_ -split "`t")[0].Trim() } | Where-Object { $_ }
if (-not $ids) { Write-Host "No releases found in $Repo." -ForegroundColor Yellow; return }

foreach ($id in $ids) {
    $d = Join-Path $releasesDir $id
    if (Test-Path (Join-Path $d "$id.7z.001")) { Write-Host "have   $id"; continue }
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    Write-Host "get    $id ..." -ForegroundColor Cyan
    & $Gh release download $id --repo $Repo --dir $d --pattern "$id.7z.*" --clobber
    if ($LASTEXITCODE -ne 0) { throw "download of $id failed" }
}
Write-Host ""
Write-Host "Done. Copy the whole '$Dest' folder to the offline machine, then run unpack-offline.ps1 there." -ForegroundColor Green
