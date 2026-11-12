<#
  unpack-offline.ps1  -  run this on the OFFLINE machine after copying the export folder over.

  Extracts each encrypted dump into its own folder, ready to open in MemoryGraph. No internet needed.

  Example:
    .\unpack-offline.ps1 -Source E:\lab-export
    .\unpack-offline.ps1 -Source E:\lab-export -Id win10-agenttesla-26400d63-20261112-2012

  Each dump lands in <Dest>\<id>\ with memory.vmem plus README.md and expected.json copied from the
  text repo, so the answer key sits right next to the image.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Source,   # the folder you copied (holds memorygraph-dumps\ and releases\)
    [string]$Dest = "",                              # where to extract; default: <Source>\unpacked
    [string]$SevenZip = "C:\Program Files\7-Zip\7z.exe",
    [string]$Password = "infected",
    [string[]]$Id                                    # optional: only these ids
)
$ErrorActionPreference = "Stop"
if (-not $Dest) { $Dest = Join-Path $Source "unpacked" }
if (-not (Test-Path $SevenZip)) { throw "7-Zip not found at $SevenZip (install it, or pass -SevenZip)" }

$releases = Join-Path $Source "releases"
$textRepo = Join-Path $Source "memorygraph-dumps"
$firsts = Get-ChildItem -Path $releases -Recurse -Filter "*.7z.001" -ErrorAction Stop
if (-not $firsts) { throw "No .7z.001 files under $releases" }

foreach ($f in $firsts) {
    $id = $f.BaseName -replace "\.7z$", ""           # win10-...-2012.7z.001 -> win10-...-2012
    if ($Id -and ($Id -notcontains $id)) { continue }
    $target = Join-Path $Dest $id
    if (Test-Path (Join-Path $target "memory.vmem")) { Write-Host "have   $id"; continue }
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    Write-Host "unpack $id ..." -ForegroundColor Cyan
    & $SevenZip x $f.FullName "-p$Password" "-o$target" -y | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7-Zip failed on $id" }

    # Bring the answer key next to the image, if the text repo was copied too.
    $src = Join-Path $textRepo "packages"
    if (Test-Path $src) {
        Get-ChildItem -Path $src -Recurse -Directory -Filter $id | ForEach-Object {
            foreach ($name in @("README.md", "expected.json", "metadata.json")) {
                $p = Join-Path $_.FullName $name
                if (Test-Path $p) { Copy-Item $p (Join-Path $target $name) -Force }
            }
        }
    }
}
Write-Host ""
Write-Host "Done. In MemoryGraph, Run analysis on  $Dest\<id>\memory.vmem" -ForegroundColor Green
Write-Host "(Offline symbols: this machine needs Volatility's Win10 symbol file once - see the note below.)" -ForegroundColor Yellow
