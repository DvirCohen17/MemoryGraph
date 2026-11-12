# Called by Terraform (main.tf). Uses vmrun, which comes with VMware Workstation.
param(
    [Parameter(Mandatory = $true)][ValidateSet("create", "destroy", "gateway-start", "gateway-stop")][string]$Action,
    [Parameter(Mandatory = $true)][string]$Vmrun,
    [Parameter(Mandatory = $true)][string]$CloneVmx,
    [string]$TemplateVmx = "",
    [string]$CloneName = "",
    [string]$LabVnet = "VMnet9",
    [string]$BaseSnapshot = "base",
    [string]$ReadySnapshot = "ready",
    [int]$SettleSeconds = 180,
    [int]$BootTimeoutSeconds = 1200
)
$ErrorActionPreference = "Stop"

function Invoke-Vmrun {
    param([string[]]$Arguments, [switch]$AllowFail)
    $output = & $Vmrun -T ws @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -and -not $AllowFail) { throw "vmrun $($Arguments[0]) failed: $output" }
    return $output.Trim()
}

function Invoke-Guest {
    param([string[]]$Arguments, [switch]$AllowFail)
    $user = $env:LAB_GUEST_USER
    $password = $env:LAB_GUEST_PASSWORD
    $output = & $Vmrun -T ws -gu $user -gp $password @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -and -not $AllowFail) { throw "vmrun $($Arguments[0]) failed: $output" }
    return $output.Trim()
}

# The victim must only ever see the isolated lab network: never NAT, bridged or the host's own adapters.
function Set-IsolatedNetwork([string]$vmx, [string]$vnet) {
    $lines = Get-Content -Path $vmx
    $keep = $lines | Where-Object { $_ -notmatch '^\s*ethernet\d+\.(connectionType|vnet|startConnected)\s*=' }
    $keep += 'ethernet0.connectionType = "custom"'
    $keep += ('ethernet0.vnet = "' + $vnet + '"')
    $keep += 'ethernet0.startConnected = "TRUE"'
    # Only ethernet0 may exist.
    $extra = $lines | Where-Object { $_ -match '^\s*ethernet([1-9]\d*)\.present\s*=\s*"TRUE"' }
    if ($extra) { throw "The VM has more than one network adapter: remove the others in $vmx" }
    Set-Content -Path $vmx -Value $keep -Encoding ASCII
}

function Wait-Ready([string]$vmx) {
    $deadline = (Get-Date).AddSeconds($BootTimeoutSeconds)
    Write-Host "Waiting for VMware Tools in the guest..."
    while ((Invoke-Vmrun -Arguments @("checkToolsState", $vmx) -AllowFail) -notmatch "running") {
        if ((Get-Date) -gt $deadline) { throw "VMware Tools did not start within $BootTimeoutSeconds s" }
        Start-Sleep -Seconds 10
    }
    Write-Host "Waiting for the desktop (explorer.exe)..."
    while ((Invoke-Guest -Arguments @("listProcessesInGuest", $vmx) -AllowFail) -notmatch "explorer\.exe") {
        if ((Get-Date) -gt $deadline) { throw "Nobody logged on within $BootTimeoutSeconds s (check auto-logon)" }
        Start-Sleep -Seconds 10
    }
}

switch ($Action) {
    "create" {
        if (-not (Test-Path $TemplateVmx)) { throw "Template not found: $TemplateVmx (build it with Packer first)" }
        $snapshots = Invoke-Vmrun -Arguments @("listSnapshots", $TemplateVmx)
        if (($snapshots -split "`r?`n") -notcontains $BaseSnapshot) {
            Write-Host "Taking snapshot '$BaseSnapshot' of the template (it must be powered off)"
            Invoke-Vmrun -Arguments @("snapshot", $TemplateVmx, $BaseSnapshot) | Out-Null
        }
        if (Test-Path $CloneVmx) {
            Write-Host "Removing an old clone at $CloneVmx"
            Invoke-Vmrun -Arguments @("stop", $CloneVmx, "hard") -AllowFail | Out-Null
            Invoke-Vmrun -Arguments @("deleteVM", $CloneVmx) -AllowFail | Out-Null
        }
        New-Item -ItemType Directory -Force -Path (Split-Path $CloneVmx) | Out-Null
        Write-Host "Linked clone $CloneName"
        Invoke-Vmrun -Arguments @("clone", $TemplateVmx, $CloneVmx, "linked", "-snapshot=$BaseSnapshot", "-cloneName=$CloneName") | Out-Null
        Set-IsolatedNetwork $CloneVmx $LabVnet
        Invoke-Vmrun -Arguments @("start", $CloneVmx, "nogui") | Out-Null
        Wait-Ready $CloneVmx
        Write-Host "Letting Windows settle for $SettleSeconds s"
        Start-Sleep -Seconds $SettleSeconds
        Write-Host "Taking snapshot '$ReadySnapshot' (with memory)"
        Invoke-Vmrun -Arguments @("snapshot", $CloneVmx, $ReadySnapshot) | Out-Null
        Invoke-Vmrun -Arguments @("stop", $CloneVmx, "hard") -AllowFail | Out-Null
        Write-Host "Ready: $CloneVmx"
    }
    "destroy" {
        if (Test-Path $CloneVmx) {
            Invoke-Vmrun -Arguments @("stop", $CloneVmx, "hard") -AllowFail | Out-Null
            Invoke-Vmrun -Arguments @("deleteVM", $CloneVmx) -AllowFail | Out-Null
            $dir = Split-Path $CloneVmx
            if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
        }
    }
    "gateway-start" {
        if (-not (Test-Path $CloneVmx)) { throw "Gateway VM not found: $CloneVmx" }
        Set-IsolatedNetwork $CloneVmx $LabVnet
        Invoke-Vmrun -Arguments @("start", $CloneVmx, "nogui") | Out-Null
    }
    "gateway-stop" {
        Invoke-Vmrun -Arguments @("stop", $CloneVmx, "soft") -AllowFail | Out-Null
    }
}
