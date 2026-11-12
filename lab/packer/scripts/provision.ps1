# Prepares the clean template. Runs once inside the VM during "packer build".
# Kept compatible with PowerShell 2.0 (Windows 7): no Invoke-WebRequest, no CIM cmdlets, no -ErrorAction Ignore.
param(
    [Parameter(Mandatory = $true)][string]$Os,
    [Parameter(Mandatory = $true)][string]$User,
    [Parameter(Mandatory = $true)][string]$Password,
    [string]$VictimIp = "10.66.0.10",
    [string]$GatewayIp = "10.66.0.1"
)
$ErrorActionPreference = "Stop"
$lab = "C:\Windows\Temp\lab"
$files = Join-Path $lab "files"

function Log($text) { Write-Host ("[provision] " + $text) }

function Set-Reg($path, $name, $value, $type = "DWord") {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
}

function Install-Msi($path, $extra = "") {
    Log "Installing $path"
    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$path`" /qn /norestart $extra" -Wait -PassThru
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "msiexec failed for $path with exit code $($p.ExitCode)" }
}

# --- 7-Zip: the guest unpacks the password-protected samples itself (they never get unpacked on your computer)
$sevenZipMsi = Get-ChildItem -Path $files -Filter "7z*-x64.msi" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sevenZipMsi -eq $null) { throw "Put the 7-Zip x64 MSI (for example 7z2408-x64.msi) in lab/packer/files/ (see files/README.md)." }
Install-Msi $sevenZipMsi.FullName
$sevenZip = "C:\Program Files\7-Zip\7z.exe"

# --- .NET Framework 4.8 on Windows 7 (most current Windows malware is .NET and needs it)
if ($Os -eq "win7") {
    $dotnet = Get-ChildItem -Path $files -Filter "ndp48*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($dotnet -ne $null) {
        Log "Installing .NET Framework 4.8"
        $p = Start-Process -FilePath $dotnet.FullName -ArgumentList "/q /norestart" -Wait -PassThru
        if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010 -and $p.ExitCode -ne 1641) { throw ".NET 4.8 setup failed: $($p.ExitCode)" }
    } else {
        Log "No .NET 4.8 offline installer in files/: .NET samples may not run on Windows 7."
    }
}

# --- VMware Tools (needed: the orchestrator copies files and starts programs through them; no network to your computer is used)
$toolsIso = "C:\Windows\Temp\vmtools.iso"
if (Test-Path $toolsIso) {
    $toolsDir = "C:\Windows\Temp\vmtools"
    & $sevenZip x $toolsIso ("-o" + $toolsDir) -y | Out-Null
    $setup = Join-Path $toolsDir "setup64.exe"
    if (-not (Test-Path $setup)) { $setup = Join-Path $toolsDir "setup.exe" }
    Log "Installing VMware Tools (without shared folders)"
    # Hgfs = shared folders: left out so the infected guest has no file path to your computer.
    $p = Start-Process -FilePath $setup -ArgumentList '/S /v"/qn REBOOT=R ADDLOCAL=ALL REMOVE=Hgfs"' -Wait -PassThru
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "VMware Tools setup failed: $($p.ExitCode)" }
} else {
    throw "VMware Tools ISO was not uploaded to $toolsIso"
}

# --- Lab folders and the detonation scripts
foreach ($d in @("C:\lab", "C:\lab\in", "C:\lab\out")) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null } }
Copy-Item -Path (Join-Path $lab "guest\*") -Destination "C:\lab" -Force
"$VictimIp`n$GatewayIp" | Out-File -FilePath "C:\lab\network.txt" -Encoding ASCII

# --- Static IP on the isolated lab network, applied at every boot (the build itself uses NAT/DHCP)
$task = "schtasks.exe /Create /F /TN LabNetwork /SC ONSTART /RU SYSTEM /RL HIGHEST /TR `"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\lab\set-network.ps1`""
cmd.exe /c $task | Out-Null

# --- Keep the desktop session alive (programs started with vmrun -interactive need a logged-on user)
$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-Reg $winlogon "AutoAdminLogon" "1" "String"
Set-Reg $winlogon "DefaultUserName" $User "String"
Set-Reg $winlogon "DefaultPassword" $Password "String"
Set-Reg $winlogon "AutoLogonCount" 9999
cmd.exe /c "powercfg -change -standby-timeout-ac 0" | Out-Null
cmd.exe /c "powercfg -change -monitor-timeout-ac 0" | Out-Null
cmd.exe /c "powercfg -change -hibernate-timeout-ac 0" | Out-Null
cmd.exe /c "powercfg -h off" | Out-Null
Set-Reg "HKCU:\Control Panel\Desktop" "ScreenSaveActive" "0" "String"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreen" 1

# --- No prompts while samples run (UAC stays on: elevation happens without asking, like a careless admin)
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "Off" "String"
Set-Reg "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" 1

# --- No Windows Update or automatic maintenance changing the machine between runs
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 1
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" "MaintenanceDisabled" 1
foreach ($svc in @("wuauserv", "UsoSvc", "WaaSMedicSvc", "DiagTrack")) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s -ne $null) {
        try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch { }
        cmd.exe /c "sc config $svc start= disabled" | Out-Null
    }
}

Log "Done ($Os)."
