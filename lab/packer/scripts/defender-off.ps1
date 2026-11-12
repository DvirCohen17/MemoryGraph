# Switches Microsoft Defender off in the template so samples are not deleted before they run.
# Windows 10/11: works only after Tamper Protection was switched off by hand (Packer pauses for that).
# Windows 7: Windows Defender there is only an anti-spyware tool; it is disabled as a service.
param([Parameter(Mandatory = $true)][string]$Os)
$ErrorActionPreference = "Continue"

function Set-Reg($path, $name, $value) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -Path $path -Name $name -Value $value -PropertyType DWord -Force | Out-Null
}

$policy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
Set-Reg $policy "DisableAntiSpyware" 1
Set-Reg $policy "DisableAntiVirus" 1
Set-Reg "$policy\Real-Time Protection" "DisableRealtimeMonitoring" 1
Set-Reg "$policy\Real-Time Protection" "DisableBehaviorMonitoring" 1
Set-Reg "$policy\Real-Time Protection" "DisableOnAccessProtection" 1
Set-Reg "$policy\Real-Time Protection" "DisableScanOnRealtimeEnable" 1
Set-Reg "$policy\Real-Time Protection" "DisableIOAVProtection" 1
Set-Reg "$policy\Spynet" "SpynetReporting" 0
Set-Reg "$policy\Spynet" "SubmitSamplesConsent" 2

if ($Os -ne "win7") {
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        try {
            Add-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue
            Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true `
                -DisableScriptScanning $true -MAPSReporting 0 -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
        } catch { }
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($status -ne $null) {
            Write-Host ("[defender] Tamper protection: " + $status.IsTamperProtected + "  real-time protection: " + $status.RealTimeProtectionEnabled)
            if ($status.IsTamperProtected) {
                Write-Host "[defender] WARNING: Tamper Protection is still on. Samples may be removed before they run."
            }
        }
    }
} else {
    cmd.exe /c "sc config WinDefend start= disabled" | Out-Null
    cmd.exe /c "net stop WinDefend" | Out-Null
}
