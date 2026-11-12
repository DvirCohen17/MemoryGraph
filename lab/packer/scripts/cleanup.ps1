# Last build step: remove build leftovers. WinRM (needed only by Packer) is closed at the NEXT boot,
# because Packer still sends its shutdown command over WinRM after this script.
$ErrorActionPreference = "Continue"
Remove-Item -Path "C:\Windows\Temp\vmtools", "C:\Windows\Temp\vmtools.iso" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\lab\files" -Recurse -Force -ErrorAction SilentlyContinue

$off = @'
@echo off
netsh advfirewall firewall delete rule name="WinRM-HTTP (lab build)"
call winrm set winrm/config/service @{AllowUnencrypted="false"}
call winrm set winrm/config/service/auth @{Basic="false"}
sc config winrm start= demand
net stop winrm
schtasks /Delete /F /TN LabWinRMOff
'@
$off | Out-File -FilePath "C:\lab\winrm-off.cmd" -Encoding ASCII
cmd.exe /c "schtasks.exe /Create /F /TN LabWinRMOff /SC ONSTART /RU SYSTEM /RL HIGHEST /TR C:\lab\winrm-off.cmd" | Out-Null
# From the next boot on, the VM uses its static address on the isolated lab network (set-network.ps1).
"enabled" | Out-File -FilePath "C:\lab\network.enabled" -Encoding ASCII
Write-Host "[cleanup] done; WinRM is switched off at the next boot"
