@echo off
rem Runs once at the first logon (from the answer file) so Packer can connect over WinRM.
rem Plain cmd + winrm/netsh: works the same on Windows 7, 10 and 11.
rem WinRM is only reachable on Packer's build network; cleanup.ps1 switches it off again.

rem Windows refuses WinRM on networks marked "Public": mark every network Private.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private } catch { }" 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\FirstNetwork" /v Category /t REG_DWORD /d 1 /f >nul 2>&1

call winrm quickconfig -q
call winrm quickconfig -transport:http -q
call winrm set winrm/config @{MaxTimeoutms="7200000"}
call winrm set winrm/config/winrs @{MaxMemoryPerShellMB="2048"}
call winrm set winrm/config/service @{AllowUnencrypted="true"}
call winrm set winrm/config/service/auth @{Basic="true"}
call winrm set winrm/config/client/auth @{Basic="true"}
netsh advfirewall firewall add rule name="WinRM-HTTP (lab build)" dir=in localport=5985 protocol=TCP action=allow
sc config winrm start= auto
net stop winrm
net start winrm
