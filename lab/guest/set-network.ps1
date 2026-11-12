# Runs at every boot (scheduled task "LabNetwork"). Gives the VM its fixed address on the isolated lab
# network: default gateway and DNS = the fake-internet VM (INetSim). Does nothing during the Packer build
# (the build uses NAT); cleanup.ps1 creates C:\lab\network.enabled at the end of the build.
$ErrorActionPreference = "Continue"
if (-not (Test-Path "C:\lab\network.enabled")) { exit 0 }
$lines = Get-Content "C:\lab\network.txt"
$ip = $lines[0].Trim()
$gateway = $lines[1].Trim()
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE"
foreach ($a in $adapters) {
    [void]$a.EnableStatic(@($ip), @("255.255.255.0"))
    [void]$a.SetGateways(@($gateway), @([uint16]1))
    [void]$a.SetDNSServerSearchOrder(@($gateway))
    break   # one network adapter
}
