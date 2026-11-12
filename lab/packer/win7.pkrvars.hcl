os            = "win7"
iso_url       = "file:///D:/iso/en_windows_7_professional_with_sp1_x64.iso"
iso_checksum  = "none"
guest_os_type = "windows7-64"
firmware      = "bios"
disk_adapter  = "lsisas1068"
nic_type      = "e1000"
memory_mb     = 2048
disk_mb       = 40960
# Current VMware Tools no longer install on Windows 7: give an older Tools ISO (10.3.x or 11.x).
tools_iso     = "D:/iso/VMware-tools-windows-11.0.6.iso"
