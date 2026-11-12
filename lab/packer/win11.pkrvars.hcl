os            = "win11"
iso_url       = "file:///D:/iso/Win11_24H2_English_x64.iso"
iso_checksum  = "none"
guest_os_type = "windows11-64"
firmware      = "efi"
disk_adapter  = "nvme"
nic_type      = "e1000e"
memory_mb     = 4096
# The answer file sets LabConfig BypassTPMCheck/BypassSecureBootCheck, so no virtual TPM
# (and no VM encryption) is needed. An encrypted VM would also encrypt the .vmem dump.
