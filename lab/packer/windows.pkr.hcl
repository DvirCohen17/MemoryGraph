# Builds one clean Windows "template" VM for VMware Workstation.
#   packer init  .
#   packer build -var-file=win10.pkrvars.hcl .
# The template is never infected: Terraform makes linked clones of it (lab/terraform).

packer {
  required_plugins {
    vmware = {
      source  = "github.com/hashicorp/vmware"
      version = ">= 1.0.0"
    }
  }
}

variable "os" {
  type        = string
  description = "win7 | win10 | win11 (picks the answer file in answer/<os>/)"
  validation {
    condition     = contains(["win7", "win10", "win11"], var.os)
    error_message = "The os must be win7, win10 or win11."
  }
}

variable "iso_url" {
  type        = string
  description = "Path to your Windows ISO, for example file:///D:/iso/Win10_22H2_English_x64.iso"
}

variable "iso_checksum" {
  type        = string
  default     = "none"
  description = "sha256:<hash> of the ISO (recommended), or none"
}

variable "guest_os_type" { type = string }        # VMware guestOS id: windows7-64 / windows9-64 / windows11-64
variable "firmware"      { type = string }        # bios (win7) or efi (win10/win11)
variable "disk_adapter"  { type = string }        # lsisas1068 (win7) or nvme (win10/win11)
variable "nic_type"      { type = string }        # e1000 (win7) or e1000e (win10/win11)

variable "cpus" {
  type    = number
  default = 2
}

variable "memory_mb" {
  type        = number
  default     = 4096
  description = "Guest RAM = the size of every memory dump (2048 is enough for win7)"
}

variable "disk_mb" {
  type    = number
  default = 61440
}

variable "output_root" {
  type        = string
  default     = "D:/malware-lab/templates"
  description = "Where the template VM folder is written (one folder per os)"
}

variable "lab_vnet" {
  type        = string
  default     = "VMnet9"
  description = "Isolated host-only network the template is switched to after the build (see lab/README.md, one-time setup)"
}

variable "guest_user" {
  type    = string
  default = "analyst"
}

variable "guest_password" {
  type      = string
  default   = "Lab!Passw0rd"
  sensitive = true
  # Must match the answer files in answer/<os>/autounattend.xml.
}

variable "victim_ip" {
  type    = string
  default = "10.66.0.10"
}

variable "gateway_ip" {
  type        = string
  default     = "10.66.0.1"
  description = "The fake-internet VM (INetSim): default gateway and DNS server of the victim"
}

variable "tools_iso" {
  type        = string
  default     = ""
  description = "Leave empty to use Workstation's own VMware Tools. Windows 7 needs an older Tools ISO (10.x/11.x): give its path here."
}

variable "pause_for_defender" {
  type        = bool
  default     = true
  description = "Win10/11: pause so you can switch Tamper Protection off by hand (it cannot be scripted)"
}

locals {
  vm_name = "${var.os}-template"
}

source "vmware-iso" "windows" {
  vm_name          = local.vm_name
  output_directory = "${var.output_root}/${local.vm_name}"
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  guest_os_type    = var.guest_os_type
  version          = 19
  firmware         = var.firmware
  cpus             = var.cpus
  memory           = var.memory_mb
  disk_size        = var.disk_mb
  disk_adapter_type    = var.disk_adapter
  network_adapter_type = var.nic_type
  network          = "nat" # the build needs a network for WinRM only; the finished template is moved to the isolated VMnet
  headless         = false
  boot_wait        = "3s"
  boot_command     = ["<spacebar><wait><spacebar>"] # "Press any key to boot from CD" on EFI firmware

  floppy_files = [
    "answer/${var.os}/autounattend.xml",
    "scripts/enable-winrm.cmd",
  ]

  communicator   = "winrm"
  winrm_username = var.guest_user
  winrm_password = var.guest_password
  winrm_timeout  = "3h" # Windows setup + updates offered by setup can take a while

  tools_upload_flavor = var.tools_iso == "" ? "windows" : null
  tools_source_path   = var.tools_iso == "" ? null : var.tools_iso
  tools_upload_path   = "C:/Windows/Temp/vmtools.iso"

  shutdown_command = "shutdown /s /t 10 /f /d p:4:1 /c \"Packer shutdown\""
  shutdown_timeout = "30m"
  skip_compaction  = false

  vmx_data = {
    # Memory: keep the whole guest RAM in one .vmem file so a suspend gives a complete, consistent dump.
    "mainMem.useNamedFile"      = "TRUE"
    "MemTrimRate"               = "0"
    "sched.mem.pshare.enable"   = "FALSE"
    # Isolation between the (future) infected guest and your computer.
    "isolation.tools.copy.disable"        = "TRUE"
    "isolation.tools.paste.disable"       = "TRUE"
    "isolation.tools.dnd.disable"         = "TRUE"
    "isolation.tools.setGUIOptions.enable" = "FALSE"
    "isolation.tools.hgfs.disable"        = "TRUE"
    "sharedFolder.maxNum"                 = "0"
    "usb.present"                         = "FALSE"
    "sound.present"                       = "FALSE"
    "serial0.present"                     = "FALSE"
    "parallel0.present"                   = "FALSE"
  }

  vmx_data_post = {
    # From now on the VM only sees the isolated lab network (never NAT or bridged).
    "ethernet0.connectionType" = "custom"
    "ethernet0.vnet"           = var.lab_vnet
    "ethernet0.startConnected" = "TRUE"
    "floppy0.present"          = "FALSE"
  }
}

build {
  name    = "malware-lab-template"
  sources = ["source.vmware-iso.windows"]

  # Lab scripts and the offline installers you put in files/ (see files/README.md).
  provisioner "file" {
    source      = "scripts/"
    destination = "C:/Windows/Temp/lab"
  }
  provisioner "file" {
    source      = "files/"
    destination = "C:/Windows/Temp/lab/files"
  }
  provisioner "file" {
    source      = "../guest/"
    destination = "C:/Windows/Temp/lab/guest"
  }

  provisioner "windows-shell" {
    inline = [
      "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\lab\\provision.ps1 -Os ${var.os} -User ${var.guest_user} -Password \"${var.guest_password}\" -VictimIp ${var.victim_ip} -GatewayIp ${var.gateway_ip}",
    ]
  }

  provisioner "windows-restart" {
    restart_timeout = "30m"
  }

  # Windows 10/11: Tamper Protection blocks every scripted way of switching Defender off.
  provisioner "breakpoint" {
    disable = var.os == "win7" || !var.pause_for_defender
    note    = "In the VM: Windows Security > Virus & threat protection > Manage settings > switch OFF Tamper Protection (and Real-time protection). Then press Enter here."
  }

  provisioner "windows-shell" {
    inline = [
      "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\lab\\defender-off.ps1 -Os ${var.os}",
    ]
  }

  provisioner "windows-restart" {
    restart_timeout = "30m"
  }

  provisioner "windows-shell" {
    inline = [
      "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\lab\\cleanup.ps1",
    ]
  }
}
