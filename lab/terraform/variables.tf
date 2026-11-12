variable "guests" {
  type        = list(string)
  default     = ["win10"]
  description = "Which templates to clone: any of win7, win10, win11 (each must have been built with Packer)"
  validation {
    condition     = alltrue([for g in var.guests : contains(["win7", "win10", "win11"], g)])
    error_message = "Guests must be win7, win10 or win11."
  }
}

variable "vmrun_path" {
  type    = string
  default = "C:/Program Files (x86)/VMware/VMware Workstation/vmrun.exe"
}

variable "templates_root" {
  type        = string
  default     = "D:/malware-lab/templates"
  description = "Same as output_root in the Packer variables"
}

variable "vms_root" {
  type        = string
  default     = "D:/malware-lab/vms"
  description = "Where the victim VMs (linked clones) are created"
}

variable "lab_vnet" {
  type        = string
  default     = "VMnet9"
  description = "The isolated host-only network (no host adapter, no DHCP, no NAT): see lab/README.md"
}

variable "guest_user" {
  type    = string
  default = "analyst"
}

variable "guest_password" {
  type      = string
  default   = "Lab!Passw0rd"
  sensitive = true
}

variable "base_snapshot" {
  type        = string
  default     = "base"
  description = "Snapshot taken of the powered-off template; linked clones are made from it"
}

variable "ready_snapshot" {
  type        = string
  default     = "ready"
  description = "Snapshot (with memory) of the booted, logged-on, idle victim; every detonation starts here"
}

variable "settle_seconds" {
  type        = number
  default     = 180
  description = "How long the fresh clone idles after logon before 'ready' is taken (lets start-up tasks finish)"
}

variable "gateway_vmx" {
  type        = string
  default     = ""
  description = "Optional: .vmx of the fake-internet VM (INetSim). Empty = do not manage it."
}
