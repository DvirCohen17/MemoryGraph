# Creates the lab VMs on VMware Workstation from the Packer templates.
#
# Workstation has no official Terraform provider, and the community ones talk to the vmrest API, which
# cannot clone from a snapshot or take memory snapshots. So each VM is a terraform_data resource whose
# create/destroy steps call VMware's own `vmrun` tool (scripts/victim.ps1). `terraform apply` builds the
# lab, `terraform destroy` deletes the VMs; the templates are never changed except for one "base" snapshot.
#
# Per guest it makes a LINKED clone (a few GB instead of a full copy), boots it on the isolated network,
# waits until Windows has logged on and VMware Tools answer, and takes the snapshot "ready" with memory.
# Every detonation starts from "ready" and is thrown away afterwards.

terraform {
  required_version = ">= 1.4.0" # terraform_data
}

locals {
  guests = { for name in var.guests : name => {
    template_vmx = "${var.templates_root}/${name}-template/${name}-template.vmx"
    clone_vmx    = "${var.vms_root}/victim-${name}/victim-${name}.vmx"
    clone_name   = "victim-${name}"
  } }
  script = "${path.module}/scripts/victim.ps1"
}

resource "terraform_data" "victim" {
  for_each = local.guests

  # Changing any of these re-creates the clone.
  input = {
    vmrun          = var.vmrun_path
    script         = abspath(local.script)
    template_vmx   = each.value.template_vmx
    clone_vmx      = each.value.clone_vmx
    clone_name     = each.value.clone_name
    lab_vnet       = var.lab_vnet
    base_snapshot  = var.base_snapshot
    ready_snapshot = var.ready_snapshot
    settle_seconds = var.settle_seconds
  }

  provisioner "local-exec" {
    interpreter = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
    command     = "& '${self.input.script}' -Action create -Vmrun '${self.input.vmrun}' -TemplateVmx '${self.input.template_vmx}' -CloneVmx '${self.input.clone_vmx}' -CloneName '${self.input.clone_name}' -LabVnet '${self.input.lab_vnet}' -BaseSnapshot '${self.input.base_snapshot}' -ReadySnapshot '${self.input.ready_snapshot}' -SettleSeconds ${self.input.settle_seconds}"
    environment = {
      LAB_GUEST_USER     = var.guest_user
      LAB_GUEST_PASSWORD = var.guest_password
    }
  }

  provisioner "local-exec" {
    when        = destroy
    interpreter = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
    command     = "& '${self.input.script}' -Action destroy -Vmrun '${self.input.vmrun}' -CloneVmx '${self.input.clone_vmx}'"
  }

  depends_on = [terraform_data.gateway]
}

# Optional: the fake-internet VM (for example REMnux with INetSim, see lab/gateway/README.md).
# Terraform only starts and stops it; it is imported into Workstation once by hand.
resource "terraform_data" "gateway" {
  count = var.gateway_vmx == "" ? 0 : 1

  input = {
    vmrun  = var.vmrun_path
    script = abspath(local.script)
    vmx    = var.gateway_vmx
    vnet   = var.lab_vnet
  }

  provisioner "local-exec" {
    interpreter = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
    command     = "& '${self.input.script}' -Action gateway-start -Vmrun '${self.input.vmrun}' -CloneVmx '${self.input.vmx}' -LabVnet '${self.input.vnet}'"
  }

  provisioner "local-exec" {
    when        = destroy
    interpreter = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
    command     = "& '${self.input.script}' -Action gateway-stop -Vmrun '${self.input.vmrun}' -CloneVmx '${self.input.vmx}'"
  }
}
