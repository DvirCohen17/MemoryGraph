output "victims" {
  description = "Paste these into orchestrator/lab.toml ([guests.<name>] vmx = ...)"
  value       = { for name, g in local.guests : name => g.clone_vmx }
}

output "ready_snapshot" {
  value = var.ready_snapshot
}
