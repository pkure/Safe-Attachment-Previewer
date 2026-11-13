# hal-id: #HAL-20261113-0023-PK-I6
output "portal_url" {
  value = local.public_url
}

output "addin_manifest_url" {
  description = "Sideload this in Outlook, or upload it in Microsoft 365 admin center > Integrated apps."
  value       = "${local.public_url}/addin/manifest.xml"
}

output "app_client_id" {
  value = azuread_application.sap.client_id
}

output "storage_account" {
  value = azurerm_storage_account.data.name
}

output "log_workspace" {
  value = azurerm_log_analytics_workspace.logs.name
}

output "render_job" {
  value = azurerm_container_app_job.render.name
}

output "analyst_pc" {
  description = "Connect: Azure portal > vm-analyst > Connect > Bastion. Local admin 'labadmin' (password: scripts/cloud.sh vm-password)."
  value       = var.analyst_pc ? azurerm_windows_virtual_machine.analyst[0].name : "not created"
}

output "vm_admin_password" {
  value     = random_password.vm.result
  sensitive = true
}
