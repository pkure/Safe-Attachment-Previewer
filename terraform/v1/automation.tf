# hal-id: #HAL-20261107-0015-PK-T5
# Orchestrator: Automation account with a managed identity.
#   Invoke-SandboxTriage : watches secops-triage Inbox/Sandbox, ships attachments to the sandbox, writes verdict mails.
#   Remove-PocResourceGroup : one-time schedule at `expires` deletes this whole resource group (forgot-to-teardown backstop).
# Mailbox access is NOT granted here: scripts/exchange-setup.ps1 grants "Application Mail.ReadWrite" through
# Exchange RBAC for Applications, scoped to mailboxes with CustomAttribute1 = sandbox-poc.

resource "azurerm_automation_account" "poc" {
  name                          = "aa-attsandbox"
  location                      = local.location
  resource_group_name           = azurerm_resource_group.poc.name
  sku_name                      = "Basic"
  public_network_access_enabled = true
  local_authentication_enabled  = false # no webhooks needed
  tags                          = local.tags
  identity {
    type = "SystemAssigned"
  }
}

# hal-debt: one identity does triage AND self-destruct, so it holds Contributor on this RG. Production: split them.
resource "azurerm_role_assignment" "aa_rg" {
  scope                = azurerm_resource_group.poc.id
  role_definition_name = "Contributor" # Run Command on the sandbox + delete the RG at expiry
  principal_id         = azurerm_automation_account.poc.identity[0].principal_id
}

resource "azurerm_role_assignment" "aa_blob" {
  scope                = azurerm_storage_account.cases.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_automation_account.poc.identity[0].principal_id
}

resource "azurerm_automation_runtime_environment" "ps74" {
  name                     = "PowerShell-74"
  automation_account_id    = azurerm_automation_account.poc.id
  location                 = local.location
  runtime_language         = "PowerShell"
  runtime_version          = "7.4"
  runtime_default_packages = { "az" = "12.3.0" } # API stores the key lowercase
  description              = "PowerShell 7.4 + Az"
  tags                     = { for k in ["owner", "project", "cost-center"] : k => local.tags[k] } # API max 3 tags
}

locals {
  runbook_vars = {
    TriageMailbox  = "secops-triage@${local.domain}"
    StorageAccount = azurerm_storage_account.cases.name
    SandboxVmName  = azurerm_windows_virtual_machine.sandbox.name
    ResourceGroup  = azurerm_resource_group.poc.name
    SubscriptionId = local.subscription_id
    # Sandbox has no DNS (network.tf), so the runbook pins the storage FQDN to the private endpoint in hosts.
    PrivateEndpointIp = azurerm_private_endpoint.blob.private_service_connection[0].private_ip_address
  }
}

resource "azurerm_automation_variable_string" "cfg" {
  for_each                = local.runbook_vars
  name                    = each.key
  resource_group_name     = azurerm_resource_group.poc.name
  automation_account_name = azurerm_automation_account.poc.name
  value                   = each.value
}

resource "azurerm_automation_runbook" "triage" {
  name                     = "Invoke-SandboxTriage"
  location                 = local.location
  resource_group_name      = azurerm_resource_group.poc.name
  automation_account_name  = azurerm_automation_account.poc.name
  runbook_type             = "PowerShell"
  runtime_environment_name = azurerm_automation_runtime_environment.ps74.name
  log_progress             = false
  log_verbose              = false
  description              = "Watch secops-triage Inbox/Sandbox and detonate attachments in vm-sandbox."
  content                  = file("${path.module}/../runbooks/Invoke-SandboxTriage.ps1")
  tags                     = local.tags
}

resource "azurerm_automation_runbook" "self_destruct" {
  name                     = "Remove-PocResourceGroup"
  location                 = local.location
  resource_group_name      = azurerm_resource_group.poc.name
  automation_account_name  = azurerm_automation_account.poc.name
  runbook_type             = "PowerShell"
  runtime_environment_name = azurerm_automation_runtime_environment.ps74.name
  log_progress             = false
  log_verbose              = false
  description              = "Deletes rg-attsandbox. Runs once at the expires time."
  content                  = file("${path.module}/../runbooks/Remove-PocResourceGroup.ps1")
  tags                     = local.tags
}

resource "azurerm_automation_schedule" "expires" {
  name                    = "at-expiry"
  resource_group_name     = azurerm_resource_group.poc.name
  automation_account_name = azurerm_automation_account.poc.name
  frequency               = "OneTime"
  start_time              = time_offset.expires.rfc3339
  timezone                = "Etc/UTC"
  description             = "Self-destruct backstop"
}

resource "azurerm_automation_job_schedule" "expires" {
  resource_group_name     = azurerm_resource_group.poc.name
  automation_account_name = azurerm_automation_account.poc.name
  schedule_name           = azurerm_automation_schedule.expires.name
  runbook_name            = azurerm_automation_runbook.self_destruct.name
}

# Test user who plays the analyst. Licensed by scripts/setup.sh once the Business Premium trial exists.
resource "random_password" "analyst1" {
  length      = 20
  special     = true
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
  min_special = 1
}

resource "azuread_user" "analyst1" {
  user_principal_name   = "analyst1@${local.domain}"
  display_name          = "Analyst One (sandbox POC)"
  mail_nickname         = "analyst1"
  password              = random_password.analyst1.result
  usage_location        = "US"
  force_password_change = false
}

output "automation_principal_id" {
  value = azurerm_automation_account.poc.identity[0].principal_id
}

# A new managed identity's service principal takes a minute or two to replicate in Entra; reading it
# immediately fails with "not found" (seen on first apply 2026-11-10).
resource "time_sleep" "aa_sp_replication" {
  create_duration = "120s"
  triggers        = { principal_id = azurerm_automation_account.poc.identity[0].principal_id }
}

data "azuread_service_principal" "aa" {
  object_id = time_sleep.aa_sp_replication.triggers["principal_id"]
}

output "automation_app_id" {
  value = data.azuread_service_principal.aa.client_id
}

output "storage_account" {
  value = azurerm_storage_account.cases.name
}

output "expires_utc" {
  value = time_offset.expires.rfc3339
}

output "vm_admin_user" {
  value = local.vm_admin
}

output "vm_admin_password" {
  value     = random_password.vm.result
  sensitive = true
}

output "analyst1_upn" {
  value = azuread_user.analyst1.user_principal_name
}

output "analyst1_password" {
  value     = random_password.analyst1.result
  sensitive = true
}
