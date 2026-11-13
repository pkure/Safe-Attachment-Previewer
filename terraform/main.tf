# hal-id: #HAL-20261113-0020-PK-I3
# Resource group, logs, storage, the Container Apps environment, and the two workload identities.

locals {
  tags = {
    owner         = "peter"
    project       = "safe-attachment-previewer"
    "cost-center" = "lab"
    managed-by    = "terraform"
  }
  portal_host = "ca-sap-portal.${azurerm_container_app_environment.env.default_domain}"
  public_url  = "https://${local.portal_host}"
  blob        = azurerm_storage_account.data.primary_blob_endpoint
  container_scope = {
    for c in ["cases", "results"] :
    c => "${azurerm_storage_account.data.id}/blobServices/default/containers/${c}"
  }
}

data "azurerm_client_config" "me" {}

resource "random_id" "suffix" {
  byte_length = 3
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-sap-lab"
  location = var.location
  tags     = local.tags
}

# ---------------------------------------------------------------- logs (audit trail: AU controls)
resource "azurerm_log_analytics_workspace" "logs" {
  name                = "log-sap-${random_id.suffix.hex}"
  resource_group_name = azurerm_resource_group.lab.name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  daily_quota_gb      = 0.5 # cost guard for a lab; production would size this to policy
  tags                = local.tags
}

# ---------------------------------------------------------------- storage (no keys, TLS 1.2+, double encryption)
resource "azurerm_storage_account" "data" {
  name                              = "stsap${random_id.suffix.hex}"
  resource_group_name               = azurerm_resource_group.lab.name
  location                          = var.location
  account_tier                      = "Standard"
  account_replication_type          = "LRS"
  account_kind                      = "StorageV2"
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false # Entra ID only: no account keys or SAS tokens can exist
  default_to_oauth_authentication   = true
  infrastructure_encryption_enabled = true # second layer of encryption at rest
  # Public endpoint, Entra-only. A private endpoint would move the Container Apps environment onto the Dedicated
  # plan's management fee (~$73/month); see docs/threat-model.md for the trade-off.
  public_network_access = "Enabled"
  blob_properties {
    delete_retention_policy {
      days = 1 # short safety net; retention is enforced by the lifecycle rule below
    }
  }
  tags = local.tags
}

resource "azurerm_storage_container" "c" {
  for_each              = local.container_scope
  name                  = each.key
  storage_account_id    = azurerm_storage_account.data.id
  container_access_type = "private"
}

resource "azurerm_storage_management_policy" "retention" {
  storage_account_id = azurerm_storage_account.data.id
  rule {
    name    = "delete-after-${var.retention_days}-days"
    enabled = true
    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["cases/", "results/"]
    }
    actions {
      base_blob {
        delete_after_days_since_creation_greater_than = var.retention_days
      }
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "blob" {
  name                       = "blob-to-logs"
  target_resource_id         = "${azurerm_storage_account.data.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id
  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }
}

# ---------------------------------------------------------------- Container Apps (consumption, scale to zero)
resource "azurerm_container_app_environment" "env" {
  name                       = "cae-sap-${random_id.suffix.hex}"
  resource_group_name        = azurerm_resource_group.lab.name
  location                   = var.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id
  tags                       = local.tags
}

# ---------------------------------------------------------------- identities (one per workload, least privilege)
resource "azurerm_user_assigned_identity" "job" {
  name                = "id-sap-render"
  resource_group_name = azurerm_resource_group.lab.name
  location            = var.location
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "portal" {
  name                = "id-sap-portal"
  resource_group_name = azurerm_resource_group.lab.name
  location            = var.location
  tags                = local.tags
}

# Render job: READ the case's email, WRITE results. It has no mailbox access and no way to start anything.
resource "azurerm_role_assignment" "job_read_cases" {
  scope                = local.container_scope["cases"]
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.job.principal_id
  depends_on           = [azurerm_storage_container.c]
}

resource "azurerm_role_assignment" "job_write_results" {
  scope                = local.container_scope["results"]
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.job.principal_id
  depends_on           = [azurerm_storage_container.c]
}

# Portal: drop emails into cases/, read and seed results/. Mailbox access is never its own: it acts for the analyst.
resource "azurerm_role_assignment" "portal_data" {
  for_each             = local.container_scope
  scope                = each.value
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.portal.principal_id
  depends_on           = [azurerm_storage_container.c]
}

# Portal may read and start the render job, and nothing else in Azure.
resource "azurerm_role_definition" "job_starter" {
  name        = "SAP render job starter (${random_id.suffix.hex})"
  scope       = azurerm_resource_group.lab.id
  description = "Read and start one Container Apps job."
  permissions {
    actions = ["Microsoft.App/jobs/read", "Microsoft.App/jobs/start/action"]
  }
  assignable_scopes = [azurerm_resource_group.lab.id]
}

resource "azurerm_role_assignment" "portal_start_job" {
  scope              = azurerm_container_app_job.render.id
  role_definition_id = azurerm_role_definition.job_starter.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.portal.principal_id
}
