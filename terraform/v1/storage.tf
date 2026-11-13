# hal-id: #HAL-20261107-0013-PK-T3
# Case storage. Entra-only (no shared keys). Containers:
#   tools   - offline toolkit for the sandbox (python + oletools + analyze.ps1), uploaded by scripts/stage-tools.sh
#   samples - benign test samples, uploaded by scripts/make-samples.py, injected into the mailbox by the runbook
#   cases   - attachment bytes per case (runbook writes, sandbox reads)
#   reports - report.json per case (sandbox writes, runbook reads)
# hal-debt: public endpoint stays on because cloud Automation jobs can't reach a private endpoint.
#           Production: Hybrid Runbook Worker / VNet-integrated Function, then public_network_access_enabled = false.

resource "azurerm_storage_account" "cases" {
  name                            = "stattsbx${random_id.suffix.hex}"
  resource_group_name             = azurerm_resource_group.poc.name
  location                        = local.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  shared_access_key_enabled       = false
  default_to_oauth_authentication = true
  allow_nested_items_to_be_public = false
  public_network_access           = "Enabled"
  tags                            = local.tags

  blob_properties {
    delete_retention_policy {
      days = 1
    }
  }
}

resource "azurerm_storage_container" "c" {
  for_each              = toset(["tools", "samples", "cases", "reports"])
  name                  = each.key
  storage_account_id    = azurerm_storage_account.cases.id
  container_access_type = "private"
}

# Peter's CLI identity uploads tools + samples.
resource "azurerm_role_assignment" "me_blob" {
  scope                = azurerm_storage_account.cases.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.me.object_id
}

resource "azurerm_private_dns_zone" "blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = azurerm_resource_group.poc.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  name                = "link-vnet-attsandbox"
  private_dns_zone_id = azurerm_private_dns_zone.blob.id
  virtual_network_id  = azurerm_virtual_network.poc.id
  tags                = local.tags
}

resource "azurerm_private_endpoint" "blob" {
  name                = "pe-blob"
  location            = local.location
  resource_group_name = azurerm_resource_group.poc.name
  subnet_id           = azurerm_subnet.sandbox.id
  tags                = local.tags

  private_service_connection {
    name                           = "psc-blob"
    private_connection_resource_id = azurerm_storage_account.cases.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob.id]
  }
}
