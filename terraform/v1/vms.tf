# hal-id: #HAL-20261107-0014-PK-T4
# Two Windows VMs, no public IPs. Reach both through Bastion.
#   vm-analyst : Windows 11 + Microsoft 365 Apps (classic Outlook preinstalled), stands in for an analyst PC.
#   vm-sandbox : Windows Server 2025, offline, does the analysis.

resource "random_password" "vm" {
  length           = 24
  special          = true
  override_special = "!@#%*-_=+"
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
}

locals {
  vm_admin = "labadmin"
}

resource "azurerm_network_interface" "analyst" {
  name                = "nic-analyst"
  location            = local.location
  resource_group_name = azurerm_resource_group.poc.name
  tags                = local.tags
  ip_configuration {
    name                          = "ipconfig"
    subnet_id                     = azurerm_subnet.analyst.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_windows_virtual_machine" "analyst" {
  name                  = "vm-analyst"
  computer_name         = "ANALYST01"
  location              = local.location
  resource_group_name   = azurerm_resource_group.poc.name
  size                  = var.vm_size
  admin_username        = local.vm_admin
  admin_password        = random_password.vm.result
  network_interface_ids = [azurerm_network_interface.analyst.id]
  license_type          = "Windows_Client" # Business Premium includes Windows 11 Business/Enterprise rights
  secure_boot_enabled   = true
  vtpm_enabled          = true
  patch_mode            = "AutomaticByOS"
  tags                  = local.tags

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsDesktop"
    offer     = "office-365"
    sku       = "win11-25h2-avd-m365" # multi-session image with Microsoft 365 Apps (classic Outlook) baked in
    version   = "latest"
  }
}

resource "azurerm_network_interface" "sandbox" {
  name                = "nic-sandbox"
  location            = local.location
  resource_group_name = azurerm_resource_group.poc.name
  tags                = local.tags
  ip_configuration {
    name                          = "ipconfig"
    subnet_id                     = azurerm_subnet.sandbox.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_windows_virtual_machine" "sandbox" {
  name                      = "vm-sandbox"
  computer_name             = "SANDBOX01"
  location                  = local.location
  resource_group_name       = azurerm_resource_group.poc.name
  size                      = var.vm_size
  admin_username            = local.vm_admin
  admin_password            = random_password.vm.result
  network_interface_ids     = [azurerm_network_interface.sandbox.id]
  secure_boot_enabled       = true
  vtpm_enabled              = true
  patch_mode                = "Manual" # offline: Windows Update can't reach anything anyway
  automatic_updates_enabled = false    # required with patch_mode Manual (API 400 otherwise)
  tags                      = local.tags

  identity {
    type = "SystemAssigned" # pulls cases / pushes reports via the private endpoint
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2025-datacenter-g2"
    version   = "latest"
  }

  depends_on = [azurerm_private_endpoint.blob] # DNS must resolve privately from first boot
}

resource "azurerm_role_assignment" "sandbox_read_tools" {
  for_each             = toset(["tools", "cases"])
  scope                = azurerm_storage_container.c[each.key].id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_windows_virtual_machine.sandbox.identity[0].principal_id
}

resource "azurerm_role_assignment" "sandbox_write_reports" {
  scope                = azurerm_storage_container.c["reports"].id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_windows_virtual_machine.sandbox.identity[0].principal_id
}
