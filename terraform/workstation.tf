# hal-id: #HAL-20261113-0027-PK-W1
# Lab analyst PC (optional, var.analyst_pc): Windows 11 + Microsoft 365 Apps (classic Outlook), the same OS and mail
# client the security team uses. It only ever SEES previews; attachments are never opened here.
# No public IP: reach it through Bastion Developer (free) in the Azure portal. Shuts down every evening; start it when
# you want it. Cost: ~$0.10/h while running (Windows client rights come with Microsoft 365 Business Premium, so it is
# billed at the Linux rate) + ~$10/month for its disk while it exists.

resource "azurerm_virtual_network" "lab" {
  count               = var.analyst_pc ? 1 : 0
  name                = "vnet-sap-lab"
  location            = var.location
  resource_group_name = azurerm_resource_group.lab.name
  address_space       = ["10.60.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "analyst" {
  count                           = var.analyst_pc ? 1 : 0
  name                            = "snet-analyst"
  resource_group_name             = azurerm_resource_group.lab.name
  virtual_network_name            = azurerm_virtual_network.lab[0].name
  address_prefixes                = ["10.60.1.0/24"]
  default_outbound_access_enabled = true # Outlook needs Exchange Online; free default outbound (no NAT gateway)
}

resource "azurerm_network_security_group" "analyst" {
  count               = var.analyst_pc ? 1 : 0
  name                = "nsg-analyst"
  location            = var.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
  # Defaults: inbound only from inside the VNet (Bastion), nothing public points in.
}

resource "azurerm_subnet_network_security_group_association" "analyst" {
  count                     = var.analyst_pc ? 1 : 0
  subnet_id                 = azurerm_subnet.analyst[0].id
  network_security_group_id = azurerm_network_security_group.analyst[0].id
}

resource "azurerm_bastion_host" "lab" {
  count               = var.analyst_pc ? 1 : 0
  name                = "bas-sap-lab"
  location            = var.location
  resource_group_name = azurerm_resource_group.lab.name
  sku                 = "Developer" # free; browser RDP from the Azure portal
  virtual_network_id  = azurerm_virtual_network.lab[0].id
  tags                = local.tags
}

resource "random_password" "vm" {
  length           = 24
  special          = true
  override_special = "!@#%*-_=+"
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "azurerm_network_interface" "analyst" {
  count               = var.analyst_pc ? 1 : 0
  name                = "nic-analyst"
  location            = var.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
  ip_configuration {
    name                          = "ipconfig"
    subnet_id                     = azurerm_subnet.analyst[0].id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_windows_virtual_machine" "analyst" {
  count                 = var.analyst_pc ? 1 : 0
  name                  = "vm-analyst"
  computer_name         = "ANALYST01"
  location              = var.location
  resource_group_name   = azurerm_resource_group.lab.name
  size                  = var.vm_size
  admin_username        = "labadmin"
  admin_password        = random_password.vm.result
  network_interface_ids = [azurerm_network_interface.analyst[0].id]
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
    sku       = "win11-25h2-avd-m365" # Windows 11 with Microsoft 365 Apps (classic Outlook) preinstalled
    version   = "latest"
  }
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "analyst" {
  count                 = var.analyst_pc ? 1 : 0
  virtual_machine_id    = azurerm_windows_virtual_machine.analyst[0].id
  location              = var.location
  enabled               = true
  daily_recurrence_time = var.shutdown_time
  timezone              = "Pacific Standard Time"
  notification_settings {
    enabled = false
  }
  tags = local.tags
}
