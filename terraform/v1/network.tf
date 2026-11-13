# hal-id: #HAL-20261107-0012-PK-T2
# analyst subnet: normal internet (Outlook needs Exchange Online).
# sandbox subnet: NO internet and NO DNS. Only the storage private endpoint + the Azure platform IP on the
#   VM-agent ports. DNS is denied because Azure-provided DNS resolves public names, so malware could tunnel data
#   out through DNS queries even with all other egress blocked. The sandbox finds its storage endpoint through a
#   hosts-file entry written by the runbook (see automation.tf: PrivateEndpointIp).

resource "azurerm_virtual_network" "poc" {
  name                = "vnet-attsandbox"
  location            = local.location
  resource_group_name = azurerm_resource_group.poc.name
  address_space       = ["10.50.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "analyst" {
  name                            = "snet-analyst"
  resource_group_name             = azurerm_resource_group.poc.name
  virtual_network_name            = azurerm_virtual_network.poc.name
  address_prefixes                = ["10.50.1.0/24"]
  default_outbound_access_enabled = true # free outbound for Outlook; new VNets default to private subnets
}

resource "azurerm_subnet" "sandbox" {
  name                            = "snet-sandbox"
  resource_group_name             = azurerm_resource_group.poc.name
  virtual_network_name            = azurerm_virtual_network.poc.name
  address_prefixes                = ["10.50.2.0/24"]
  default_outbound_access_enabled = false # no implicit internet route at all
}

resource "azurerm_subnet" "bastion" {
  name                 = "AzureBastionSubnet" # only used by the Basic SKU; free to keep
  resource_group_name  = azurerm_resource_group.poc.name
  virtual_network_name = azurerm_virtual_network.poc.name
  address_prefixes     = ["10.50.250.0/26"]
}

resource "azurerm_network_security_group" "sandbox" {
  name                = "nsg-sandbox"
  location            = local.location
  resource_group_name = azurerm_resource_group.poc.name
  tags                = local.tags

  security_rule {
    name                       = "allow-blob-private-endpoint"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "10.50.2.0/24" # the private endpoint NIC lives in this subnet
    destination_port_range     = "443"
  }

  security_rule {
    name                       = "deny-azure-dns"
    priority                   = 105
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "AzurePlatformDNS" # closes the DNS-tunneling exfil path (MS-documented method)
    destination_port_range     = "*"
  }

  security_rule {
    name                       = "allow-azure-platform-agent"
    priority                   = 110
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "168.63.129.16" # WireServer (80) + HostGAPlugin (32526): VM agent, Run Command, extensions
    destination_port_ranges    = ["80", "32526"] # IMDS (169.254.169.254) is link-local and never NSG-filtered
  }

  security_rule {
    name                       = "deny-all-outbound"
    priority                   = 4000
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }

  security_rule {
    name                       = "allow-bastion-rdp-in"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "VirtualNetwork" # Bastion (Basic: AzureBastionSubnet; Developer: platform-managed)
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "3389"
  }
}

resource "azurerm_subnet_network_security_group_association" "sandbox" {
  subnet_id                 = azurerm_subnet.sandbox.id
  network_security_group_id = azurerm_network_security_group.sandbox.id
}

resource "azurerm_network_security_group" "analyst" {
  name                = "nsg-analyst"
  location            = local.location
  resource_group_name = azurerm_resource_group.poc.name
  tags                = local.tags
  # Defaults: inbound only from VirtualNetwork (Bastion), outbound to internet allowed. Nothing public points in.
}

resource "azurerm_subnet_network_security_group_association" "analyst" {
  subnet_id                 = azurerm_subnet.analyst.id
  network_security_group_id = azurerm_network_security_group.analyst.id
}

resource "azurerm_public_ip" "bastion" {
  count               = var.bastion_sku == "Basic" ? 1 : 0
  name                = "pip-bastion"
  location            = local.location
  resource_group_name = azurerm_resource_group.poc.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_bastion_host" "poc" {
  name                = "bas-attsandbox"
  location            = local.location
  resource_group_name = azurerm_resource_group.poc.name
  sku                 = var.bastion_sku
  virtual_network_id  = var.bastion_sku == "Developer" ? azurerm_virtual_network.poc.id : null
  # Text copy/paste stays on (default) so analyst1's password can be pasted into Outlook.
  # File transfer is off (default; needs Standard SKU anyway), so files can't leave the sandbox through Bastion.
  tags = local.tags

  dynamic "ip_configuration" {
    for_each = var.bastion_sku == "Basic" ? [1] : []
    content {
      name                 = "ipconfig"
      subnet_id            = azurerm_subnet.bastion.id
      public_ip_address_id = azurerm_public_ip.bastion[0].id
    }
  }
}
