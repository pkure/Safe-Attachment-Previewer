# hal-id: #HAL-20261113-0018-PK-I1
# Cloud lab (v2): Outlook add-in -> portal -> one offline render job per email. Everything Azure lives in ONE resource
# group; the Entra app registration is the only tenant-level object. Tenant values come from terraform.tfvars and
# backend.hcl (both gitignored; copy the *.example files).

terraform {
  required_version = ">= 1.11"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.13"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.10"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }
  backend "azurerm" {} # partial config: terraform init -backend-config=backend.hcl
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false # teardown must always succeed
    }
  }
  tenant_id           = var.tenant_id
  subscription_id     = var.subscription_id
  storage_use_azuread = true # the storage account has no access keys at all
}

provider "azuread" {
  tenant_id = var.tenant_id
}
