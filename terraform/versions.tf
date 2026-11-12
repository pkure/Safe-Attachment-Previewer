# hal-id: #HAL-20261107-0011-PK-T1
# Attachment sandbox. Everything lives in ONE resource group so teardown (or the self-destruct schedule)
# removes all of it. Tenant-specific values come from terraform.tfvars + backend.hcl (both gitignored);
# copy the *.example files to start.

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
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
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
  tenant_id           = local.tenant_id
  subscription_id     = local.subscription_id
  storage_use_azuread = true
}

provider "azuread" {
  tenant_id = local.tenant_id
}

variable "tenant_id" {
  description = "Entra tenant that holds both the Azure subscription and Exchange Online."
  type        = string
}

variable "subscription_id" {
  type = string
}

variable "domain" {
  description = "Mail domain for the test users and the triage mailbox, e.g. contoso.onmicrosoft.com."
  type        = string
}

variable "location" {
  type    = string
  default = "eastus2"
}

locals {
  tenant_id       = var.tenant_id
  subscription_id = var.subscription_id
  location        = var.location
  domain          = var.domain
  tags = {
    owner         = "peter"
    project       = "attachment-sandbox"
    "cost-center" = "lab"
    managed-by    = "terraform"
    expires       = time_offset.expires.rfc3339
  }
}

variable "ttl_hours" {
  description = "Hours after apply when the self-destruct schedule deletes the whole resource group."
  type        = number
  default     = 8
  validation {
    condition     = var.ttl_hours >= 1 && var.ttl_hours <= 24
    error_message = "ttl_hours must be 1-24 (this is a short-lived demo)."
  }
}

variable "bastion_sku" {
  description = "Developer is free but only in some regions; fall back to Basic ($0.19/h) if apply rejects it."
  type        = string
  default     = "Developer"
  validation {
    condition     = contains(["Developer", "Basic"], var.bastion_sku)
    error_message = "bastion_sku must be Developer or Basic."
  }
}

variable "vm_size" {
  type    = string
  default = "Standard_D2as_v7" # 2 vCPU / 8 GB; v7 is what this subscription offers in eastus2
}

resource "time_offset" "expires" {
  offset_hours = var.ttl_hours
}

data "azurerm_client_config" "me" {}

resource "random_id" "suffix" {
  byte_length = 3
}

resource "azurerm_resource_group" "poc" {
  name     = "rg-attsandbox"
  location = local.location
  tags     = local.tags
  lifecycle {
    ignore_changes = [tags["expires"]]
  }
}
