# hal-id: #HAL-20261113-0019-PK-I2
variable "tenant_id" {
  description = "Entra tenant that holds the Azure subscription and Exchange Online."
  type        = string
}

variable "subscription_id" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus2"
}

variable "engine_image" {
  description = "Render engine image (public GHCR, rebuilt nightly with fresh signatures)."
  type        = string
  default     = "ghcr.io/pkure/safe-attachment-previewer:latest"
}

variable "portal_image" {
  description = "Portal image (add-in backend + viewer)."
  type        = string
  default     = "ghcr.io/pkure/safe-attachment-previewer:portal-latest"
}

variable "analyst_group_name" {
  description = "Entra security group allowed to use the tool. Best practice: the SAME group that has Full Access to the shared mailbox (a mail-enabled security group), so one membership controls both."
  type        = string
  default     = ""
}

variable "lab_mailboxes" {
  description = "Shared mailbox address(es) to try when Outlook doesn't report the mailbox (comma separated). Access is still the analyst's own."
  type        = string
  default     = ""
}

variable "org_domains" {
  description = "The organization's own domains, for lookalike-domain flags (comma separated)."
  type        = string
  default     = ""
}

variable "simple_mode" {
  description = "true = page images, text and links only (heuristic findings switched off)."
  type        = bool
  default     = false
}

variable "retention_days" {
  description = "Emails and previews are deleted automatically after this many days."
  type        = number
  default     = 7
  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 90
    error_message = "retention_days must be 1-90."
  }
}

variable "log_retention_days" {
  description = "Audit and platform logs in Log Analytics."
  type        = number
  default     = 30
}
