# hal-id: #HAL-20261113-0021-PK-I4
# Entra app registration: the add-in signs analysts in with it (nested app auth), the portal signs browsers in with
# it, and the portal uses it to act ON BEHALF OF the analyst (Mail.Read.Shared, delegated). There is no application
# permission and no client secret: the portal proves the app's identity with its managed identity.

data "azuread_application_published_app_ids" "well_known" {}

data "azuread_service_principal" "graph" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
}

resource "random_uuid" "scope_access_as_user" {}
resource "random_uuid" "role_previewer" {}
resource "random_uuid" "addin_id" {}

locals {
  graph_delegated = ["Mail.Read.Shared", "User.Read", "openid", "profile", "offline_access"]
}

resource "azuread_application" "sap" {
  display_name     = "Safe Attachment Previewer (lab)"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azurerm_client_config.me.object_id]

  api {
    requested_access_token_version = 2
    oauth2_permission_scope {
      id                         = random_uuid.scope_access_as_user.result
      value                      = "access_as_user"
      type                       = "User"
      enabled                    = true
      admin_consent_display_name = "Use Safe Attachment Previewer"
      admin_consent_description  = "Lets the Outlook add-in call the previewer as the signed-in analyst."
      user_consent_display_name  = "Use Safe Attachment Previewer"
      user_consent_description   = "Lets the Outlook add-in call the previewer as you."
    }
  }

  app_role {
    id                   = random_uuid.role_previewer.result
    value                = "Previewer.Use"
    display_name         = "Use Safe Attachment Previewer"
    description          = "Can send emails from mailboxes they can already read to the safe previewer."
    allowed_member_types = ["User"]
    enabled              = true
  }

  # Nested app auth (the add-in inside Outlook) uses the brk-multihub broker redirect; set in entra_redirects below
  # because it isn't an https URI. The browser fallback and viewer sign-in use the web redirect.
  web {
    redirect_uris = ["${local.public_url}/auth/callback"]
    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false
    }
  }

  required_resource_access {
    resource_app_id = data.azuread_service_principal.graph.client_id
    dynamic "resource_access" {
      for_each = local.graph_delegated
      content {
        id   = data.azuread_service_principal.graph.oauth2_permission_scope_ids[resource_access.value]
        type = "Scope"
      }
    }
  }

  lifecycle {
    ignore_changes = [single_page_application, identifier_uris]
  }
}

resource "azuread_application_identifier_uri" "sap" {
  application_id = azuread_application.sap.id
  identifier_uri = "api://${azuread_application.sap.client_id}"
}

# The brk-multihub redirect (a custom scheme) is set through Graph directly.
resource "terraform_data" "entra_redirects" {
  triggers_replace = [azuread_application.sap.object_id, local.portal_host]
  provisioner "local-exec" {
    command = <<-EOT
      az rest --method PATCH \
        --url "https://graph.microsoft.com/v1.0/applications/${azuread_application.sap.object_id}" \
        --headers "Content-Type=application/json" \
        --body '{"spa":{"redirectUris":["brk-multihub://${local.portal_host}"]}}'
    EOT
  }
}

resource "azuread_service_principal" "sap" {
  client_id                    = azuread_application.sap.client_id
  app_role_assignment_required = true # only people (groups) assigned the role can get a token at all
  owners                       = [data.azurerm_client_config.me.object_id]
}

# Admin consent for the delegated Graph permissions (what an IT admin approves once for the organization).
resource "azuread_service_principal_delegated_permission_grant" "graph" {
  service_principal_object_id          = azuread_service_principal.sap.object_id
  resource_service_principal_object_id = data.azuread_service_principal.graph.object_id
  claim_values                         = local.graph_delegated
}

# The add-in (same app) calling its own API.
resource "azuread_service_principal_delegated_permission_grant" "self" {
  service_principal_object_id          = azuread_service_principal.sap.object_id
  resource_service_principal_object_id = azuread_service_principal.sap.object_id
  claim_values                         = ["access_as_user"]
}

# No secret: the portal's managed identity is the app's credential (workload identity federation).
resource "azuread_application_federated_identity_credential" "portal" {
  application_id = azuread_application.sap.id
  display_name   = "portal-managed-identity"
  description    = "Container App id-sap-portal acts as this app (no client secret exists)."
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://login.microsoftonline.com/${var.tenant_id}/v2.0"
  subject        = azurerm_user_assigned_identity.portal.principal_id
}

data "azuread_group" "analysts" {
  count            = var.analyst_group_name == "" ? 0 : 1
  display_name     = var.analyst_group_name
  security_enabled = true
}

resource "azuread_app_role_assignment" "analysts" {
  count               = var.analyst_group_name == "" ? 0 : 1
  app_role_id         = random_uuid.role_previewer.result
  principal_object_id = data.azuread_group.analysts[0].object_id
  resource_object_id  = azuread_service_principal.sap.object_id
}
