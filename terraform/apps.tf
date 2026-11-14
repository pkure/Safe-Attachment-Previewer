# hal-id: #HAL-20261113-0022-PK-I5
# The render job (one execution per email, offline renderer) and the portal (add-in backend + viewer).

resource "azurerm_container_app_job" "render" {
  name                         = "caj-sap-render"
  resource_group_name          = azurerm_resource_group.lab.name
  location                     = var.location
  container_app_environment_id = azurerm_container_app_environment.env.id
  workload_profile_name        = "Consumption"
  replica_timeout_in_seconds   = 900
  replica_retry_limit          = 0 # a failed case is reported, never silently re-run
  tags                         = local.tags

  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.job.id]
  }

  template {
    container {
      name    = "engine"
      image   = var.engine_image
      cpu     = 2
      memory  = "4Gi"
      command = ["python", "-m", "saferender.fetcher"]
      env {
        name  = "SAFERENDER_STORE"
        value = "blob:${trimsuffix(local.blob, "/")}"
      }
      env {
        name  = "AZURE_CLIENT_ID"
        value = azurerm_user_assigned_identity.job.client_id
      }
      env {
        name  = "IMAGE_TAG"
        value = var.engine_image
      }
      env {
        name  = "SAFERENDER_ORG_DOMAINS"
        value = var.org_domains
      }
      env {
        name  = "SAFERENDER_SIMPLE"
        value = var.simple_mode ? "1" : "0"
      }
    }
  }

  depends_on = [azurerm_role_assignment.job_read_cases, azurerm_role_assignment.job_write_results]
}

resource "random_password" "session" {
  length  = 48
  special = false
}

resource "azurerm_container_app" "portal" {
  name                         = "ca-sap-portal"
  resource_group_name          = azurerm_resource_group.lab.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  workload_profile_name        = "Consumption"
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.portal.id]
  }

  secret {
    name  = "session-secret"
    value = random_password.session.result
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = 0 # nothing runs (or bills) while nobody is using it
    max_replicas = 2
    container {
      name   = "portal"
      image  = var.portal_image
      cpu    = 0.5
      memory = "1Gi"
      env {
        name  = "TENANT_ID"
        value = var.tenant_id
      }
      env {
        name  = "CLIENT_ID"
        value = azuread_application.sap.client_id
      }
      env {
        name  = "PUBLIC_URL"
        value = local.public_url
      }
      env {
        name  = "STORE"
        value = "blob:${trimsuffix(local.blob, "/")}"
      }
      env {
        name  = "JOB_ID"
        value = azurerm_container_app_job.render.id
      }
      env {
        name  = "AZURE_CLIENT_ID"
        value = azurerm_user_assigned_identity.portal.client_id
      }
      env {
        name        = "SESSION_SECRET"
        secret_name = "session-secret"
      }
      env {
        name  = "LAB_MAILBOXES"
        value = var.lab_mailboxes
      }
      env {
        name  = "ADDIN_ID"
        value = random_uuid.addin_id.result
      }
      env {
        name  = "RETENTION_DAYS"
        value = tostring(var.retention_days)
      }
      liveness_probe {
        transport = "HTTP"
        path      = "/healthz"
        port      = 8000
      }
    }
  }
}
