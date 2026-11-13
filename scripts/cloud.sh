#!/usr/bin/env bash
# hal-id: #HAL-20261113-0026-PK-C1
# Cloud v2 lab (Terraform in terraform/). Needs: az login as a tenant admin, terraform/backend.hcl + terraform/terraform.tfvars.
#   scripts/cloud.sh plan | up | down | status | logs | vm-password | vm-start | vm-stop
set -euo pipefail
cd "$(dirname "$0")/.."
TF="terraform -chdir=terraform"
$TF init -input=false -backend-config=backend.hcl >/dev/null
case "${1:-}" in
  plan)   $TF plan -input=false ;;
  up)     $TF apply -input=false; $TF output ;;
  down)   $TF destroy -input=false ;;
  status) $TF output ;;
  logs)   # last hour of audit lines from the portal
    ws=$($TF output -raw log_workspace)
    id=$(az monitor log-analytics workspace show -g rg-sap-lab -n "$ws" --query customerId -o tsv)
    az monitor log-analytics query -w "$id" -o table --analytics-query \
      "ContainerAppConsoleLogs_CL | where TimeGenerated > ago(1h) and Log_s has '\"audit\"' | project TimeGenerated, Log_s | order by TimeGenerated desc" ;;
  vm-password) # into the macOS Keychain, never to the screen
    security add-generic-password -U -a labadmin -s "SAP lab vm-analyst labadmin" -w "$($TF output -raw vm_admin_password)"
    echo 'saved to Keychain: "SAP lab vm-analyst labadmin"' ;;
  vm-start) az vm start -g rg-sap-lab -n vm-analyst -o none && echo "vm-analyst running (auto-shutdown 7 PM Pacific)" ;;
  vm-stop)  az vm deallocate -g rg-sap-lab -n vm-analyst -o none && echo "vm-analyst deallocated (no compute cost)" ;;
  *) sed -n 2,4p "$0"; exit 1 ;;
esac
