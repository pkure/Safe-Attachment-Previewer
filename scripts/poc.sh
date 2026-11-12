#!/usr/bin/env bash
# hal-id: #HAL-20261107-0022-PK-S3
# One entry point for the POC. See attachment-sandbox_how-to.md.
#   poc.sh plan       terraform plan (creates nothing)
#   poc.sh up         terraform apply (COSTS MONEY while up, ~$0.40-0.60/h)
#   poc.sh license    give analyst1 a Business Premium license (after the trial exists)
#   poc.sh stage      upload tools.zip + samples to storage
#   poc.sh inject     create the 4 test-sample emails in secops-triage
#   poc.sh watch [N]  run the triage watcher for N minutes (default 90)
#   poc.sh status     show what exists and when it self-destructs
#   poc.sh meter      live cost meter (estimate: list price x uptime), Ctrl-C to stop
#   poc.sh cost-actual [days]  real billed cost for the RG from Cost Management (lags 8-24 h)
#   poc.sh secrets    print VM + analyst1 passwords
#   poc.sh down       terraform destroy + verify nothing is left
set -euo pipefail
cd "$(dirname "$0")/.."
TF="terraform -chdir=terraform"
RG=rg-attsandbox
AA=aa-attsandbox

out() { $TF output -raw "$1"; }

start_runbook() { # args = KEY=VALUE runbook parameters
  local job
  job=$(az automation runbook start -g "$RG" --automation-account-name "$AA" -n Invoke-SandboxTriage \
    --parameters "$@" --query jobId -o tsv)
  echo "runbook job $job started"
  echo "$job"
}

case "${1:-}" in
  plan) $TF init -input=false -upgrade -reconfigure -backend-config=backend.hcl >/dev/null && $TF plan -input=false -out=tfplan ;;
  up) $TF apply -input=false tfplan && $TF output ;;
  license)
    sku=$(az rest --method get --url https://graph.microsoft.com/v1.0/subscribedSkus \
      --query "value[?skuPartNumber=='SPB' || contains(skuPartNumber,'BUSINESS_PREMIUM')].skuId | [0]" -o tsv)
    [[ -n $sku ]] || { echo "No Business Premium license (SPB or BUSINESS_PREMIUM*) in the tenant yet - start the trial first."; exit 1; }
    az rest --method post --url "https://graph.microsoft.com/v1.0/users/$(out analyst1_upn)/assignLicense" \
      --body "{\"addLicenses\":[{\"skuId\":\"$sku\"}],\"removeLicenses\":[]}" --query userPrincipalName -o tsv
    ;;
  stage)
    [[ -f dist/tools.zip ]] || bash scripts/build.sh
    acct=$(out storage_account)
    az storage blob upload --auth-mode login --account-name "$acct" -c tools -n tools.zip -f dist/tools.zip --overwrite -o none
    az storage blob upload-batch --auth-mode login --account-name "$acct" -d samples -s dist/samples --overwrite -o none
    az storage blob list --auth-mode login --account-name "$acct" -c samples --query "[].name" -o tsv
    ;;
  inject) start_runbook Mode=Inject ;;
  watch) start_runbook Mode=Watch MaxMinutes="${2:-90}" ;;
  status)
    az group exists -n "$RG"
    az resource list -g "$RG" --query "[].{name:name,type:type}" -o table 2>/dev/null || true
    az group show -n "$RG" --query tags.expires -o tsv 2>/dev/null | sed 's/^/self-destruct at (UTC): /' || true
    ;;
  meter) python3 -I scripts/cost_meter.py --rg "$RG" "${@:2}" ;;
  cost-actual)
    sub=$(az account show --query id -o tsv)
    from=$(date -u -v-"${2:-3}"d +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -d "-${2:-3} days" +%Y-%m-%dT00:00:00Z)
    to=$(date -u +%Y-%m-%dT23:59:59Z)
    az rest --method post --url "https://management.azure.com/subscriptions/$sub/providers/Microsoft.CostManagement/query?api-version=2023-11-01" \
      --body "{\"type\":\"ActualCost\",\"timeframe\":\"Custom\",\"timePeriod\":{\"from\":\"$from\",\"to\":\"$to\"},\"dataset\":{\"granularity\":\"None\",\"aggregation\":{\"cost\":{\"name\":\"Cost\",\"function\":\"Sum\"}},\"grouping\":[{\"type\":\"Dimension\",\"name\":\"MeterCategory\"}],\"filter\":{\"dimensions\":{\"name\":\"ResourceGroupName\",\"operator\":\"In\",\"values\":[\"$RG\"]}}}}" \
      --query "properties.rows" -o tsv | awk -F'\t' '{printf "  %-28s $%.4f\n", $2, $1; t+=$1} END {printf "  %-28s $%.4f\n", "TOTAL (billed)", t}'
    ;;
  secrets)
    echo "VM login (both VMs): $(out vm_admin_user) / $(out vm_admin_password)"
    echo "Outlook login:       $(out analyst1_upn) / $(out analyst1_password)"
    ;;
  down)
    $TF destroy -input=false -auto-approve
    echo "resource group still exists? $(az group exists -n "$RG")"
    ;;
  *) sed -n '3,15p' "$0"; exit 1 ;;
esac
