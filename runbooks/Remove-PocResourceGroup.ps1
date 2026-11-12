# hal-id: #HAL-20261107-0016-PK-R1
# Self-destruct backstop: deletes rg-attsandbox (including this Automation account).
# ARM DELETE returns 202 and keeps going server-side even after this job's own account disappears.
$ErrorActionPreference = 'Stop'
Connect-AzAccount -Identity | Out-Null
$sub = Get-AutomationVariable -Name SubscriptionId
$rg  = Get-AutomationVariable -Name ResourceGroup
if ($rg -ne 'rg-attsandbox') { throw "Refusing to delete unexpected resource group '$rg'" }
$path = "/subscriptions/$sub/resourcegroups/$rg`?api-version=2021-04-01"
$r = Invoke-AzRestMethod -Method DELETE -Path $path
"DELETE $rg -> HTTP $($r.StatusCode)"
if ($r.StatusCode -notin 200, 202) { throw $r.Content }
