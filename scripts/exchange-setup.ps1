# hal-id: #HAL-20261107-0021-PK-E1
# One-time Exchange Online setup (run by an Exchange admin; interactive browser sign-in).
#   pwsh ./scripts/exchange-setup.ps1 -Domain <domain> -AppId <automation_app_id> -ObjectId <automation_principal_id>
# Creates the shared mailbox, gives analyst1 Full Access, and grants the Automation identity
# "Application Mail.ReadWrite" ONLY on mailboxes tagged CustomAttribute1 = sandbox-poc (RBAC for Applications).
# Use -Remove to undo all of it.
param(
    [Parameter(Mandatory)][guid]$AppId,
    [Parameter(Mandatory)][guid]$ObjectId,
    [Parameter(Mandatory)][string]$Domain,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$mbx = "secops-triage@$Domain"
$analyst = "analyst1@$Domain"
$scope = 'sandbox-poc-mailboxes'
$spName = 'aa-attsandbox'

Import-Module ExchangeOnlineManagement
# Browser sign-in, not -Device: security defaults block the device-code flow (AADSTS530035).
Connect-ExchangeOnline -ShowBanner:$false

if ($Remove) {
    Get-ManagementRoleAssignment -RoleAssignee $spName -ErrorAction SilentlyContinue | Remove-ManagementRoleAssignment -Confirm:$false
    Remove-ManagementScope $scope -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ServicePrincipal $spName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Mailbox $mbx -Confirm:$false -ErrorAction SilentlyContinue
    'Exchange objects removed.'
    return
}

# New tenants are "dehydrated": custom management scopes are refused until this one-time switch is on.
if ((Get-OrganizationConfig).IsDehydrated) {
    'Enabling organization customization (one-time per tenant)...'
    Enable-OrganizationCustomization
}

# analyst1's mailbox appears a few minutes after licensing; Full Access needs it to exist.
$deadline = (Get-Date).AddMinutes(15)
while (-not (Get-Mailbox $analyst -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { throw "$analyst has no mailbox after 15 min - is it licensed? (poc.sh license)" }
    "waiting for $analyst mailbox to be provisioned..."; Start-Sleep -Seconds 30
}

if (-not (Get-Mailbox $mbx -ErrorAction SilentlyContinue)) {
    New-Mailbox -Shared -Name 'SecOps Triage' -DisplayName 'SecOps Triage (sandbox POC)' -PrimarySmtpAddress $mbx | Out-Null
}
Set-Mailbox $mbx -CustomAttribute1 'sandbox-poc'
Add-MailboxPermission $mbx -User $analyst -AccessRights FullAccess -AutoMapping $true -ErrorAction SilentlyContinue | Out-Null

if (-not (Get-ServicePrincipal $spName -ErrorAction SilentlyContinue)) {
    New-ServicePrincipal -AppId $AppId -ObjectId $ObjectId -DisplayName $spName | Out-Null
}
# Right after Enable-OrganizationCustomization, scopes stay refused until it propagates (minutes, up to ~1 h).
$deadline = (Get-Date).AddMinutes(60)
while (-not (Get-ManagementScope $scope -ErrorAction SilentlyContinue)) {
    try { New-ManagementScope -Name $scope -RecipientRestrictionFilter "CustomAttribute1 -eq 'sandbox-poc'" -ErrorAction Stop | Out-Null }
    catch {
        if ($_.Exception.Message -notmatch 'Enable-OrganizationCustomization' -or (Get-Date) -gt $deadline) { throw }
        "$(Get-Date -Format HH:mm) organization customization still propagating, retrying in 60 s..."; Start-Sleep -Seconds 60
    }
}
if (-not (Get-ManagementRoleAssignment -RoleAssignee $spName -Role 'Application Mail.ReadWrite' -ErrorAction SilentlyContinue)) {
    New-ManagementRoleAssignment -App $spName -Role 'Application Mail.ReadWrite' -CustomResourceScope $scope | Out-Null
}

# Verification V3: in scope for the triage mailbox, NOT for analyst1's own mailbox.
'--- scope test (expect InScope True for secops-triage, False for analyst1) ---'
foreach ($r in $mbx, $analyst) {
    Test-ServicePrincipalAuthorization -Identity $spName -Resource $r |
        Select-Object @{n = 'Mailbox'; e = { $r } }, RoleName, InScope | Format-Table -AutoSize | Out-String
}
Disconnect-ExchangeOnline -Confirm:$false
