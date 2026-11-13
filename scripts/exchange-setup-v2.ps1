# hal-id: #HAL-20261113-0025-PK-E2
# One-time Exchange Online setup for cloud v2 (run by an Exchange admin; interactive browser sign-in).
#   pwsh ./scripts/exchange-setup-v2.ps1 -Domain <domain> [-Remove]
#
# v2 gives the TOOL no mailbox access at all. Instead, one mail-enabled security group gets Full Access to the shared
# mailbox, and Terraform assigns that same group the app role. One membership controls both:
#   in the group  -> can open the shared mailbox AND use the previewer;  removed -> loses both.
# It also removes v1's application access (RBAC for Applications), which v2 no longer needs.
param(
    [Parameter(Mandatory)][string]$Domain,
    [string]$Mailbox = 'secops-triage',
    [string]$Group = 'SecOps Triage Analysts',
    [string[]]$Members = @('analyst1'),
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$mbx = "$Mailbox@$Domain"
$groupSmtp = "secops-analysts@$Domain"

Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -ShowBanner:$false

# v1 leftovers: the Automation identity's app-only mailbox access. v2 acts only on behalf of signed-in analysts.
foreach ($sp in @('aa-attsandbox')) {
    Get-ManagementRoleAssignment -RoleAssignee $sp -ErrorAction SilentlyContinue | Remove-ManagementRoleAssignment -Confirm:$false
    Remove-ServicePrincipal $sp -Confirm:$false -ErrorAction SilentlyContinue
}
Remove-ManagementScope 'sandbox-poc-mailboxes' -Confirm:$false -ErrorAction SilentlyContinue
'v1 application mailbox access: removed (if it existed).'

if ($Remove) {
    Remove-MailboxPermission $mbx -User $Group -AccessRights FullAccess -InheritanceType All -Confirm:$false -ErrorAction SilentlyContinue
    Remove-DistributionGroup $Group -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction SilentlyContinue
    "Removed group '$Group' and its access to $mbx (the shared mailbox itself is kept)."
    return
}

if (-not (Get-Mailbox $mbx -ErrorAction SilentlyContinue)) {
    New-Mailbox -Shared -Name $Mailbox -DisplayName 'SecOps Triage (lab)' -PrimarySmtpAddress $mbx | Out-Null
    "Created shared mailbox $mbx"
}

if (-not (Get-DistributionGroup $Group -ErrorAction SilentlyContinue)) {
    New-DistributionGroup -Name $Group -Type Security -PrimarySmtpAddress $groupSmtp `
        -Notes 'Full Access to the triage mailbox AND the Safe Attachment Previewer app role.' | Out-Null
    # Not a mailing list: nobody outside should be able to email it.
    Set-DistributionGroup $Group -RequireSenderAuthenticationEnabled $true -HiddenFromAddressListsEnabled $true
    "Created mail-enabled security group '$Group'"
}

foreach ($m in $Members) {
    $upn = "$m@$Domain"
    $deadline = (Get-Date).AddMinutes(15)
    while (-not (Get-Mailbox $upn -ErrorAction SilentlyContinue)) {
        if ((Get-Date) -gt $deadline) { throw "$upn has no mailbox yet (licensed?)" }
        "waiting for $upn's mailbox..."; Start-Sleep 30
    }
    Add-DistributionGroupMember $Group -Member $upn -BypassSecurityGroupManagerCheck -ErrorAction SilentlyContinue
}

# Group-based Full Access doesn't auto-map in Outlook; analysts add the mailbox once (Outlook: Add shared mailbox).
Add-MailboxPermission $mbx -User $Group -AccessRights FullAccess -InheritanceType All -AutoMapping $false | Out-Null

''
"Full Access on ${mbx}:"
Get-MailboxPermission $mbx | Where-Object { -not $_.IsInherited -and $_.User -notlike 'NT AUTHORITY*' } |
    Format-Table User, AccessRights -AutoSize
"Members of '$Group':"
Get-DistributionGroupMember $Group | Format-Table PrimarySmtpAddress -AutoSize
Disconnect-ExchangeOnline -Confirm:$false
