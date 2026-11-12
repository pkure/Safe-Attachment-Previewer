# Verification evidence (v1: Azure VM sandbox, superseded by the safe-render engine; see [../threat-model.md](../threat-model.md))

Live run 2026-11-10, region eastus2, test samples only. Commands are reproducible from this repo.

## V1: plan and build

`terraform validate`: valid. `terraform plan`: **45 to add, 0 to change, 0 to destroy**, all in `rg-attsandbox`
plus the `analyst1` test user. Measured create times: analyst VM 2 m 07 s, sandbox VM **1 m 36 s**.

First-deploy problems found and fixed in code, so the next deploy works first time:

| Symptom | Cause | Fix |
|---|---|---|
| `MissingSubscriptionRegistration: Microsoft.Compute` | New subscription never registered for VMs | Prerequisite: `az provider register -n Microsoft.Compute` |
| `Service Principal ... was not found` | The managed identity's service principal hadn't replicated in Entra yet | `time_sleep` (120 s) before the lookup |
| `patchMode 'Manual' is invalid` | The API requires automatic updates off with manual patching | `automatic_updates_enabled = false` |
| `New-ManagementScope ... Enable-OrganizationCustomization` | New M365 tenants are "dehydrated" | The script enables it, then retries while it propagates |
| License step found no SKU | The trial SKU is `BUSINESS_PREMIUM_*`, not `SPB` | Match either |
| `poc.sh inject`: `usage error: --parameters [KEY=VALUE ...]` | `az automation runbook start` takes KEY=VALUE, not JSON | Pass `Mode=Inject` style args |
| Sandbox: `Cannot convert value "ï»¿<?xml..." to type System.Xml.XmlDocument` | Blob list XML has a UTF-8 BOM; Windows PowerShell decodes the body as Latin-1, so `TrimStart(0xFEFF)` misses it | Decode the raw bytes as UTF-8, parse from the first `<` |
| Cost meter `KeyError: 'diskSizeGb'` | The CLI field is `diskSizeGB` | Accept either |

## V2: sandbox isolation (Run Command on vm-sandbox)

```
internet 1.1.1.1:443      = False
public DNS resolves       = False
blob private endpoint 443 = True
blob read via MI          = True
hosts entries: 10.50.2.4 stattsbx7cf3e4.blob.core.windows.net
```

**PASS.** No internet. Public DNS fails, so the DNS-tunneling path is closed. The only working path is the storage
private endpoint, authenticated with the VM's own managed identity.

## V3: mailbox scope (Exchange RBAC for Applications)

```
Mailbox                                         RoleName                   InScope
secops-triage@<lab-tenant>.onmicrosoft.com Application Mail.ReadWrite True
analyst1@<lab-tenant>.onmicrosoft.com      Application Mail.ReadWrite False
```

**PASS.** The runbook identity can read the triage mailbox and nothing else, with no tenant-wide Graph mail permission.
Note: on a brand-new M365 tenant, `New-ManagementScope` was refused for ~55 minutes after
`Enable-OrganizationCustomization` while it propagated. `exchange-setup.ps1` retries automatically. This is a one-time cost per tenant.
