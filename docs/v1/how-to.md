# v1 Attachment Sandbox (Azure VM): how to run it

Superseded by the safe-render engine ([../../attachment-sandbox_how-to.md](../../attachment-sandbox_how-to.md)). Kept for reference.

**What it was:** an analyst drags a suspicious email into a **Sandbox** folder in the shared security mailbox. A
throwaway Windows computer in Azure, with no internet and no DNS, downloads the attachments and scans them. A verdict
email shows up in **Sandbox/Done**.

**Money:** about $0.40–0.60 an hour while it's up, and $0 once it's torn down. It deletes itself 8 hours after it's built.

## One-time setup

| Step | How |
|---|---|
| Microsoft 365 with Exchange Online in the same Entra tenant | A Business Premium trial works. Turn recurring billing off. |
| Settings files | Copy `terraform/terraform.tfvars.example` → `terraform.tfvars` and `backend.hcl.example` → `backend.hcl` (both gitignored) |
| PowerShell | `brew install --cask powershell`, then `pwsh -c "Install-Module ExchangeOnlineManagement -Scope CurrentUser"` |

## Each demo session (from the repo root)

1. `scripts/poc.sh plan` previews what will be built. Costs nothing.
2. `scripts/poc.sh up` builds it (about 10 minutes). Billing starts here.
3. `scripts/poc.sh license` licenses the test analyst (analyst1).
4. `pwsh scripts/exchange-setup.ps1 -Domain <tenant>.onmicrosoft.com -AppId <automation_app_id> -ObjectId <automation_principal_id>`
   (sign in as a tenant admin). The output should show **True** for secops-triage and **False** for analyst1.
5. `scripts/poc.sh stage` uploads the scanning tools and the 4 test samples.
6. `scripts/poc.sh inject` drops 4 test emails into the triage mailbox.
7. Azure portal → **vm-analyst** → Connect → **Bastion**. Get the login with `scripts/poc.sh secrets`. Open Outlook
   as analyst1.
8. `scripts/poc.sh watch` starts the robot, which watches the Sandbox folder for 90 minutes.
9. Drag a test email into **Inbox → Sandbox**. A **[Sandbox: VERDICT]** email arrives in **Sandbox → Done** within about 2 minutes.
10. **`scripts/poc.sh down`** when you're done. It should end with `resource group still exists? false`.

Expected verdicts: invoice-eicar.zip **MALICIOUS**; statement-js.pdf **SUSPICIOUS** (JavaScript); budget-macro.xlsm
**SUSPICIOUS** (macro); statement-clean.pdf **NO DETECTIONS**.

## If something goes wrong

- **No verdict email:** Azure portal → aa-attsandbox → Jobs → latest job → Output.
- **"Bastion Developer not available":** `terraform -chdir=terraform plan -var bastion_sku=Basic -out=tfplan`, then
  `scripts/poc.sh up` (about $0.19/hour more).
- **Remove the Exchange pieces:** run step 4 again with `-Remove` added.
