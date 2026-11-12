# Threat model (v1: Azure VM sandbox, superseded by the safe-render engine; see [../threat-model.md](../threat-model.md))

Scope: the PoC as built in this repo, a short-lived lab running test samples only.
Method: data-flow review, then STRIDE per trust boundary. Every row names the control in the code,
or says plainly that it's an accepted PoC risk with the production fix.

## Assets

| Asset | Why it matters |
|---|---|
| Analyst workstation | The thing we're protecting. Today, opening or previewing a shared-mailbox attachment writes it to local disk, which trips EDR alerts or worse. |
| Triage mailbox contents | Suspicious email, often with sensitive business context (BEC threads, invoices). |
| Attachment bytes | Potential live malware. |
| Verdict reports | Analysts act on them, so a forged "clean" verdict is a real harm. |
| Cloud control plane | The subscription, the identities and the Exchange permissions. |

## Trust boundaries and data flow

```
[Exchange Online: triage mailbox] --Graph (app-only, RBAC-scoped)--> [Automation runbook]
      ^ analyst drags mail to Sandbox folder                              | blob PUT cases/<id>/
      |                                                                   v
[Analyst VM]  (never receives the file)                           [Storage: Entra-only]
                                                                          ^ private endpoint (443)
                                          Run Command (control only) -->  |
                                                                    [Sandbox VM: no internet, no DNS]
                                                                          | blob PUT reports/<id>/
[Verdict mail in Sandbox/Done] <--Graph-- [Runbook reads report.json] <---+
```

B1: Exchange ↔ runbook. B2: runbook ↔ storage. B3: sandbox ↔ storage (the only path out of the sandbox).
B4: humans ↔ VMs (Bastion). B5: report content ↔ analyst's mail client.

## STRIDE

| # | Threat | Boundary | Control in this repo | Residual / production fix |
|---|---|---|---|---|
| S1 | The runbook identity is abused to read other mailboxes | B1 | Exchange **RBAC for Applications**, scoped by a management scope (`CustomAttribute1 = sandbox-poc`). No tenant-wide Graph `Mail.*` app role. Verified with `Test-ServicePrincipalAuthorization` (V3). | Same pattern in production, plus a dedicated identity. |
| S2 | Someone gets onto the VMs | B4 | No public IPs, Bastion only, random 24-char admin password, NSGs deny inbound from the internet. | Entra-joined VMs + Just-In-Time access. |
| T1 | Malware on the sandbox **forges the verdict** for another case | B3 | Sandbox identity can write only to `reports`. | **Accepted for PoC:** a compromised sandbox could overwrite another case's report. Production: one disposable sandbox per case, or a per-case SAS with write scope on `reports/<id>/` only, plus a runbook check that the report's SHA list matches the uploaded hashes. |
| T2 | A malicious subject or filename injects HTML/script into the verdict email | B5 | Every untrusted string is HTML-encoded (`Enc`). Filenames are rewritten to `[A-Za-z0-9._-]`. Case IDs and the storage account name are regex-validated inside the sandbox. | — |
| T3 | Command injection through Run Command | B2→B3 | The Run Command script contains only values the runbook generates itself (case ID, account name, private endpoint IP), never email content. | — |
| R1 | No record of who submitted what | B1 | Automation job output logs the case ID → message ID mapping, and the verdict mail keeps the original subject and sender. | Send job streams to Log Analytics / Sentinel with retention. |
| I1 | **Exfiltration from the sandbox through the internet** | B3 | `default_outbound_access_enabled = false`, no public IP, NSG `deny-all-outbound`. Each report includes `internetReached` (expect `False`). | — |
| I2 | **Exfiltration through DNS tunneling** | B3 | NSG denies the `AzurePlatformDNS` service tag. The storage FQDN is pinned in `hosts` to the private endpoint IP. Each report includes `dnsResolved` (expect `False`). | Same in production, or an Azure DNS Security Policy with an allow-list. |
| I3 | Exfiltration through the storage account | B3 | The sandbox can reach only its own storage account (private endpoint), read `tools` + `cases`, and write `reports`. Report content reaches humans only as HTML-encoded text. | A compromised sandbox can read other cases' bytes in the same session. Production: per-case isolation (see T1). |
| I4 | Attachment bytes linger after the demo | B2 | One resource group; `poc.sh down` + a self-destruct schedule at apply + `ttl_hours` (default 8). Blob soft delete is 1 day. Verified with `az group exists` → `false` (V6). | Production needs a records-retention decision: case data is evidence. |
| I5 | Files are copied out of the sandbox by an analyst | B4 | Bastion file transfer is off (Developer/Basic SKU has none). | Text clipboard is still on, so it's not a DLP control. Production: Standard SKU with copy/paste disabled. |
| D1 | A message that keeps failing loops the sandbox | B1 | Failed cases are moved to `Done` anyway, and attachments over 25 MB are skipped. | — |
| D2 | Runaway cost | — | Self-destruct, plus subscription budgets ($40 alert, $100 kill switch that deallocates VMs) from the governance stack. | — |
| E1 | Malware escapes from the sandbox VM into Azure | B3 | The sandbox's managed identity holds only blob data roles. It has no ARM roles, so it can't touch other resources. | Hypervisor escape is out of scope. |
| E2 | The orchestrator identity is over-privileged | B2 | — | **Accepted for PoC:** the Automation identity holds Contributor on the resource group (Run Command + self-destruct). Production: split into a triage identity (VM Run Command only) and a teardown identity. |

## Known limits (stated up front, not hidden)

- **Static analysis plus manual detonation, not automated dynamic analysis.** The sandbox hashes files and runs
  Defender, olevba and pdfid. Opening a file is a human step inside the sandbox, through Bastion.
- **Offline signatures.** Defender in the sandbox has whatever signatures shipped in the image. "No detections" is
  not "safe", and the verdict email says so. Production: a nightly Packer image, or a signature-only egress allow-list.
- **Password-protected archives** are reported as files but not unpacked.
- **Cloud Automation can't reach private endpoints**, so the storage account keeps its public endpoint
  (Entra auth only, no shared keys). Production: Hybrid Runbook Worker or a VNet-integrated Function, then
  `public_network_access = Disabled`.
