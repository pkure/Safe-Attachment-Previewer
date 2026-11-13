# Control mapping: NIST SP 800-53 Rev. 5

<!-- hal-id: #HAL-20261113-0028-PK-N1 -->

How the cloud version (v2: Outlook add-in, portal, offline render job) implements common security controls, and what
it leaves to the organization that runs it. Use it as the starting point for a security review or an ATO package:
each row names where the evidence lives in this repo.

**Scope:** `terraform/` (Azure + Entra), `portal/`, `saferender/`, `viewer/`, `.github/workflows/`.
**Status key:** ✅ implemented here · 🟡 partly (finish with org settings) · 🏢 organization's responsibility.

## Summary

| Area | What protects it |
|---|---|
| Who can use it | Entra app role assigned to one security group **and** the analyst's own Exchange permission on the shared mailbox |
| What the tool can reach | Nothing standing: it reads mail only on behalf of a signed-in analyst, one selected email at a time |
| Where files are opened | One offline container per email; kernel-enforced no-network; never on the analyst PC |
| Data at rest / in transit | Keyless storage (Entra-only), double encryption at rest, TLS 1.2+ |
| How long data lives | 7 days, then deleted automatically (configurable) |
| Evidence | Audit log line per action, storage access logs, per-case attestation (hashes + lock proof) |
| Keeping it patched | Nightly rebuild with fresh signatures; vulnerability scan blocks fixable critical issues |

## Access control (AC)

| Control | Status | Implementation | Evidence |
|---|---|---|---|
| AC-2 Account management | ✅ | No tool-specific accounts. Use is granted by membership in one Entra security group (best practice: the mail-enabled group that already holds Full Access to the shared mailbox), so joiner/mover/leaver follows the existing process. | `terraform/entra.tf` (`azuread_app_role_assignment`), `scripts/exchange-setup-v2.ps1` |
| AC-3 Access enforcement | ✅ | Two independent checks: Entra issues a token only to assigned users (`app_role_assignment_required`), and the portal verifies the `Previewer.Use` role; Exchange then decides whether that analyst can read the mailbox (delegated `Mail.Read.Shared`). Either "no" stops the request. | `portal/app.py` (`validate_bearer`, `graph_message`), tests `test_bad_tokens_refused`, `test_mailbox_without_access_is_denied` |
| AC-4 Information flow enforcement | ✅ | Only rendered page images, text and a JSON report leave the renderer; the original file and anything unexpected are dropped by an allowlist and recorded. | `saferender/saferender/fetcher.py` (`check_output`), `test_output_check_drops_unexpected_files` |
| AC-6 Least privilege | ✅ | One identity per workload: render job reads `cases/`, writes `results/`; portal writes `cases/`, reads `results/`, and may only read/start one job (custom role). No application mailbox permission exists. The renderer process gets no credentials at all. | `terraform/main.tf` (role assignments, `job_starter`), `fetcher.py` (`render`: empty environment) |
| AC-12 Session termination | ✅ | Viewer sessions expire after 8 hours; tokens from Outlook are short-lived and never stored. | `portal/app.py` (`PERMANENT_SESSION_LIFETIME`) |
| AC-17 Remote access | 🏢 | Lab only: the analyst PC has no public IP and is reached through Azure Bastion. In production analysts use their normal PCs. | `terraform/workstation.tf` |

## Audit and accountability (AU)

| Control | Status | Implementation | Evidence |
|---|---|---|---|
| AU-2 / AU-12 Event logging | ✅ | Portal writes one JSON audit line per sign-in, denied request, case created, case viewed; storage logs every read/write/delete; the job logs each run. | `portal/app.py` (`audit`), `terraform/main.tf` (`azurerm_monitor_diagnostic_setting.blob`) |
| AU-3 Content of audit records | ✅ | Who (UPN, object ID), what (case, mailbox, hashed message ID, size), when (UTC), how (add-in or browser), result. | `audit(...)` calls |
| AU-6 Review and reporting | 🟡 | `scripts/cloud.sh logs` queries the last hour. Forwarding the workspace to the SIEM (e.g. Microsoft Sentinel) and alert rules are the organization's. | `scripts/cloud.sh` |
| AU-9 Protection of audit information | 🟡 | Logs live in Log Analytics, outside the workloads' reach (neither identity has log permissions). Immutability/export per org policy. | `terraform/main.tf` |
| AU-11 Audit record retention | 🟡 | 30 days in the lab (`log_retention_days`); set to the organization's retention schedule. | `terraform/variables.tf` |

## Configuration management (CM)

| Control | Status | Implementation | Evidence |
|---|---|---|---|
| CM-2 Baseline configuration | ✅ | Everything is Terraform; the container images are versioned and built from this repo. | `terraform/`, `saferender/Dockerfile`, `portal/Dockerfile` |
| CM-3 Change control | 🟡 | Changes arrive by pull request; images publish only from `main` after tests and scan. Approval workflow is the org's. | `.github/workflows/nightly-image.yml` |
| CM-7 Least functionality | ✅ | Renderer: no sockets except local, no `io_uring`, foreign syscall ABIs killed, read-only input, non-root, no compilers in the image. Portal: serves an allowlist of paths only. | `saferender/saferender/lockdown.py`, `portal/app.py` (`addin_files`, `RESULT_FILE_RE`) |

## Identification and authentication (IA)

| Control | Status | Implementation | Evidence |
|---|---|---|---|
| IA-2 User identification and authentication | 🟡 | Entra ID sign-in through Outlook (nested app auth) or the browser. MFA and Conditional Access come from the tenant's policies. | `portal/addin/taskpane.js`, `portal/app.py` (`login`) |
| IA-5 Authenticator management | ✅ | No client secret, certificate or storage key exists. The portal proves the app's identity with its managed identity (workload identity federation); storage accepts Entra tokens only. | `terraform/entra.tf` (`federated_identity_credential`), `main.tf` (`shared_access_key_enabled = false`) |
| IA-9 Service identification | ✅ | Managed identities for both workloads. | `terraform/main.tf` |

## Media protection and retention (MP, SI-12)

| Control | Status | Implementation | Evidence |
|---|---|---|---|
| MP-6 / SI-12 Sanitization and retention | ✅ | Emails and previews are deleted 7 days after creation by a lifecycle rule (soft-delete safety net: 1 day). | `terraform/main.tf` (`azurerm_storage_management_policy`) |

## Risk assessment and acquisition (RA, SA, SR)

| Control | Status | Implementation | Evidence |
|---|---|---|---|
| RA-5 Vulnerability monitoring | ✅ | Nightly Trivy scan of both images; fixable CRITICAL blocks publishing; HIGH reported. First run caught 5 critical + 35 high in the image library and 20 high in the PDF library (both upgraded before deploy). | `.github/workflows/nightly-image.yml` |
| SA-11 Developer testing | ✅ | 41 engine tests (in the offline, hardened container) + 27 portal tests + a network-lock proof with the network ON, all in CI. | `saferender/tests/`, `portal/tests/` |
| SR-3 / SR-11 Supply chain | 🟡 | Python dependencies pinned to exact versions; base images refreshed nightly. Image signing / SBOM attestation is a recommended next step. | `requirements.txt` files |

## System and communications protection (SC)

| Control | Status | Implementation | Evidence |
|---|---|---|---|
| SC-7 Boundary protection | 🟡 | Renderer: kernel-enforced no network (proved per run, fail-closed). Storage: public endpoint but Entra-only and TLS-only. A private endpoint is possible but moves the Container Apps environment to a paid plan (~$73/month): an org decision. | `lockdown.py`, `docs/threat-model.md` |
| SC-8 Transmission confidentiality | ✅ | HTTPS only (HSTS on the portal), storage TLS 1.2 minimum, Graph and Azure APIs over TLS. | `terraform/main.tf`, `portal/app.py` (`headers`) |
| SC-12 / SC-13 Cryptographic keys | 🟡 | Microsoft-managed keys with infrastructure (double) encryption. Customer-managed keys in Key Vault if policy requires. | `terraform/main.tf` |
| SC-28 Protection at rest | ✅ | Storage service encryption + infrastructure encryption. | `terraform/main.tf` |
| SC-39 Process isolation | ✅ | One container execution per email: no case can see another case's files. | `terraform/apps.tf` (`replica_completion_count = 1`, one start per case) |
| SC-44 Detonation chambers | ✅ | Suspicious content is opened only in the isolated, offline renderer, never on the endpoint. (This is a preview chamber, not a behavioral sandbox: executables are refused and escalated, never run.) | `saferender/`, `README.md` |

## System and information integrity (SI)

| Control | Status | Implementation | Evidence |
|---|---|---|---|
| SI-2 Flaw remediation | ✅ | Nightly rebuild picks up OS and parser patches; dependency pins are bumped when the scan finds fixes. | CI workflow |
| SI-3 Malicious code protection | ✅ | ClamAV with signatures refreshed nightly, plus structure checks (disguised executables, macros, active PDF content). Complements, not replaces, the gateway/EOP/EDR. | `saferender/saferender/formats.py` |
| SI-4 System monitoring | 🟡 | Platform and audit logs in Log Analytics; a failed nightly build opens a GitHub issue. SIEM alerting is the org's. | CI workflow, `terraform/main.tf` |
| SI-7 Software and information integrity | ✅ | Per-case `attestation.json`: SHA-256 of every input, lock proof, image tag, timings, dropped outputs. | `fetcher.py` |
| SI-10 Information input validation | ✅ | Request size/count limits, ID and mailbox format checks, rate limit; all email content is treated as untrusted (text-only rendering, strict CSP, no inline script). | `portal/app.py` (`clean_items`, `rate_ok`), `viewer/app.js` |

## What the organization still provides

- MFA / Conditional Access for the analysts (IA-2), SIEM forwarding and alert rules (AU-6, SI-4).
- Log retention and immutability to the records schedule (AU-9, AU-11).
- Decisions on private networking and customer-managed keys (SC-7, SC-12).
- Change approval (CM-3) and the add-in's central deployment to the analyst group.
- Mailboxes must be in Exchange Online (Graph can't reach on-premises mailboxes in a hybrid setup).
