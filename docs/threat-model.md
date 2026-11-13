# Threat model: safe-render preview (v2)

Scope: the safe-render engine and viewer, run locally, and the cloud version (Outlook add-in, portal, one render job
per email; `terraform/`). Control-by-control mapping: [controls.md](controls.md) (NIST SP 800-53). Method: data-flow review, then STRIDE per trust boundary. Each row names the
control in the code, or says plainly that it's an accepted risk and what the production fix is.
The v1 VM sandbox has its own review: [v1/threat-model.md](v1/threat-model.md).

## Assets

| Asset | Why it matters |
|---|---|
| Analyst workstation | The thing we're protecting. The original attachment must never land on it. |
| Attachment bytes | Potential live malware, and often sensitive business content (invoices, BEC threads). |
| Report + page images | Analysts act on them. A forged "clean" report, or a viewer that runs attacker content, is a real harm. |
| Host running the container | A container escape would put malware on that host (a laptop locally, or the cloud job host). |

## Data flow and trust boundaries

```
[attachment bytes] --ro mount--> [saferender container: no network, ro root, no caps, uid 10001]
                                         | writes report.json + pages/*.png
                                         v
                                  [case output folder] --HTTP (static)--> [viewer in analyst's browser]
```

Cloud version:

```
[analyst in classic Outlook] --"Preview safely": message ID + analyst's token--> [portal (Container App)]
   portal --on-behalf-of the analyst (Mail.Read.Shared)--> [Exchange Online] --raw MIME--> portal
   portal --writes--> [storage: cases/<id>/message.eml]   (portal never parses it)
   portal --starts--> [render job: fetcher (has identity) -> renderer (seccomp: no network, no identity)]
   job --writes--> [storage: results/<id>/ status, report, PNGs, attestation]
[analyst's browser] --Entra sign-in--> portal /case/<id> --> live progress, then the preview
```

B0: analyst → portal (who may ask, and for which mailbox).
B1: attachment → engine (the dangerous boundary: hostile bytes meet parsers).
B2: engine → output (what's allowed to leave).
B3: output → viewer (attacker-controlled strings shown in a browser).
B4: engine → host (container isolation).

## STRIDE

| # | Threat | Boundary | Control in this repo | Residual / production fix |
|---|---|---|---|---|
| T1 | A parser bug (pdfium, LibreOffice, Pillow, tesseract) lets the file run code | B1 | It runs inside a container with no network, a read-only root, no capabilities, `no-new-privileges`, non-root, and PID/memory/CPU caps. Macros are never executed: LibreOffice converts but doesn't run them. | Code execution inside the container is **possible and expected now and then**. The design limits what it can do: no network, nothing to persist to, one case only. Production: rebuild the image daily for patched parsers. Consider gVisor or a microVM runtime (the cloud job host is already a sandboxed VM). |
| T2 | Malicious output: a crafted file makes the engine write HTML or script into the report | B2→B3 | The viewer sets every untrusted string with `textContent` and never uses `innerHTML`. CSP is `default-src 'none'; script-src 'self'`. Links appear defanged and never as `<a>`. | Production host must send CSP + `frame-ancestors 'none'` as HTTP headers (a meta tag can't set frame-ancestors). |
| T3 | A compromised engine forges a clean report for its own case | B2 | One container per case, so it can only lie about the file it already controls. ClamAV runs over the same bytes. | Accepted: a fully compromised renderer can under-report its own file. Mitigation: the verdict is advisory, flagged files still go to escalation, and production should re-scan hashes outside the container (EDR or gateway hash lookup). |
| T4 | Cross-case tampering or leakage | B1/B2 | A new container per case (`--rm`), its own temp dir, only that case's input mounted. | — |
| I1 | Exfiltration or callback from the file (tracking pixels, remote templates, phone-home macros) | B1 | Local: `--network none`. Cloud: the renderer runs under a seccomp filter (`lockdown.py`) that denies every non-AF_UNIX socket and io_uring and kills foreign-ABI syscalls, inherited by all child processes and irremovable. The fetcher proves the lock on the live host before every render and fails closed (`attestation.json`). Every report records `internetReached=false` and `dnsResolved=false`. Tests attack the lock directly (raw syscall, grandchild process, removal attempt, io_uring). Remote templates are flagged, never fetched. | Cloud: add a no-internet egress rule on the job subnet as a second, independent layer. A kernel bug that bypasses seccomp is out of scope. |
| I1b | The renderer steals the job's identity to reach storage | B1 | The renderer's environment is emptied (no `IDENTITY_ENDPOINT`/`IDENTITY_HEADER`), and it couldn't connect to the token endpoint anyway (no sockets). Only the fetcher, which never parses attachment content, holds the identity. | Done in the cloud version: read `cases`, write `results`, nothing else (`terraform/main.tf`). |
| T2b | A compromised renderer smuggles something out through its output | B2 | The fetcher uploads only `report.json` and PNGs with expected names, ≤25 MB each, PNG signature checked, no symlinks; everything else is dropped and listed in the attestation. | A malicious-but-valid PNG reaches the browser as an image; browsers decode PNG in a sandboxed process. |
| I2 | The original file leaks to the analyst | B2 | Only re-encoded PNG (from raw pixels) and JSON leave. The original is copied to a private temp dir and deleted with it. | — |
| I3 | Sensitive content lingers in case output | B2 | Local output lives in `.preview/` (gitignored). | Cloud: deleted after 7 days by a lifecycle rule (`retention_days`), viewer access needs the app role. Set the period with legal/records. |
| D1 | Zip bombs, decompression bombs, 10,000-page PDFs, slow files | B1 | `LIMITS`: 50 files, 200 MB unpacked, 200:1 ratio, depth 2, 300 pages, 40 MP images, per-tool timeouts, a 1 GB tmpfs, memory and PID caps. | — |
| S1 | Someone who isn't an analyst views case output | B3 | Local: the viewer binds to `127.0.0.1` only. | Cloud: Entra sign-in plus the app role (see S2). Case IDs are random but are **not** treated as secrets: every analyst on the team can see the team's cases. |
| E1 | Container escape to the host | B4 | Hardened `docker run`, no privileged mode, no host mounts except the case's own in/out folders. | Kernel or runtime escapes are out of scope. Keep Docker/runtime patched, and in the cloud rely on the per-job sandboxed host. |
| R1 | No record of who previewed what | — | Each report has a case ID, SHA-256 per file, and a timestamp. Cloud: the portal logs sign-in, denial, case creation and viewing (who, which mailbox, hashed message ID); storage logs every read/write/delete; all to Log Analytics. | Forward the workspace to the SIEM (org). |

### Cloud boundary B0: who can send what

| # | Threat | Control | Residual |
|---|---|---|---|
| S2 | Someone outside the security team uses the tool | Entra issues a token only to users assigned the app role (`app_role_assignment_required`); the portal also checks the role, tenant, audience and scope on every call. Best practice: assign the same mail-enabled group that holds Full Access to the shared mailbox. | Group hygiene is the org's joiner/mover/leaver process. |
| S3 | An analyst asks for a mailbox they can't read (e.g. an executive's) | The portal holds no mailbox permission. It reads mail only with the analyst's own delegated token (on-behalf-of), so Exchange refuses anything the analyst couldn't open in Outlook. Denials are logged. | `Mail.Read.Shared` covers every mailbox the analyst can already read; that's the intended boundary. |
| E2 | The portal is compromised | It can write to `cases/`, read `results/`, and start one job. It has no standing mailbox access, no secret to steal (its app credential is its managed identity), and analysts' tokens are used per request and never stored. | A compromised portal could act for analysts who use it while compromised, within their own access. Keep it patched (nightly image, Trivy). |
| S4 | Forged requests from another site (CSRF) | Creating a case needs a bearer token (not a cookie). Viewer pages are read-only. Session cookie is `HttpOnly`, `Secure`, `SameSite=Lax`. | — |
| D2 | Request flooding | Max 10 emails per request, 50 MB per email, 60 previews per analyst per hour; one job run per email (no retries). | Container Apps scales per request; Azure budget alerts cap spend. |
| I4 | The add-in reads mail content | It reads only the selected items' IDs, subjects and shared-mailbox owner (`ReadItem`). The bytes travel server-side, Exchange → portal → storage, never through Outlook. | — |
| I5 | Storage reachable from the internet | Entra-only (no keys or SAS can exist), TLS 1.2+, no anonymous access, every access logged. | A private endpoint removes the public path but puts the Container Apps environment on the Dedicated plan (about $73/month). Org decision (SC-7). |

## Detection gaps (stated up front, not hidden)

- **Static view, not behavior.** The engine shows content and structure. It doesn't detonate. A file that is only
  malicious when it runs (an exploit doc with clean-looking content) can look fine. That's what the escalation path is for.
- **Lookalike checks cover a short brand list.** Hosts that imitate Microsoft, DocuSign, PayPal, Adobe, Dropbox or
  the organization's own domains (`SAFERENDER_ORG_DOMAINS`) are flagged, including digit swaps (`micros0ft`, `m1crosoft`)
  and `rn`→`m`. Real brand-hosted pages (`contoso.sharepoint.com`) are never flagged. Other brands and full Unicode
  confusables aren't covered yet; punycode hosts get a general warning.
- **Outlook `.msg` files aren't parsed yet.** `.eml` is fully supported. In the cloud version, intake fetches the
  message as MIME through Microsoft Graph, so `.msg` never has to be handled. Locally, save as `.eml` first.
- **Sender checks trust the headers in the file.** For a forwarded email, `Authentication-Results` is what the
  receiving server recorded. That's useful, but a crafted `.eml` could fake it. The cloud intake reads it straight from
  Exchange.
- **Antivirus is ClamAV with build-time signatures.** "No detections" is not "safe", and the viewer says so.
  The image is rebuilt nightly (`.github/workflows/nightly-image.yml`). Production also needs hash lookups in the organization's own EDR/gateway.
- **Password-protected archives and PDFs** are flagged but not opened. A password field in the viewer is possible, but
  it is deliberately left out of the demo.
- **Encrypted or obfuscated macros** are shown as oletools extracts them. Heavy obfuscation needs a human or a sandbox.
