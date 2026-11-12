# Threat model: safe-render preview (v2)

Scope: the safe-render engine and viewer in this repo, run locally with test samples, plus the planned cloud hosting
(called out where it changes the answer). Method: data-flow review, then STRIDE per trust boundary. Each row names the
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
| I1 | Exfiltration or callback from the file (tracking pixels, remote templates, phone-home macros) | B1 | `--network none`: no interface besides loopback. Every report records `internetReached=false` and `dnsResolved=false`, checked by a test. Remote templates are flagged, never fetched. | Cloud: the job's environment gets no outbound route and the same in-report proof. Verified at deploy time. |
| I2 | The original file leaks to the analyst | B2 | Only re-encoded PNG (from raw pixels) and JSON leave. The original is copied to a private temp dir and deleted with it. | — |
| I3 | Sensitive content lingers in case output | B2 | Local output lives in `.preview/` (gitignored). | Production: retention rules for case data, decided with legal/records, plus access limited to the SOC group (Entra). |
| D1 | Zip bombs, decompression bombs, 10,000-page PDFs, slow files | B1 | `LIMITS`: 50 files, 200 MB unpacked, 200:1 ratio, depth 2, 300 pages, 40 MP images, per-tool timeouts, a 1 GB tmpfs, memory and PID caps. | — |
| S1 | Someone who isn't an analyst views case output | B3 | Local: the viewer binds to `127.0.0.1` only. | Production: Entra ID sign-in limited to a SOC group. Case IDs are random but are **not** treated as secrets. |
| E1 | Container escape to the host | B4 | Hardened `docker run`, no privileged mode, no host mounts except the case's own in/out folders. | Kernel or runtime escapes are out of scope. Keep Docker/runtime patched, and in the cloud rely on the per-job sandboxed host. |
| R1 | No record of who previewed what | — | Each report has a case ID, SHA-256 per file, and a timestamp. | Production: log case creation and viewer access to the SIEM. |

## Detection gaps (stated up front, not hidden)

- **Static view, not behavior.** The engine shows content and structure. It doesn't detonate. A file that is only
  malicious when it runs (an exploit doc with clean-looking content) can look fine. That's what the escalation path is for.
- **Lookalike domains are listed, not flagged.** A "Click here" link to `login-micros0ft-support.example` shows up in
  the link index with its page position, but it is only flagged when the visible text names a *different* domain. Next:
  a lookalike/homoglyph check against an allow-list of the organization's real domains.
- **Antivirus is ClamAV with build-time signatures.** "No detections" is not "safe", and the viewer says so.
  Production: daily image rebuild, and hash lookups in the organization's own EDR/gateway.
- **Password-protected archives and PDFs** are flagged but not opened. A password field in the viewer is possible, but
  it is deliberately left out of the demo.
- **Encrypted or obfuscated macros** are shown as oletools extracts them. Heavy obfuscation needs a human or a sandbox.
