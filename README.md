# Safe Attachment Preview for SOC Triage

**Problem.** SOC analysts work suspicious email from a shared triage mailbox. In classic Outlook, shared-mailbox
items are cached on the analyst's PC ("Download shared folders"), so opening or even previewing an attachment writes
it to disk. The people investigating malware end up putting it on company endpoints. At best that sets off EDR
alerts. At worst it causes an incident.

Almost everything in that mailbox turns out to be harmless. The analyst mostly needs to **see** the document: what it
says, where its links go, whether it carries a QR code or a callback number. Detonating it isn't usually the point.

**Solution.** Each attachment is rendered inside a throwaway container that has **no network**. Only harmless output
comes out:

- freshly re-encoded page images (PNG), so nothing from the original file's own encoding survives
- extracted text, with OCR for scanned or image-only pages
- every link, defanged and tied to its page: link annotations, plain text, OCR, QR codes, and Office `.rels` targets
- phone numbers, email addresses, macro source code, and PDF active content
- flags for phishing tells: link text that names one site but opens another, lookalike domains (`micros0ft`,
  `contoso.com.billing-check`), QR codes (quishing), executables disguised as documents, remote-template injection,
  and HTML smuggling patterns
- for forwarded emails (`.eml`): spoofed sender names, Reply-To redirection, failed SPF/DKIM/DMARC, and every
  attachment and inline image unpacked and previewed in turn
- a ClamAV verdict, plus proof in every report that the container really was offline

The analyst reviews all of this in a locked-down web viewer. The original file never reaches their PC. When a file
can't be previewed safely (a real executable, for example), the viewer says so and recommends escalation: a hash
lookup first, then a detonation sandbox. Sandbox runs are spent only on the rare file that needs one.

> Lab project with **benign test samples only**: the EICAR test string, a harmless macro, harmless PDFs, a fake
> "EXE", and test QR codes and links on reserved `.example` domains. It handles no real organization's email.

![Viewer: a hidden link whose text shows one site but opens another](evidence/viewer-2-hidden-link.png)

## How it works

```mermaid
flowchart LR
  A[Attachment bytes] -->|read-only mount| C["saferender container<br/>--network none, read-only,<br/>no capabilities, non-root"]
  C -->|report.json + page PNGs| O[(Case output)]
  O --> V["Viewer<br/>static, strict CSP,<br/>no innerHTML, links defanged"]
  V --> Analyst
  C -. "unpreviewable / disguised EXE" .-> E["Escalate:<br/>hash lookup → detonation sandbox"]
```

**One container per case, started on demand.** Nothing runs while it waits. A case comes in, a new container starts,
renders, writes its output, and is destroyed (`docker run --rm`). One case can never see another case's files. The
image is built ahead of time with antivirus signatures baked in, since the container can't download them at run time.

Inside the container (`saferender/saferender/pipeline.py`):

1. **Sniff the real file type** from its bytes, not its name. A `.pdf` that starts with `MZ` gets flagged as a
   disguised executable and is never rendered.
2. **Unpack archives and emails** with zip-bomb guards: an entry-ratio cap, a total-bytes cap, a file-count cap, and a depth
   limit. Password-protected entries are flagged, because antivirus can't see inside them. Attached emails are
   parsed with Python's standard library, and their attachments and inline images become child files.
3. **Render.** PDFs go through pdfium. Office files are converted to PDF with headless LibreOffice, with macros never
   run. Images are decoded under a pixel limit.
4. **Extract** text, link annotations with their on-page positions, QR codes (zxing), OCR text (tesseract), Office
   relationships, and VBA macros (oletools).
5. **Scan** everything with ClamAV, then write `report.json`. The verdict is MALICIOUS, SUSPICIOUS, NO DETECTIONS
   or NO FILE ATTACHMENTS.

The viewer (`viewer/`) has thumbnails, page navigation (`←`/`→` pages, `n`/`p` jump between findings, `f` shows only pages with findings), search,
a link index grouped by page, and highlight boxes drawn over links and QR codes on the page image.

## Security design

| Control | Where |
|---|---|
| No network at all (`--network none`). Each report records `internetReached` and `dnsResolved` | `scripts/preview-local.sh`, `pipeline.py` `isolation()` |
| Read-only root filesystem. `/tmp` is a size-capped `noexec` tmpfs. Input mounted read-only | `HARDEN` flags in `scripts/preview-local.sh` |
| No Linux capabilities, `no-new-privileges`, non-root UID 10001, caps on PIDs, memory and CPU | same |
| Build-time and run-time separated: compilers live only in the build stage; signatures baked in at build | `saferender/Dockerfile` |
| Output is limited to re-encoded PNGs and JSON text. The original file never leaves | `pipeline.py` `save_page()` |
| Every limit (pages, pixels, zip ratio, timeouts) set in one place | `saferender/saferender/formats.py` `LIMITS` |
| Case IDs regex-validated. Filenames sanitized before touching disk | `pipeline.py`, `formats.py` `safe_name()` |
| Viewer: CSP `default-src 'none'`, `textContent` only (never `innerHTML`), links shown defanged and never clickable, `no-referrer` | `viewer/index.html`, `viewer/app.js` |

Full review, including what is **not** solved: [docs/threat-model.md](docs/threat-model.md).

## Verification

27 automated tests run inside the same offline, hardened container the analyst path uses. They prove what an
analyst would see for every sample: the hidden link with its position, OCR-only URLs, QR decode, callback number,
disguised EXE, macro, PDF JavaScript, EICAR, a forwarded phishing email, a BEC bank-change letter, an HTML
login page, a voicemail screenshot, a clean spreadsheet, and the offline proof. Results and timings:
[docs/verification.md](docs/verification.md).

```bash
scripts/preview-local.sh build      # build the engine image (needs internet once, for packages and signatures)
scripts/preview-local.sh samples    # generate the benign test samples
scripts/preview-local.sh test       # 27 passed
scripts/preview-local.sh render dist/samples-v2/long-report.pdf   # opens the viewer
```

Needs Docker only. Everything runs locally, and it costs $0.

## Keeping signatures and parsers current

The rendering container is never online, so it can't update itself. Instead, a GitHub Actions workflow
([`nightly-image.yml`](.github/workflows/nightly-image.yml)) rebuilds the image every night. That build is the only
step with internet: it pulls fresh ClamAV signatures and patched PDF, Office and image libraries, runs all the tests
inside the offline container, and publishes the image only if they pass. The next morning's cases use the new image.

## Why not just use Microsoft Defender or the email gateway?

You should, and this complements them. Gateway and Safe Attachments scanning happens at delivery, and mail that is
rerouted internally, released from quarantine or forwarded into a triage mailbox may not be scanned again, depending
on policy. EDR sees the file only after it is already on the endpoint. This tool covers the moment after delivery, when
a person has to look at the file, and keeps that moment off the workstation. Escalation to a commercial sandbox stays
available, but only for the rare file that needs it.

## Roadmap: cloud version

The local version above is the finished engine. The cloud version swaps the hosting and reuses the mailbox intake that
v1 built and verified:

- **Intake:** analyst drags an email to a `Sandbox` folder. A managed identity, limited by Exchange RBAC for
  Applications to that one mailbox, fetches the attachments.
- **Engine:** Azure Container Apps **Job**, one run per case, scale to zero, no outbound network. Same image, same
  hardening.
- **Viewer:** an Entra ID-protected web app, linked from a short notification email.
- **Infrastructure as code:** Terraform, with nothing running and $0 cost between cases.

## History: v1 (Windows VM sandbox)

The first version used a Terraform-built Windows VM in Azure with no internet and no DNS. Analysts dragged an email to a
folder and got a verdict email back in 37–80 seconds. It worked and was verified live: network isolation, mailbox-scoped
permissions, and four test samples end to end. Code is still here: `terraform/`, `runbooks/`, `sandbox/`,
`scripts/poc.sh`.

What v1 taught, and why v2 exists:

- **The preview is the product, not the scan.** Gateway, EOP and EDR already scan. Analysts needed to see the content
  safely, and a verdict line didn't give them that. A remote desktop into a VM did, but it was slow and clunky.
- **A shared VM is a shared blast radius.** One sample could, in principle, read or forge another case's report. One
  container per case removes that whole class of problem.
- **Cost and startup time.** Two VMs plus Bastion cost about $0.40/hour while running and took minutes to start. A
  container job starts in seconds and costs nothing while idle.
- **DNS is a network path.** The v1 build found and closed a DNS-tunneling gap (Azure DNS stays reachable when
  "no internet" is only an NSG rule). v2 doesn't have this problem, because the container has no network interface at all.

v1 docs: [threat model](docs/v1/threat-model.md), [live verification](docs/v1/verification.md).

## Repo map

```
saferender/   the engine: Dockerfile, pipeline (render + extract + flag), tests, sample generator
viewer/       static analyst viewer (HTML/CSS/JS, no dependencies)
scripts/      preview-local.sh (v2 entry point); poc.sh, exchange-setup.ps1, build tools (v1)
docs/         threat model, verification; docs/v1/ for the VM version
evidence/     viewer screenshots, v1 cost meter snapshot
terraform/, runbooks/, sandbox/   v1 Azure VM sandbox (reference)
```

Step-by-step, non-technical: [attachment-sandbox_how-to.md](attachment-sandbox_how-to.md). MIT licensed.
