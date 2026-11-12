# Verification evidence (v2 safe-render)

Run 2026-11-11 on an Apple M4 Mac (Docker), test samples only. Reproduce with `scripts/preview-local.sh test`.
v1 (Azure VM) live evidence: [v1/verification.md](v1/verification.md).

## V1: automated tests in the offline container

```
$ scripts/preview-local.sh test
...........................                                              [100%]
27 passed in 72.72s
```

The tests run inside the same hardened container (`--network none --read-only --cap-drop ALL ...`) as the real path.

| Sample (benign) | What the test proves the analyst sees |
|---|---|
| `long-report.pdf` (multi-page) | Hidden "Click here" link with its on-page position; link text showing `contoso.com` but opening another host is flagged; a URL that exists only inside a scanned image is found by OCR; QR code decoded; callback phone number; at least 4 pages marked as needing attention; verdict SUSPICIOUS |
| `invoice-hidden-link.docx` | Link target found in the Office relationships, pages rendered |
| `photo-qr.png` | QR decoded, recognized as a URL, flagged as a quishing check |
| `invoice.pdf` (starts with `MZ`) | Flagged as a disguised executable, never rendered, escalation recommended |
| `update.js` | Executable script type flagged, URL inside it extracted |
| `budget-macro.xlsm` | VBA macro module listed with its source |
| `statement-js.pdf` | PDF JavaScript flagged |
| `invoice-eicar.zip` | Unpacked; ClamAV detects EICAR; verdict MALICIOUS |
| `statement-clean.pdf` | NO DETECTIONS |
| `fwd-account-alert.eml` | Spoofed "Microsoft 365 Security" sender name, lookalike domain, SPF/DMARC fail, Reply-To elsewhere, deceptive link text; inline QR and attached PDF unpacked, QR decoded, callback number found in the PDF |
| `vendor-bank-change.docx` (BEC) | Letter rendered and readable, callback number listed |
| `shared-document.html` | Password field flagged, form posting to a DocuSign lookalike flagged |
| `voicemail.png` | OCR finds the link and the phone number that exist only as pixels |
| `timesheet.xlsx` | Clean file: rendered, NO DETECTIONS |
| lookalike unit tests | `micros0ft`, `m1crosoft`, `rnicrosoft`, `contoso.com.<other>` flagged; `login.microsoftonline.com`, `contoso.sharepoint.com` not |
| every case | `isolation.internetReached == false` and `isolation.dnsResolved == false` |

## V2: whole-case run and timing

All 9 samples submitted as one case (10 files after unzipping):

```
verify-all: MALICIOUS files=10 pages=29 links=8 qr=2 phones=1 total=8.28s internet=False dns=False
timing: render 2.42 s, OCR 0.60 s (4 pages), ClamAV 4.68 s
```

**PASS.** About 8 seconds for a 29-page case. Antivirus is the biggest share. The container proved it was offline.

## V3: viewer

Screenshots from the local viewer: `evidence/viewer-2-hidden-link.png` (deceptive link flagged and boxed on the page),
`evidence/viewer-3-qr-filtered.png` (QR filter), `evidence/viewer-4-disguised-exe.png` (escalation card).
The viewer never uses `innerHTML`; check with `rg innerHTML viewer/` (the only hit is the comment saying so).
