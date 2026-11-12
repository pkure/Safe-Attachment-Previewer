# hal-id: #HAL-20261110-0007-PK-R5
"""Generate BENIGN test samples for the safe-render pipeline (run inside the container).

  python -m saferender.make_samples /out
Every URL uses the reserved .example TLD (RFC 2606) and every phone number the fictional 555-01xx range.
Nothing here is malware; the "disguised exe" is just the two bytes "MZ" plus text and cannot run.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import qrcode
from PIL import Image, ImageDraw, ImageFont

from .formats import LO_PROFILE_XCU

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
PAGES = 24
HIDDEN = "https://login-micros0ft-support.example/verify?id=7731"
DECEPTIVE_SHOWN, DECEPTIVE_REAL = "https://www.contoso.com/billing", "https://payments-portal.example/contoso/billing"
SCANNED = "https://overdue-billing.example/pay"
QR = "https://quish-test.example/login"
PHONE = "(800) 555-0143"
FILLER = ("This section summarizes vendor performance for the quarter, including delivery timeliness, invoice "
          "accuracy and service-level adherence. Figures are illustrative test content only. ") * 6


def scanned_png(path: Path) -> None:
    """An image-only 'scan': the URL exists only as pixels, so only OCR can find it."""
    img = Image.new("RGB", (1400, 500), "white")
    d = ImageDraw.Draw(img)
    big, small = ImageFont.truetype(FONT, 44), ImageFont.truetype(FONT, 34)
    d.text((60, 60), "FINAL NOTICE - ACCOUNT PAST DUE", font=big, fill="black")
    d.text((60, 170), "To avoid service interruption pay today at:", font=small, fill="black")
    d.text((60, 240), SCANNED, font=small, fill="black")
    d.text((60, 330), "Reference: TEST SAMPLE ONLY", font=small, fill="gray")
    img.save(path)


def qr_png(path: Path) -> None:
    qrcode.make(QR, box_size=10, border=4).save(path)


def soffice(src: Path, fmt: str, outdir: Path, infilter: str | None = None) -> None:
    profile = Path(tempfile.mkdtemp())
    (profile / "user").mkdir()
    (profile / "user" / "registrymodifications.xcu").write_text(LO_PROFILE_XCU)
    cmd = ["soffice", f"-env:UserInstallation=file://{profile}", "--headless", "--norestore"]
    if infilter:
        cmd.append(f"--infilter={infilter}")
    subprocess.run(cmd + ["--convert-to", fmt, "--outdir", str(outdir), str(src)], check=True, capture_output=True,
                   timeout=180, env={"HOME": str(profile), "PATH": "/usr/bin:/bin"})


def report_html(work: Path) -> Path:
    scanned_png(work / "scan.png")
    qr_png(work / "qr.png")
    parts = ["<html><body><h1>Quarterly Vendor Report (TEST SAMPLE)</h1><p>Prepared for Accounts Payable.</p>"]
    for n in range(2, PAGES + 1):
        body = f"<h2>Section {n - 1}</h2><p>{FILLER}</p>"
        if n == 5:
            body += f'<p>Your invoice is ready. <a href="{HIDDEN}">Click here to view your invoice</a>.</p>'
        if n == 7:
            body += f'<p>Billing portal: <a href="{DECEPTIVE_REAL}">{DECEPTIVE_SHOWN}</a></p>'
        if n == 11:
            body += '<p>Scanned notice attached below:</p><p><img src="scan.png" width="600"></p>'
        if n == 15:
            body += '<p>Scan to confirm your account:</p><p><img src="qr.png" width="220"></p>'
        if n == 19:
            body += f"<p>Questions about this renewal? Call our billing desk at {PHONE} to cancel.</p>"
        parts.append(f'<p style="page-break-before: always"></p>{body}')
    parts.append("</body></html>")
    p = work / "long-report.html"
    p.write_text("".join(parts))
    return p


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp())
    html = report_html(work)
    soffice(html, "pdf:writer_pdf_Export", out, "HTML (StarWriter)")
    # A short Word doc whose only link hides behind "Click here" (target lives in the .rels, not the text).
    doc = work / "invoice-hidden-link.html"
    doc.write_text(f'<html><body><h1>Invoice 7731 (TEST SAMPLE)</h1><p>Your invoice is ready. '
                   f'<a href="{HIDDEN}">Click here</a> to view it.</p></body></html>')
    soffice(doc, "docx:MS Word 2007 XML", out, "HTML (StarWriter)")
    qr_png(out / "photo-qr.png")  # an image attachment that is only a QR code
    (out / "invoice.pdf").write_bytes(b"MZ" + b"\x00" * 62 + b"TEST SAMPLE: named .pdf, starts like an EXE. Not runnable.")
    (out / "update.js").write_text('// TEST SAMPLE: harmless text, never executed\n'
                                   'var u = "https://dl-test.example/payload.bin";\n'
                                   'WScript.Echo("this is a test sample: " + u);\n')
    for p in sorted(out.iterdir()):
        print(f"{p.stat().st_size:>9}  {p.name}")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "/out"))
