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
SHOWN_MS = "https://account.microsoft.com/security"
MFA_QR = "https://mfa-reverify.example/start"
SEC_PHONE = "(800) 555-0177"
BEC_PHONE = "(800) 555-0187"
VM_PHONE = "+1 (800) 555-0199"
VM_URL = "https://vm-listen.example/play"
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


def voicemail_png(path: Path) -> None:
    """A screenshot-style lure: the number and URL exist only as pixels."""
    img = Image.new("RGB", (1200, 420), (245, 247, 250))
    d = ImageDraw.Draw(img)
    big, small = ImageFont.truetype(FONT, 42), ImageFont.truetype(FONT, 32)
    d.text((50, 50), "New voicemail (0:42) - TEST SAMPLE", font=big, fill="black")
    d.text((50, 150), f"From: {VM_PHONE}", font=small, fill="black")
    d.text((50, 220), f"Listen here: {VM_URL}", font=small, fill="black")
    d.text((50, 300), "Expires in 24 hours", font=small, fill=(180, 0, 0))
    img.save(path)


def preview_set(out: Path, work: Path) -> None:
    """Everyday-looking lures for demos: a forwarded phishing email, a BEC letter, an HTML login page,
    a voicemail screenshot, and a clean spreadsheet. All benign."""
    from email.message import EmailMessage

    # 1. Forwarded phishing email: spoofed display name, lookalike domain, failed auth, deceptive link,
    #    an inline QR image and an attached PDF with a callback number.
    rep = work / "Security-Report.html"
    rep.write_text("<html><body><h1>Microsoft 365 Security Report (TEST SAMPLE)</h1>"
                   "<p>We blocked 3 sign-in attempts on your account.</p>"
                   f"<p>If this wasn't you, call the security desk now at {SEC_PHONE}.</p></body></html>")
    soffice(rep, "pdf:writer_pdf_Export", work, "HTML (StarWriter)")
    qr = work / "qr-mfa.png"
    qrcode.make(MFA_QR, box_size=8, border=4).save(qr)
    msg = EmailMessage()
    msg["From"] = '"Microsoft 365 Security" <no-reply@micros0ft-alerts.example>'
    msg["Reply-To"] = "helpdesk@quick-support.example"
    msg["To"] = "analyst@contoso.com"
    msg["Subject"] = "Action required: unusual sign-in activity (TEST SAMPLE)"
    msg["Date"] = "Tue, 10 Nov 2026 08:14:00 -0800"
    msg["Message-ID"] = "<test-sample-0001@micros0ft-alerts.example>"
    msg["Authentication-Results"] = "mx.contoso.com; spf=fail smtp.mailfrom=micros0ft-alerts.example; dkim=none; dmarc=fail"
    msg.set_content("We detected an unusual sign-in. Review it at https://micros0ft-alerts.example/review "
                    "or scan the code. TEST SAMPLE ONLY.")
    msg.add_alternative(
        "<html><body><p>We detected an unusual sign-in to your account.</p>"
        f'<p><a href="https://micros0ft-alerts.example/review?u=analyst">{SHOWN_MS}</a></p>'
        '<p>Or scan to re-verify MFA:</p><p><img src="cid:qr1"></p>'
        "<p>TEST SAMPLE ONLY.</p></body></html>", subtype="html")
    msg.get_payload()[1].add_related(qr.read_bytes(), "image", "png", cid="<qr1>", filename="qr-mfa.png")
    msg.add_attachment((work / "Security-Report.pdf").read_bytes(), maintype="application", subtype="pdf",
                       filename="Security-Report.pdf")
    (out / "fwd-account-alert.eml").write_bytes(bytes(msg))

    # 2. BEC: a plain letter asking to change bank details. No links, no macros: the content IS the threat.
    bec = work / "vendor-bank-change.html"
    bec.write_text("<html><body><h2>Northwind Supplies (TEST SAMPLE)</h2><p>Dear Accounts Payable,</p>"
                   "<p>Please note our banking details have changed effective immediately. All open invoices "
                   "should be remitted to our new account below. Our old account is under audit and payments "
                   "sent there will be returned.</p><p>Bank: Example Federal Bank<br>Routing: 000000000 (TEST)<br>"
                   f"Account: 0000000000 (TEST)</p><p>To confirm, call our controller directly at {BEC_PHONE}. "
                   "Please do not use the number on file.</p><p>Regards,<br>J. Smith, Controller</p></body></html>")
    soffice(bec, "docx:MS Word 2007 XML", out, "HTML (StarWriter)")

    # 3. HTML attachment that is a fake sign-in page (password field, posts to a lookalike).
    (out / "shared-document.html").write_text(
        "<html><head><title>DocuSign - Review Document</title></head><body>"
        "<h2>DocuSign</h2><p>You have a document to review. Sign in to continue. TEST SAMPLE ONLY.</p>"
        '<form action="https://docusign-secure-view.example/submit" method="post">'
        '<input name="email" type="email"><input name="pw" type="password"><button>Sign in</button></form>'
        "</body></html>")

    # 4. Voicemail screenshot (OCR finds the number and the link).
    voicemail_png(out / "voicemail.png")

    # 5. A clean spreadsheet: the common case, which should come back NO DETECTIONS.
    csv = work / "timesheet.csv"
    csv.write_text("Employee,Mon,Tue,Wed,Thu,Fri,Total\nA. Analyst,8,8,8,8,8,40\nB. Analyst,8,8,7.5,8,8,39.5\n")
    soffice(csv, "xlsx:Calc MS Excel 2007 XML", out, "CSV:44,34,76,1")


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
    preview_set(out, work)
    for p in sorted(out.iterdir()):
        print(f"{p.stat().st_size:>9}  {p.name}")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "/out"))
