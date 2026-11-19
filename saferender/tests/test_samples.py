# hal-id: #HAL-20261110-0009-PK-T2
"""End to end: run the real pipeline on every benign sample and check what an analyst would see.

Samples: /samples (mounted read-only by scripts/preview-local.sh test). Generated ones come from make_samples.py;
v1 ones (EICAR zip, macro xlsm, JS PDF, clean PDF) from scripts/build_artifacts.py.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SAMPLES = Path(os.environ.get("SAMPLES", "/samples"))


def run(tmp_path: Path, name: str) -> dict:
    src = SAMPLES / name
    if not src.exists():
        pytest.skip(f"sample {name} not built")
    inp, out = tmp_path / "in", tmp_path / "out"
    inp.mkdir()
    shutil.copy(src, inp / name)
    r = subprocess.run([sys.executable, "-m", "saferender.pipeline", "--in", str(inp), "--out", str(out),
                        "--case", "t1"], capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr[-2000:]
    rep = json.loads((out / "report.json").read_text())
    rep["_out"] = out
    print(r.stdout)
    return rep


def flags(rep):
    return [x["text"] for f in rep["files"] for x in f["flags"]]


def test_isolation_is_recorded_and_offline(tmp_path):
    rep = run(tmp_path, "statement-clean.pdf")
    assert rep["isolation"] == {"internetReached": False, "dnsResolved": False}


def test_clean_pdf(tmp_path):
    rep = run(tmp_path, "statement-clean.pdf")
    assert rep["verdict"] == "NO DETECTIONS"
    assert rep["summary"]["pages"] == 1
    assert (rep["_out"] / rep["files"][0]["pages"][0]["image"]).exists()


def test_js_pdf(tmp_path):
    rep = run(tmp_path, "statement-js.pdf")
    assert rep["verdict"] == "SUSPICIOUS"
    assert any("PDF active content" in t and "/JavaScript" in t for t in flags(rep))


def test_eicar_zip(tmp_path):
    rep = run(tmp_path, "invoice-eicar.zip")
    if rep["engines"]["clamavStatus"] != "ok":
        pytest.skip("image built without ClamAV")
    assert rep["verdict"] == "MALICIOUS"
    assert any(f["av"] and "Eicar" in f["av"] for f in rep["files"])


def test_macro_xlsm(tmp_path):
    rep = run(tmp_path, "budget-macro.xlsm")
    f = rep["files"][0]
    assert f["macros"] and f["macros"]["modules"], "macro source should be extracted"
    assert rep["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    assert f["pages"], "the spreadsheet itself should also render as a page"


def test_long_report(tmp_path):
    rep = run(tmp_path, "long-report.pdf")
    f = rep["files"][0]
    assert f["pageCount"] >= 20
    by_url = {link["url"]: link for link in f["links"]}
    hidden = by_url["https://login-micros0ft-support.example/verify?id=7731"]
    assert "link" in hidden["sources"] and hidden["rect"], "hidden 'Click here' link with its position"
    assert any("contoso.com" in t and "payments-portal" in t for t in flags(rep)), "deceptive link text"
    ocr = [link for link in f["links"] if "ocr" in link["sources"] and "overdue-billing.example" in link["url"]]
    assert ocr, "URL that exists only in a scanned image must be found by OCR"
    assert any(q["text"] == "https://quish-test.example/login" for q in f["qr"]), "QR code decoded"
    assert any(p["number"] == "+18005550143" for p in f["phones"]), "callback phone number"
    assert rep["summary"]["attentionPages"] >= 4
    assert rep["verdict"] == "SUSPICIOUS"


def test_docx_hidden_link(tmp_path):
    rep = run(tmp_path, "invoice-hidden-link.docx")
    urls = [link["url"] for f in rep["files"] for link in f["links"]]
    assert "https://login-micros0ft-support.example/verify?id=7731" in urls
    assert rep["files"][0]["pages"]


def test_image_qr(tmp_path):
    rep = run(tmp_path, "photo-qr.png")
    assert rep["files"][0]["qr"][0]["isUrl"]
    assert rep["verdict"] == "SUSPICIOUS"


def test_disguised_exe(tmp_path):
    rep = run(tmp_path, "invoice.pdf")
    f = rep["files"][0]
    assert any("not what its name says" in t for t in flags(rep))
    assert f["escalate"] and not f["pages"], "never rendered, escalation recommended"


def test_script_shown_as_text(tmp_path):
    rep = run(tmp_path, "update.js")
    f = rep["files"][0]
    assert "WScript.Echo" in f["text"]
    assert any(link["host"] == "dl-test.example" for link in f["links"])
    assert any("executable or script" in t for t in flags(rep))


def test_forwarded_email(tmp_path):
    rep = run(tmp_path, "fwd-account-alert.eml")
    mail = rep["files"][0]
    assert mail["email"]["Subject"].startswith("Action required")
    t = flags(rep)
    assert any("sender name says" in x for x in t), "spoofed display name"
    assert any("sender authentication failed" in x and "DMARC" in x for x in t)
    assert any("replies go to" in x for x in t)
    assert any("imitates microsoft" in x for x in t), "lookalike sender/link domain"
    assert any("link text shows 'account.microsoft.com'" in x for x in t), "deceptive anchor in HTML body"
    kids = {f["name"]: f for f in rep["files"] if f["parent"] == mail["id"]}
    assert {"qr-mfa.png", "Security-Report.pdf"} <= set(kids), kids.keys()
    assert kids["qr-mfa.png"]["qr"][0]["text"] == "https://mfa-reverify.example/start"
    assert any(p["number"] == "+18005550177" for p in kids["Security-Report.pdf"]["phones"])
    assert kids["Security-Report.pdf"]["pages"]
    assert rep["verdict"] == "SUSPICIOUS"


def test_bec_letter_shows_content_and_number(tmp_path):
    rep = run(tmp_path, "vendor-bank-change.docx")
    f = rep["files"][0]
    assert f["pages"] and "banking details have changed" in f["pages"][0]["text"]
    assert any(p["number"] == "+18005550187" for p in f["phones"])


def test_html_login_page(tmp_path):
    rep = run(tmp_path, "shared-document.html")
    t = flags(rep)
    assert any("password fields" in x for x in t)
    assert any("imitates docusign" in x for x in t)


def test_voicemail_screenshot_ocr(tmp_path):
    rep = run(tmp_path, "voicemail.png")
    f = rep["files"][0]
    assert any("vm-listen.example" in link["url"] for link in f["links"])
    assert any(p["number"] == "+18005550199" for p in f["phones"])


def test_clean_spreadsheet(tmp_path):
    rep = run(tmp_path, "timesheet.xlsx")
    assert rep["files"][0]["pages"]
    assert rep["verdict"] == "NO DETECTIONS", flags(rep)


def test_tracked_links_in_legit_mail_are_not_alarming(tmp_path):
    rep = run(tmp_path, "newsletter-tracked-links.eml")
    sev = [x["severity"] for f in rep["files"] for x in f["flags"]]
    assert sev == ["low"], flags(rep)
    assert rep["verdict"] == "NO DETECTIONS"


def test_small_photo_is_upscaled_for_ocr(tmp_path):
    rep = run(tmp_path, "receipt-photo.jpg")
    f = rep["files"][0]
    assert "50834" in f["pages"][0]["text"]
    assert any(p["number"] == "+17075550136" for p in f["phones"])


# ---------------------------------------------------------------- depth (deep.py): hidden below the first layer
def links_of(rep):
    return {link["url"]: link for f in rep["files"] for link in f["links"]}


def test_pdf_active_content_hidden_in_object_stream(tmp_path):
    rep = run(tmp_path, "statement-objstm.pdf")
    f = rep["files"][0]
    t = flags(rep)
    assert any("hides active content inside compressed objects" in x and "/JavaScript" in x for x in t), t
    assert any("PDF form sends what you type to" in x and "objstm-form" in x for x in t), t
    by_url = links_of(rep)
    assert "decoded" in by_url["https://objstm-hidden.example/pay"]["sources"], "JS link built from pieces"
    assert "https://objstm-form.example/collect" in by_url
    assert f["scripts"] and "launchURL" in f["scripts"][0]["code"]
    assert f["pages"], "still renders"
    assert rep["verdict"] == "SUSPICIOUS"


def test_pdf_embedded_file_is_unpacked(tmp_path):
    rep = run(tmp_path, "statement-embedded.pdf")
    pdf = rep["files"][0]
    kids = [f for f in rep["files"] if f["parent"] == pdf["id"]]
    assert [k["name"] for k in kids] == ["invoice-details.html"]
    assert any(link["url"] == "https://embedded-link.example/login" for link in kids[0]["links"])
    assert any("embedded file" in x for x in flags(rep))


def test_html_smuggling(tmp_path):
    rep = run(tmp_path, "smuggle-invoice.html")
    page = rep["files"][0]
    t = flags(rep)
    assert any("HTML smuggling" in x and "invoice-7731.zip" in x for x in t), t
    by_name = {f["name"]: f for f in rep["files"]}
    assert by_name["invoice-7731.zip"]["parent"] == page["id"]
    assert any(link["url"] == "https://smuggled-zip.example/pay" for link in by_name["readme.txt"]["links"])
    by_url = links_of(rep)
    assert "decoded" in by_url["https://charcode-hidden.example/next"]["sources"]
    assert "decoded" in by_url["https://reversed-hidden.example/next"]["sources"]
    assert page["pages"], "the HTML is drawn as a page too"


def test_qr_drawn_as_html_table(tmp_path):
    rep = run(tmp_path, "qr-table.html")
    assert any(q["text"] == "https://table-qr.example/scan" for f in rep["files"] for q in f["qr"])


def test_inverted_qr(tmp_path):
    rep = run(tmp_path, "qr-inverted.png")
    assert rep["files"][0]["qr"][0]["text"] == "https://inverted-qr.example/scan"


def test_plain_html_has_no_hidden_link_noise(tmp_path):
    rep = run(tmp_path, "shared-document.html")
    assert not any("only visible after decoding" in x or "builds file(s)" in x for x in flags(rep))


def test_local_files_never_drawn_into_html_pages(tmp_path):
    rep = run(tmp_path, "local-file-probe.html")
    f = rep["files"][0]
    assert f["pages"] and any("external resource" in n for n in f["notes"]), f["notes"]
    from PIL import Image
    img = Image.open(rep["_out"] / f["pages"][0]["image"]).convert("RGB")
    # The Debian logo is red; the probe text is black. Any reddish pixel means the local image was drawn.
    assert not any(r > 120 and g < 80 and b < 100 for r, g, b in img.getdata()), "local image leaked into the page"


# ---------------------------------------------------------------- tier 2: archives, disk images, passwords
def by_name(rep):
    return {f["name"]: f for f in rep["files"]}


def test_password_from_email_unlocks_attachments(tmp_path):
    rep = run(tmp_path, "documents-locked.eml")
    files = by_name(rep)
    urls = {link["url"] for f in rep["files"] for link in f["links"]}
    assert {"https://pw-aes-zip.example/pay", "https://pw-7z.example/pay", "https://pw-pdf.example/view"} <= urls, urls
    assert {"pay-aes.html", "pay-7z.html"} <= set(files), "children of the locked archives"
    for name in ("docs-aes.zip", "docs-hidden-names.7z", "statement-locked.pdf"):
        assert any("opened with the password '4471' (found in the email)" in x["text"] for x in files[name]["flags"]), name
    assert files["statement-locked.pdf"]["pages"], "the unlocked PDF is rendered"


def test_unknown_password_is_reported(tmp_path):
    rep = run(tmp_path, "locked-unknown.zip")
    assert any("contents weren't checked" in x for x in flags(rep))
    assert len(rep["files"]) == 1 and rep["verdict"] == "SUSPICIOUS"


def test_iso_is_opened(tmp_path):
    rep = run(tmp_path, "shipping-docs.iso")
    iso = rep["files"][0]
    assert iso["kind"] == "iso" and any("disk image" in x["text"] for x in iso["flags"])
    assert any(link["url"] == "https://iso-inside.example/open" for f in rep["files"] for link in f["links"])


def test_targz_two_layers(tmp_path):
    rep = run(tmp_path, "report.tar.gz")
    assert [f["kind"] for f in rep["files"]][:2] == ["gzip", "tar"]
    assert any(link["url"] == "https://targz-inside.example/report" for f in rep["files"] for link in f["links"])


def test_zip_iso_chain(tmp_path):
    rep = run(tmp_path, "delivery.zip")
    assert [f["kind"] for f in rep["files"]][:2] == ["zip", "iso"]
    assert any(link["url"] == "https://chain-iso.example/next" for f in rep["files"] for link in f["links"])


# ---------------------------------------------------------------- tier 2b: .msg, .lnk, OneNote, Office tricks
def test_outlook_msg(tmp_path):
    rep = run(tmp_path, "account-alert.msg")
    msg = rep["files"][0]
    assert msg["email"]["Subject"].startswith("Unusual sign-in"), msg.get("email")
    t = flags(rep)
    assert any("sender authentication failed" in x for x in t) and any("imitates microsoft" in x for x in t), t
    urls = {link["url"] for f in rep["files"] for link in f["links"]}
    assert {"https://msg-body.example/login", "https://msg-attach.example/pay"} <= urls, urls
    assert [f["name"] for f in rep["files"] if f["parent"] == msg["id"]] == ["review.html"]


def test_lnk_powershell_encoded(tmp_path):
    rep = run(tmp_path, "Invoice-7731.pdf.lnk")
    f = rep["files"][0]
    assert f["kind"] == "lnk" and not f["escalate"]
    t = flags(rep)
    assert any("shortcut runs" in x and "powershell" in x for x in t), t
    assert any(link["url"].startswith("https://lnk-payload.example/a.ps1") and "decoded" in link["sources"]
               for link in f["links"]), f["links"]


def test_office_embedded_package(tmp_path):
    rep = run(tmp_path, "contract-embedded.docx")
    doc = rep["files"][0]
    kids = [f for f in rep["files"] if f["parent"] == doc["id"]]
    assert [k["name"] for k in kids] == ["invoice.bat"], [k["name"] for k in kids]
    assert any("embedded file" in x["text"] for x in doc["flags"])
    assert any("olepkg-inside.example" in link["url"] for link in kids[0]["links"])


def test_dde_field(tmp_path):
    rep = run(tmp_path, "memo-dde.docx")
    assert any("DDE field" in x and "cmd.exe" in x for x in flags(rep)), flags(rep)


def test_protocol_handlers(tmp_path):
    t = flags(run(tmp_path, "update-required.html"))
    assert any("Windows program" in x and "ms-msdt:" in x for x in t), t
    assert any("Windows program" in x and "search-ms:" in x for x in t), t


def test_onenote_embedded_file(tmp_path):
    rep = run(tmp_path, "shared-notes.one")
    one = rep["files"][0]
    assert one["kind"] == "onenote" and any("OneNote file carries 1 embedded" in x["text"] for x in one["flags"])
    kid = [f for f in rep["files"] if f["parent"] == one["id"]][0]
    assert kid["name"].endswith(".hta")
    assert any(link["url"] == "https://onenote-hta.example/run" for link in kid["links"])


def test_renamed_ics_duplicate_and_invisible_subject(tmp_path):
    rep = run(tmp_path, "renamed-ics.eml")
    t = flags(rep)
    assert any("named .ics, content is a PDF" in x for x in t), t
    assert any("same file is attached 2 times" in x for x in t), t
    assert any("invisible character" in x and "subject" in x for x in t), t
    assert any("1 empty (0-byte) attachment" in x for x in t), t
