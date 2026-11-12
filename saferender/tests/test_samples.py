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
