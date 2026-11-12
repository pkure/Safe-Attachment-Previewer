#!/usr/bin/env python3
# hal-id: #HAL-20261107-0019-PK-P1
"""Build the two things the POC uploads to blob storage (stdlib only, run with `python3 -I`).

dist/tools.zip   offline toolkit for vm-sandbox: Windows embeddable Python 3.12 + oletools + pdfid + analyze.ps1
dist/samples/*   BENIGN test samples: EICAR test string in a zip, PDF with harmless JavaScript,
                 xlsm with a harmless MsgBox macro, clean PDF.

Usage: build_artifacts.py <wheels_dir> <python_embed_zip> <vbaProject.bin> <analyze.ps1> <dist_dir>
Nothing downloaded here is executed on this Mac: wheels and the embeddable Python are only unzipped/re-zipped.
"""

import hashlib
import io
import sys
import zipfile
from pathlib import Path

# Standard EICAR anti-malware test string (not malware; every AV detects it by design).
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def build_tools(wheels: Path, embed_zip: Path, analyze: Path, out: Path) -> None:
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        with zipfile.ZipFile(embed_zip) as e:
            for info in e.infolist():
                data = e.read(info)
                if info.filename.endswith("._pth"):
                    # Embeddable Python ignores site-packages unless the ._pth file lists it.
                    data = data.replace(b"#import site", b"import site") + b"\r\nLib\\site-packages\r\n"
                z.writestr(f"python/{info.filename}", data)
        wheel_files = sorted(wheels.glob("*.whl"))
        if not wheel_files:
            raise SystemExit(f"no wheels in {wheels}")
        for whl in wheel_files:
            with zipfile.ZipFile(whl) as w:  # a wheel is a zip laid out exactly like site-packages
                for info in w.infolist():
                    if not info.is_dir():
                        z.writestr(f"python/Lib/site-packages/{info.filename}", w.read(info))
        z.write(analyze, "analyze.ps1")


def pdf(objects: list[bytes]) -> bytes:
    """Assemble a minimal valid PDF with a correct xref table."""
    buf = io.BytesIO()
    buf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(buf.tell())
        buf.write(b"%d 0 obj\n" % i + body + b"\nendobj\n")
    xref = buf.tell()
    buf.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for off in offsets:
        buf.write(b"%010d 00000 n \n" % off)
    buf.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref))
    return buf.getvalue()


def text_page(text: str, extra_catalog: bytes = b"") -> list[bytes]:
    stream = b"BT /F1 14 Tf 72 720 Td (" + text.encode() + b") Tj ET"
    return [
        b"<< /Type /Catalog /Pages 2 0 R " + extra_catalog + b">>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]


XLSM_PARTS = {
    "[Content_Types].xml": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    ),
    "_rels/.rels": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/></Relationships>'
    ),
    "xl/workbook.xml": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Budget" sheetId="1" r:id="rId1"/></sheets></workbook>'
    ),
    "xl/_rels/workbook.xml.rels": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" '
        'Target="vbaProject.bin"/></Relationships>'
    ),
    "xl/worksheets/sheet1.xml": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
        '<row r="1"><c r="A1" t="inlineStr"><is><t>TEST SAMPLE - attachment sandbox POC</t></is></c></row>'
        "</sheetData></worksheet>"
    ),
}


def build_samples(vba_bin: Path, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out / "invoice-eicar.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("invoice.com", EICAR)
    js = b"/OpenAction << /S /JavaScript /JS (app.alert\\('TEST SAMPLE - attachment sandbox POC'\\);) >>"
    (out / "statement-js.pdf").write_bytes(pdf(text_page("TEST SAMPLE - PDF with harmless JavaScript", js)))
    (out / "statement-clean.pdf").write_bytes(pdf(text_page("TEST SAMPLE - clean PDF, no active content")))
    with zipfile.ZipFile(out / "budget-macro.xlsm", "w", zipfile.ZIP_DEFLATED) as z:
        for name, xml in XLSM_PARTS.items():
            z.writestr(name, xml)
        z.write(vba_bin, "xl/vbaProject.bin")  # XlsxWriter's example project: one MsgBox macro


def main() -> None:
    if len(sys.argv) != 6:
        raise SystemExit(__doc__)
    wheels, embed_zip, vba_bin, analyze, dist = map(Path, sys.argv[1:])
    dist.mkdir(parents=True, exist_ok=True)
    build_tools(wheels, embed_zip, analyze, dist / "tools.zip")
    build_samples(vba_bin, dist / "samples")
    for f in sorted([dist / "tools.zip", *sorted((dist / "samples").iterdir())]):
        print(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.stat().st_size:>9}  {f.name}")


if __name__ == "__main__":
    main()
