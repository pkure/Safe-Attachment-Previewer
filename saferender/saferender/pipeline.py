# hal-id: #HAL-20261110-0005-PK-R3
"""Safe-render pipeline: untrusted attachment in, harmless pictures + text + findings out.

Runs INSIDE the offline container (no network, read-only root, no capabilities, non-root).
  python -m saferender.pipeline --in /in --out /out --case <case-id>
/in   read-only: the attachment(s) for ONE case
/out  report.json + pages/*.png. Only freshly encoded PNGs and JSON text ever leave; the original never does.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pypdf
import pypdfium2 as pdfium
import pypdfium2.raw as pdfium_c
import zxingcpp
from PIL import Image

from . import extract as X
from . import formats as F

Image.MAX_IMAGE_PIXELS = F.LIMITS["max_pixels"]  # decompression-bomb guard for every Pillow decode
RENDER_SCALE = 2.0  # 144 dpi: readable text, decodable QR codes
THUMB_W = 160
OCR_MIN_CHARS = 40  # a page with less real text than this is probably a scan/screenshot
CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PDF_KEYWORDS = [b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile", b"/XFA", b"/RichMedia",
                b"/SubmitForm", b"/ImportData"]
PDF_HOT = {"/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/SubmitForm", "/ImportData"}
KIND_LABEL = {"pe": "a Windows executable", "ole": "a legacy Office/OLE file", "zip": "a zip archive",
              "rtf": "RTF", "image": "an image", "other": "unknown data"}
DOMAINISH = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b")


class Case:
    def __init__(self, out: Path):
        self.out, self.files, self.timing = out, [], {}
        (out / "pages").mkdir(parents=True, exist_ok=True)

    def new_file(self, name: str, path: Path, parent: str | None) -> dict:
        f = {"id": f"f{len(self.files) + 1}", "name": name, "parent": parent, "size": path.stat().st_size,
             "sha256": sha256(path), "kind": F.sniff(path), "av": None, "flags": [], "notes": [], "pages": [],
             "pageCount": 0, "links": [], "qr": [], "phones": [], "emails": [], "macros": None, "pdfActive": None,
             "htmlSignals": None, "text": None, "children": [], "escalate": None, "_path": str(path)}
        self.files.append(f)
        return f


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def flag(f: dict, severity: str, text: str, page: int | None = None) -> None:
    f["flags"].append({"severity": severity, "text": text, "page": page})


def add_link(f: dict, url: str, page: int | None, source: str, anchor: str | None = None,
             rect: list[float] | None = None) -> None:
    url = X.clean_url(url)
    if not url or len(url) > 4096:
        return
    for link in f["links"]:
        if link["url"].lower() == url.lower() and link["page"] == page:
            if source not in link["sources"]:
                link["sources"].append(source)
            if rect and not link["rect"]:
                link["rect"] = rect
            return
    link = {"url": url, "defanged": X.defang(url), "host": X.host_of(url), "page": page, "sources": [source],
            "anchor": (anchor or "").strip()[:300] or None, "rect": rect}
    f["links"].append(link)
    # Phishing tell: the visible text names one site, the link opens another.
    shown = DOMAINISH.findall(link["anchor"] or "")
    if shown and link["host"] and not any(link["host"] == d.lower() or link["host"].endswith("." + d.lower())
                                          for d in shown):
        flag(f, "high", f"link text shows '{shown[0]}' but opens {link['defanged']}", page)


def scan_text(f: dict, text: str, page: int | None, source: str) -> None:
    for u in X.find_urls(text, ocr=source == "ocr"):
        add_link(f, u, page, source)
    for e in X.find_emails(text):
        if not any(x["addr"] == e and x["page"] == page for x in f["emails"]):
            f["emails"].append({"addr": e, "page": page})
    for n in X.find_phones(text):
        if not any(x["number"] == n and x["page"] == page for x in f["phones"]):
            f["phones"].append({"number": n, "page": page, "source": source})


# ---------------------------------------------------------------- pages
def save_page(case: Case, f: dict, n: int, img: Image.Image) -> dict:
    """Re-encode from raw pixels: nothing from the source file's own image encoding survives."""
    img = img.convert("RGB")
    stem = f"{f['id']}-p{n:03d}"
    img.save(case.out / "pages" / f"{stem}.png", "PNG", optimize=True)
    t = img.copy()
    t.thumbnail((THUMB_W, THUMB_W * 2))
    t.save(case.out / "pages" / f"{stem}.t.png", "PNG", optimize=True)
    page = {"n": n, "image": f"pages/{stem}.png", "thumb": f"pages/{stem}.t.png", "w": img.width, "h": img.height,
            "chars": 0, "ocr": False, "text": ""}
    f["pages"].append(page)
    return page


def decode_qr(f: dict, page: dict, img: Image.Image) -> None:
    try:
        results = zxingcpp.read_barcodes(img)
    except Exception:
        return
    for r in results:
        p = r.position
        xs, ys = [p.top_left.x, p.top_right.x, p.bottom_left.x, p.bottom_right.x], \
                 [p.top_left.y, p.top_right.y, p.bottom_left.y, p.bottom_right.y]
        rect = [min(xs) / img.width, min(ys) / img.height, (max(xs) - min(xs)) / img.width,
                (max(ys) - min(ys)) / img.height]
        text = r.text or ""
        is_url = bool(X.find_urls(text)) or text.lower().startswith(("http:", "https:"))
        f["qr"].append({"text": text[:2000], "format": str(r.format).rsplit(".", 1)[-1], "page": page["n"],
                        "isUrl": is_url, "defanged": X.defang(text) if is_url else None, "rect": rect})
        flag(f, "medium", "QR code" + (f" opens {X.defang(text)}" if is_url else "") + " (quishing check)", page["n"])
        if is_url:
            add_link(f, text, page["n"], "qr", rect=rect)


def ocr(png: Path) -> str:
    env = {**os.environ, "OMP_THREAD_LIMIT": "1"}
    try:
        r = subprocess.run(["tesseract", str(png), "stdout", "-l", "eng", "--psm", "3"], capture_output=True,
                           text=True, timeout=F.LIMITS["ocr_timeout_s"], env=env)
        return r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def pdf_keywords(path: Path) -> dict:
    raw = path.read_bytes()
    raw = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), raw)  # undo /J#61vaScript tricks
    counts = {}
    for kw in PDF_KEYWORDS:
        n = len(re.findall(re.escape(kw) + rb"(?![A-Za-z])", raw))
        if n:
            counts[kw.decode()] = n
    return counts


def pdf_annotations(path: Path, max_pages: int) -> tuple[dict[int, list], list[str]]:
    """{page index: [(uri, rect)]} from link annotations, plus notes."""
    out, notes = {}, []
    try:
        reader = pypdf.PdfReader(str(path), strict=False)
        if reader.is_encrypted and not reader.decrypt(""):
            return {}, ["password-protected PDF"]
        for i, p in enumerate(reader.pages[:max_pages]):
            for a in (p.get("/Annots") or []):
                obj = a.get_object()
                if obj.get("/Subtype") != "/Link":
                    continue
                act = obj.get("/A")
                act = act.get_object() if act is not None else {}
                uri = act.get("/URI")
                if uri:
                    rect = [float(v) for v in obj.get("/Rect", [0, 0, 0, 0])]
                    out.setdefault(i, []).append((str(uri), rect))
                elif act.get("/S") == "/Launch":
                    out.setdefault(i, []).append(("launch:" + str(act.get("/F", "")), None))
    except Exception as e:  # malformed PDFs are normal in this job; pdfium may still render them
        notes.append(f"annotation parse error: {type(e).__name__}")
    return out, notes


def render_pdf(case: Case, f: dict, path: Path) -> None:
    t0 = time.monotonic()
    f["pdfActive"] = pdf_keywords(path)
    hot = sorted(k for k in f["pdfActive"] if k in PDF_HOT)
    if hot:
        flag(f, "high", "PDF active content: " + ", ".join(hot))
    try:
        pdf = pdfium.PdfDocument(str(path))
    except pdfium.PdfiumError as e:
        f["notes"].append(f"could not open PDF: {e}")
        return
    total = len(pdf)
    f["pageCount"] = total
    limit = min(total, F.LIMITS["max_pages"])
    if total > limit:
        f["notes"].append(f"showing first {limit} of {total} pages")
    annots, notes = pdf_annotations(path, limit)
    f["notes"] += notes
    ocr_jobs = []
    for i in range(limit):
        pg = pdf[i]
        w, h = pg.get_size()
        img = pg.render(scale=RENDER_SCALE).to_pil()
        page = save_page(case, f, i + 1, img)
        tp = pg.get_textpage()
        text = tp.get_text_range()
        page["text"], page["chars"] = text[:20000], len(text.strip())
        scan_text(f, text, i + 1, "text")
        for uri, rect in annots.get(i, []):
            if uri.startswith("launch:"):
                flag(f, "high", f"PDF Launch action: {uri[7:][:200]}", i + 1)
                continue
            anchor = tp.get_text_bounded(*rect) if rect else None
            norm = [rect[0] / w, 1 - rect[3] / h, (rect[2] - rect[0]) / w, (rect[3] - rect[1]) / h] if rect else None
            add_link(f, uri, i + 1, "link", anchor, norm)
        has_images = bool(list(pg.get_objects(filter=[pdfium_c.FPDF_PAGEOBJ_IMAGE], max_depth=2)))
        decode_qr(f, page, img)
        if has_images or page["chars"] < OCR_MIN_CHARS:
            ocr_jobs.append(page)
        tp.close()
        pg.close()
    pdf.close()
    case.timing.setdefault("render_s", 0)
    case.timing["render_s"] += round(time.monotonic() - t0, 2)
    run_ocr(case, f, ocr_jobs)


def run_ocr(case: Case, f: dict, pages: list[dict]) -> None:
    if not pages or not shutil.which("tesseract"):
        return
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(os.cpu_count() or 2, 2)) as pool:
        texts = list(pool.map(lambda p: ocr(case.out / p["image"]), pages))
    for page, text in zip(pages, texts):
        page["ocr"] = True
        if text.strip():
            page["text"] = (page["text"] + "\n\n[OCR]\n" + text)[:40000]
            scan_text(f, text, page["n"], "ocr")
    case.timing.setdefault("ocr_s", 0)
    case.timing["ocr_s"] += round(time.monotonic() - t0, 2)
    case.timing["ocr_pages"] = case.timing.get("ocr_pages", 0) + len(pages)


def render_image(case: Case, f: dict, path: Path) -> None:
    try:
        with Image.open(path) as im:
            frames = getattr(im, "n_frames", 1)
            im.seek(0)
            img = im.convert("RGB")
    except (Image.DecompressionBombError, OSError, ValueError) as e:
        f["notes"].append(f"image not rendered: {type(e).__name__}")
        return
    if frames > 1:
        f["notes"].append(f"showing frame 1 of {frames}")
    f["pageCount"] = 1
    page = save_page(case, f, 1, img)
    decode_qr(f, page, img)
    run_ocr(case, f, [page])


# ---------------------------------------------------------------- dispatch
def process(case: Case, path: Path, name: str, parent: str | None, depth: int, work: Path, budget: dict) -> None:
    f = case.new_file(name, path, parent)
    ext = Path(name).suffix.lower()
    kind = f["kind"]
    if ext in F.EXEC_EXT or kind == "pe":
        flag(f, "high", "executable file (Windows PE)" if kind == "pe" else f"executable or script file type ({ext})")
        if kind == "pe" or not looks_like_text(path):
            # Never executed, never rendered. This is what the paid sandbox (e.g. CrowdStrike) is for.
            f["escalate"] = "Executable file: can't be previewed safely. Escalate: hash lookup, then detonation sandbox."
    expected = {".pdf": {"pdf"}, **{e: {"image"} for e in F.IMAGE_EXT},
                **{e: {"ole", "zip", "rtf"} for e in F.OFFICE_EXT}, ".zip": {"zip"}}.get(ext)
    if expected and kind not in expected:
        flag(f, "high", f"file is not what its name says: named {ext}, content is {KIND_LABEL.get(kind, kind)}")
        if kind == "pe":
            f["escalate"] = "Disguised executable. Escalate: hash lookup, then detonation sandbox."
    if kind == "zip" and not F.is_ooxml_or_odf(path):
        if depth >= F.LIMITS["zip_depth"]:
            f["notes"].append("nested archive not unpacked (depth limit)")
            return
        kids, encrypted, notes = F.unpack_zip(path, work / f"{f['id']}_unzipped", budget)
        f["notes"] += notes
        if encrypted:
            flag(f, "medium", f"password-protected archive entries ({len(encrypted)}): AV can't see inside")
        for k in kids:
            child_name = k.name.split("-", 1)[1]
            f["children"].append(f"f{len(case.files) + 1}")
            process(case, k, child_name, f["id"], depth + 1, work, budget)
        return
    if kind == "pdf":
        render_pdf(case, f, path)
    elif kind in ("ole", "rtf", "zip") or ext in F.OFFICE_EXT:
        office(case, f, path, work)
    elif kind == "image":
        render_image(case, f, path)
    elif ext in F.TEXT_EXT or looks_like_text(path):
        is_html = ext in F.HTML_EXT or b"<html" in path.read_bytes()[:4096].lower()
        text, hrefs, signals = F.read_text(path, is_html)
        f["text"] = text[:200000]
        scan_text(f, text, None, "text")
        for h in hrefs:
            if re.match(r"(?i)^(https?|ftp)://|^www\.", h):
                add_link(f, h, None, "html")
        if is_html:
            f["htmlSignals"] = signals
            flag(f, "medium", "HTML attachment (a common credential-phishing and HTML-smuggling format)")
            if any(k.startswith(("password", "base64", "atob")) for k in signals):
                flag(f, "high", "HTML contains " + ", ".join(signals))
    else:
        f["notes"].append("no safe preview for this file type; hash and AV only")


def office(case: Case, f: dict, path: Path, work: Path) -> None:
    m = F.macros(path)
    if m:
        f["macros"] = m
        auto = [x["keyword"] for x in m["findings"] if x["type"] == "AutoExec"]
        sus = [x["keyword"] for x in m["findings"] if x["type"] == "Suspicious"]
        flag(f, "high" if (auto or sus) else "medium", f"{len(m['modules'])} VBA macro module(s)"
             + (f"; auto-run: {', '.join(auto)}" if auto else "") + (f"; suspicious: {', '.join(sus)}" if sus else ""))
        for mod in m["modules"]:
            scan_text(f, mod["code"], None, "macro")
    for rel in F.ooxml_relationships(path):
        if rel["kind"] == "hyperlink":
            add_link(f, rel["target"], None, "embedded")
        elif rel["kind"] in ("attachedTemplate", "oleObject", "frame", "subDocument"):
            flag(f, "high", f"remote {rel['kind']} loads {X.defang(rel['target'])} (template injection)")
    pdf, err = F.office_to_pdf(path, work / f"{f['id']}_office")
    if err:
        f["notes"].append(err)
        return
    page_links_before = {(link["url"].lower()) for link in f["links"] if link["page"] is None}
    render_pdf(case, f, pdf)
    f["pdfActive"] = None  # keywords of OUR converted PDF say nothing about the original
    f["flags"] = [x for x in f["flags"] if not x["text"].startswith("PDF active content")]
    # Embedded hyperlinks that the converted PDF also placed on a page: keep only the page-located copy.
    located = {link["url"].lower() for link in f["links"] if link["page"] is not None}
    f["links"] = [link for link in f["links"] if link["page"] is not None or link["url"].lower() not in located
                  or link["url"].lower() not in page_links_before]


def looks_like_text(path: Path) -> bool:
    chunk = path.read_bytes()[:4096]
    return bool(chunk) and b"\x00" not in chunk and sum(32 <= b < 127 or b in (9, 10, 13) for b in chunk) / len(chunk) > .9


# ---------------------------------------------------------------- report
def isolation() -> dict:
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()
        internet = True
    except OSError:
        internet = False
    try:
        socket.getaddrinfo("www.microsoft.com", 443)
        dns = True
    except OSError:
        dns = False
    return {"internetReached": internet, "dnsResolved": dns}


def verdict(files: list[dict]) -> str:
    if any(f["av"] for f in files):
        return "MALICIOUS"
    if any(x["severity"] in ("high", "medium") for f in files for x in f["flags"]):
        return "SUSPICIOUS"
    return "NO DETECTIONS" if files else "NO FILE ATTACHMENTS"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="/in")
    ap.add_argument("--out", default="/out")
    ap.add_argument("--case", required=True)
    a = ap.parse_args()
    if not CASE_RE.match(a.case):
        raise SystemExit("invalid case id")
    t_start = time.monotonic()
    out = Path(a.out)
    case = Case(out)
    work = Path(tempfile.mkdtemp(prefix="case-", dir=os.environ.get("TMPDIR", "/tmp")))
    budget = {"files": 0, "bytes": 0}
    inputs = sorted(p for p in Path(a.inp).iterdir() if p.is_file())
    for i, src in enumerate(inputs, 1):
        dst = work / f"in{i:02d}-{F.safe_name(src.name)}"
        shutil.copyfile(src, dst)  # work on a private copy; /in stays read-only
        budget["files"] += 1
        process(case, dst, src.name, None, 0, work, budget)
    t0 = time.monotonic()
    hits, av_status = F.clamav_scan(work)
    case.timing["av_s"] = round(time.monotonic() - t0, 2)
    for f in case.files:
        for path, sig in hits.items():
            if path == f["_path"] or path.startswith(f["_path"] + "/"):
                f["av"] = sig
    pages = sum(len(f["pages"]) for f in case.files)
    attention = sum(1 for f in case.files for p in f["pages"]
                    if any(x["page"] == p["n"] for k in ("links", "qr", "phones", "emails", "flags") for x in f[k]))
    case.timing["total_s"] = round(time.monotonic() - t_start, 2)
    report = {
        "schema": 1, "caseId": a.case, "verdict": verdict(case.files),
        "generatedUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "isolation": isolation(), "engines": {"clamav": F.clamav_version(), "clamavStatus": av_status},
        "timing": case.timing,
        "summary": {"files": len(case.files), "pages": pages, "attentionPages": attention,
                    "links": sum(len(f["links"]) for f in case.files), "qr": sum(len(f["qr"]) for f in case.files),
                    "phones": sum(len(f["phones"]) for f in case.files),
                    "flags": sum(len(f["flags"]) for f in case.files)},
        "files": [{k: v for k, v in f.items() if not k.startswith("_")} for f in case.files],
    }
    (out / "report.json").write_text(json.dumps(report, indent=1))
    print(f"{a.case}: {report['verdict']} files={len(case.files)} pages={pages} links={report['summary']['links']} "
          f"qr={report['summary']['qr']} phones={report['summary']['phones']} total={case.timing['total_s']}s "
          f"internet={report['isolation']['internetReached']} dns={report['isolation']['dnsResolved']}")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
