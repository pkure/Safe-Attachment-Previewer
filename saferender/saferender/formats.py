# hal-id: #HAL-20261110-0004-PK-R2
"""Per-format handlers for untrusted files. All run inside the offline container (see Dockerfile / run flags).

Every limit lives in LIMITS so there is one place to tune them.
"""

from __future__ import annotations

import html.parser
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

LIMITS = {
    "max_files": 50,  # after unpacking archives
    "max_total_bytes": 200 * 1024 * 1024,  # zip-bomb guard (uncompressed)
    "max_zip_ratio": 200,  # uncompressed / compressed per entry
    "zip_depth": 2,
    "max_pages": 300,  # per document
    "max_pixels": 40_000_000,  # image decompression-bomb guard
    "office_timeout_s": 120,
    "ocr_timeout_s": 60,
    "av_timeout_s": 300,
    "max_text_bytes": 2 * 1024 * 1024,
    "max_macro_chars": 200_000,
}

OFFICE_EXT = {".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm", ".xlsb", ".ppt", ".pptx",
              ".pptm", ".rtf", ".odt", ".ods", ".odp"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp"}
TEXT_EXT = {".txt", ".csv", ".htm", ".html", ".xhtml", ".svg", ".xml", ".json", ".eml"}
EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
            ".wsh", ".hta", ".lnk", ".msi", ".jar", ".iso", ".img", ".vhd", ".vhdx", ".one", ".reg", ".cpl", ".appx"}
HTML_EXT = {".htm", ".html", ".xhtml", ".svg", ".shtml"}


def sniff(path: Path) -> str:
    """Type by content, not by the (attacker-chosen) extension."""
    with open(path, "rb") as f:
        head = f.read(2048)
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "ole"  # legacy Office / msg
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"  # also OOXML (docx/xlsx/pptx) and ODF
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM", b"II*\x00", b"MM\x00*")) or head[8:12] == b"WEBP":
        return "image"
    if head.startswith(b"MZ"):
        return "pe"
    return "other"


def is_ooxml_or_odf(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
    except zipfile.BadZipFile:
        return False
    return "[Content_Types].xml" in names or "mimetype" in names


# ---------------------------------------------------------------- archives
def safe_name(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return re.sub(r"[^A-Za-z0-9._-]", "_", base)[:120] or "unnamed"


def unpack_zip(path: Path, dest: Path, budget: dict) -> tuple[list[Path], list[str], list[str]]:
    """Extract flat, sanitized, size-capped. Returns (files, encrypted_entry_names, notes)."""
    files, encrypted, notes = [], [], []
    dest.mkdir(parents=True, exist_ok=True)
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        return [], [], [f"not a readable zip: {e}"]
    with z:
        for info in z.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                encrypted.append(info.filename)
                continue
            if budget["files"] >= LIMITS["max_files"]:
                notes.append("file limit reached; remaining archive entries skipped")
                break
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > LIMITS["max_zip_ratio"] or budget["bytes"] + info.file_size > LIMITS["max_total_bytes"]:
                notes.append(f"skipped {safe_name(info.filename)}: size/ratio limit (possible zip bomb)")
                continue
            out = dest / f"{len(files) + 1:02d}-{safe_name(info.filename)}"  # never trust entry paths
            with z.open(info) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            budget["files"] += 1
            budget["bytes"] += info.file_size
            files.append(out)
    return files, encrypted, notes


# ---------------------------------------------------------------- office
REL_RE = re.compile(r"<Relationship\b[^>]*>", re.I)
ATTR_RE = re.compile(r'(\w+)="([^"]*)"')


def ooxml_relationships(path: Path) -> list[dict]:
    """External targets in OOXML .rels: hyperlinks (incl. ones hidden behind 'Click here'),
    remote templates (template injection), external OLE objects."""
    out = []
    try:
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if not n.endswith(".rels") or z.getinfo(n).file_size > 5_000_000:
                    continue
                xml = z.read(n).decode("utf-8", "replace")
                for tag in REL_RE.findall(xml):
                    a = dict(ATTR_RE.findall(tag))
                    if a.get("TargetMode", "").lower() != "external":
                        continue
                    kind = a.get("Type", "").rsplit("/", 1)[-1]
                    target = (a.get("Target", "").replace("&amp;", "&"))
                    out.append({"kind": kind, "target": target, "part": n})
    except (zipfile.BadZipFile, KeyError):
        pass
    return out


def macros(path: Path) -> dict | None:
    """VBA source + olevba keyword analysis. Static only: nothing is executed."""
    from oletools.olevba import VBA_Parser  # import here: slow to load, unneeded for PDFs

    try:
        vp = VBA_Parser(str(path))
    except Exception:  # not an Office container olevba understands
        return None
    try:
        if not vp.detect_vba_macros():
            return None
        modules, budget = [], LIMITS["max_macro_chars"]
        for _f, _s, name, code in vp.extract_macros():
            code = code if isinstance(code, str) else code.decode("utf-8", "replace")
            modules.append({"name": str(name), "code": code[:budget]})
            budget = max(budget - len(code), 0)
        findings = [{"type": t, "keyword": k, "description": d} for t, k, d in vp.analyze_macros()
                    if t in ("AutoExec", "Suspicious", "IOC")]
        return {"modules": modules, "findings": findings}
    finally:
        vp.close()


LO_PROFILE_XCU = """<?xml version="1.0" encoding="UTF-8"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="MacroSecurityLevel" oor:op="fuse"><value>3</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="DisableMacrosExecution" oor:op="fuse"><value>true</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Misc"><prop oor:name="UseLocking" oor:op="fuse"><value>false</value></prop></item>
</oor:items>
"""


def office_to_pdf(path: Path, workdir: Path) -> tuple[Path | None, str | None]:
    """Convert with LibreOffice in a throwaway profile that has macro execution disabled."""
    profile = workdir / "lo-profile"
    (profile / "user").mkdir(parents=True, exist_ok=True)
    (profile / "user" / "registrymodifications.xcu").write_text(LO_PROFILE_XCU)
    outdir = workdir / "converted"
    outdir.mkdir(exist_ok=True)
    env = {"HOME": str(workdir), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
    cmd = ["soffice", f"-env:UserInstallation=file://{profile}", "--headless", "--norestore", "--nologo",
           "--nolockcheck", "--convert-to", "pdf", "--outdir", str(outdir), str(path)]
    try:
        subprocess.run(cmd, env=env, capture_output=True, timeout=LIMITS["office_timeout_s"], check=False)
    except subprocess.TimeoutExpired:
        return None, "office conversion timed out"
    pdf = outdir / (path.stem + ".pdf")
    return (pdf, None) if pdf.exists() else (None, "office conversion failed")


# ---------------------------------------------------------------- html / text
class _HtmlText(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.hrefs, self._skip = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        for k, v in attrs:
            if k in ("href", "src", "action", "formaction", "data") and v:
                self.hrefs.append(v.strip())

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.text.append(data)


def read_text(path: Path, is_html: bool) -> tuple[str, list[str], dict]:
    raw = path.read_bytes()[: LIMITS["max_text_bytes"]]
    txt = raw.decode("utf-8", "replace")
    if not is_html:
        return txt, [], {}
    p = _HtmlText()
    try:
        p.feed(txt)
    except Exception:
        pass
    signals = {
        "script tags": len(re.findall(r"(?i)<script\b", txt)),
        "forms": len(re.findall(r"(?i)<form\b", txt)),
        "password fields": len(re.findall(r"(?i)type\s*=\s*['\"]?password", txt)),
        "base64 blobs (HTML smuggling)": len(re.findall(r"[A-Za-z0-9+/]{2000,}={0,2}", txt)),
        "atob/Blob/msSaveOrOpenBlob": len(re.findall(r"\b(atob|new Blob|msSaveOrOpenBlob|createObjectURL)\b", txt)),
    }
    return re.sub(r"\s+\n", "\n", "".join(p.text)).strip(), p.hrefs, {k: v for k, v in signals.items() if v}


# ---------------------------------------------------------------- antivirus
def clamav_scan(root: Path) -> tuple[dict[str, str], str]:
    """{absolute path: signature}. Signatures are baked in at image build time (see Dockerfile)."""
    if os.environ.get("SAFERENDER_AV", "1") == "0" or not shutil.which("clamscan"):
        return {}, "unavailable"
    try:
        r = subprocess.run(["clamscan", "--no-summary", "--infected", "--recursive", "--stdout",
                            "--max-filesize=100M", "--max-scansize=200M", str(root)],
                           capture_output=True, text=True, timeout=LIMITS["av_timeout_s"])
    except subprocess.TimeoutExpired:
        return {}, "timed out"
    hits = {}
    for line in r.stdout.splitlines():
        m = re.match(r"^(.*): (.+) FOUND$", line.strip())
        if m:
            hits[m.group(1)] = m.group(2)
    return hits, "ok" if r.returncode in (0, 1) else f"error ({r.returncode})"


def clamav_version() -> str | None:
    if not shutil.which("clamscan"):
        return None
    r = subprocess.run(["clamscan", "--version"], capture_output=True, text=True, timeout=30)
    return r.stdout.strip() or None
