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
    "max_zip_ratio": 200,  # uncompressed / compressed per entry...
    "ratio_min_bytes": 10 * 1024 * 1024,  # ...for entries at least this big. Small ISOs are mostly padding and
                                          # compress ~1000:1; max_total_bytes already caps what small entries can do.
    "zip_depth": 4,  # email > zip > ISO > file is a real delivery chain; file/byte budgets bound the total
    "archive_timeout_s": 120,
    "max_passwords": 25,  # tried per locked file
    "max_pages": 300,  # per document
    "max_pixels": 40_000_000,  # image decompression-bomb guard
    "office_timeout_s": 120,
    "ocr_timeout_s": 60,
    "av_timeout_s": 300,
    "max_text_bytes": 2 * 1024 * 1024,
    "max_macro_chars": 200_000,
    "max_eml_bytes": 60 * 1024 * 1024,
}

OFFICE_EXT = {".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm", ".xlsb", ".ppt", ".pptx",
              ".pptm", ".rtf", ".odt", ".ods", ".odp"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp"}
TEXT_EXT = {".txt", ".csv", ".htm", ".html", ".xhtml", ".svg", ".xml", ".json"}
EMAIL_EXT = {".eml"}
EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
            ".wsh", ".hta", ".lnk", ".msi", ".jar", ".one", ".reg", ".cpl", ".appx"}
# Opened with external tools, as separate programs inside the container: 7-Zip (7zz, LGPL) and bsdtar (libarchive, BSD)
# for RAR, which Debian's 7-Zip leaves out.
ARCHIVE_KINDS = {"7z", "rar", "gzip", "bzip2", "xz", "cab", "tar", "iso", "vhd", "vhdx", "dmg"}
DISK_KINDS = {"iso", "vhd", "vhdx", "dmg"}
# Disk images: files inside don't get Windows' "downloaded from the internet" mark (Mark of the Web), so they skip
# SmartScreen and Office's macro block. Raw images (.img/.fat/...) can't be sniffed reliably; 7-Zip tries them by name.
DISK_EXT = {".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".dmg", ".udf", ".fat", ".ntfs", ".mbr", ".gpt"}
ARCHIVE_EXT = {".7z", ".rar", ".gz", ".tgz", ".bz2", ".xz", ".txz", ".tar", ".cab"} | DISK_EXT
HTML_EXT = {".htm", ".html", ".xhtml", ".svg", ".shtml"}


MAGIC = [(b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"), (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"),
         (b"\xfd7zXZ\x00", "xz"), (b"MSCF", "cab"), (b"vhdxfile", "vhdx"), (b"conectix", "vhd"),
         (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),  # Windows shortcut (header size + LinkCLSID)
         (bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3"), "onenote")]


def sniff(path: Path) -> str:
    """Type by content, not by the (attacker-chosen) extension."""
    with open(path, "rb") as f:
        head = f.read(0x9006)  # ISO 9660's "CD001" sits at 0x8001 (or the next sector or two)
        size = f.seek(0, 2)
        f.seek(max(size - 512, 0))
        tail = f.read(512)
    kind = _sniff_head(head)
    if kind != "other":
        return kind
    for magic, k in MAGIC:
        if head.startswith(magic):
            return k
    if any(head[o:o + 5] == b"CD001" for o in (0x8001, 0x8801, 0x9001)):
        return "iso"
    if head[257:262] == b"ustar":
        return "tar"
    if tail.startswith(b"conectix"):
        return "vhd"  # fixed-size VHD: the footer is the last 512 bytes
    if tail.startswith(b"koly"):
        return "dmg"
    return "other"


def _sniff_head(head: bytes) -> str:
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
            bomb = ratio > LIMITS["max_zip_ratio"] and info.file_size >= LIMITS["ratio_min_bytes"]
            if bomb or budget["bytes"] + info.file_size > LIMITS["max_total_bytes"]:
                notes.append(f"skipped {safe_name(info.filename)}: size/ratio limit (possible zip bomb)")
                continue
            out = dest / f"{len(files) + 1:02d}-{safe_name(info.filename)}"  # never trust entry paths
            with z.open(info) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            budget["files"] += 1
            budget["bytes"] += info.file_size
            files.append(out)
    return files, encrypted, notes


def zip_encrypted(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as z:
            return any(i.flag_bits & 0x1 for i in z.infolist())
    except zipfile.BadZipFile:
        return False


def _run(cmd: list[str]) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", stdin=subprocess.DEVNULL,
                              timeout=LIMITS["archive_timeout_s"])
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


BAD_PASSWORD = re.compile(r"(?i)wrong password|can ?not open encrypted|data error in encrypted|incorrect password")


def _list_7z(path: Path, pw: str) -> tuple[list[dict], bool, bool]:
    """(entries, needs_password, readable). -p always given, so 7-Zip never stops to prompt."""
    r = _run(["7zz", "l", "-slt", "-ba", f"-p{pw}", str(path)])
    if r is None:
        return [], False, False
    out = r.stdout + r.stderr
    entries = []
    for block in r.stdout.split("\n\n"):
        kv = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
        if "Path" in kv and kv.get("Folder") != "+" and not kv.get("Attributes", "").startswith("D"):
            entries.append({"name": kv["Path"], "size": int(kv.get("Size") or 0), "encrypted": kv.get("Encrypted") == "+"})
    if r.returncode != 0 and BAD_PASSWORD.search(out):
        return [], True, False
    return entries, any(e["encrypted"] for e in entries), r.returncode == 0 or bool(entries)


def _collect(tmp: Path, dest: Path, budget: dict, notes: list[str]) -> list[tuple[Path, str]]:
    """Move extracted regular files (never symlinks) into dest with sanitized names, within the budget."""
    files = []
    for p in sorted(tmp.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        size = p.stat().st_size
        if budget["files"] >= LIMITS["max_files"] or budget["bytes"] + size > LIMITS["max_total_bytes"]:
            notes.append("file/size limit reached; remaining archive entries skipped")
            break
        out = dest / f"{len(files) + 1:02d}-{safe_name(p.name)}"
        p.rename(out)
        budget["bytes"] += size
        budget["files"] += 1
        files.append((out, p.name))
    shutil.rmtree(tmp, ignore_errors=True)
    return files


def unpack_archive(path: Path, dest: Path, budget: dict, kind: str, passwords: list[str]) -> dict:
    """7z/zip/RAR/gzip/tar/CAB and disk images (ISO, VHD, VHDX, raw FAT/NTFS, DMG), flat and capped.
    Locked archives: try '' then each candidate password. Returns {files: [(path, name)], encrypted, password,
    notes}. Sizes are checked from the listing BEFORE anything is written (bomb guard); /tmp's size cap backs it up."""
    res = {"files": [], "encrypted": False, "password": None, "notes": []}
    dest.mkdir(parents=True, exist_ok=True)
    tmp = dest.parent / (dest.name + ".x")
    if kind == "rar":  # bsdtar: reads RAR4/RAR5, refuses '..' and absolute paths; can't decrypt RAR
        r = _run(["bsdtar", "-tvf", str(path)])
        if r is None or r.returncode != 0:
            msg = (r.stderr if r else "timeout")[-200:]
            res["encrypted"] = bool(r and re.search(r"(?i)encrypt", r.stderr))
            res["notes"].append("encrypted RAR: can't be opened here" if res["encrypted"] else f"RAR not readable: {msg}")
            return res
        sizes = [int(line.split()[4]) for line in r.stdout.splitlines() if line[:1] == "-" and len(line.split()) > 4]
        if budget["bytes"] + sum(sizes) > LIMITS["max_total_bytes"]:
            res["notes"].append("archive too large when unpacked (possible archive bomb): not unpacked")
            return res
        tmp.mkdir()
        _run(["bsdtar", "-xf", str(path), "-C", str(tmp), "--no-same-owner", "--no-same-permissions"])
        res["files"] = _collect(tmp, dest, budget, res["notes"])
        return res
    tried = [""] + [pw for pw in passwords if pw][: LIMITS["max_passwords"]]
    for pw in tried:
        entries, locked, readable = _list_7z(path, pw)
        if not readable:
            if locked:  # header-encrypted (.7z -mhe): even the file names need the password
                res["encrypted"] = True
                continue
            res["notes"].append("archive not readable")
            return res
        res["encrypted"] = res["encrypted"] or locked
        total = sum(e["size"] for e in entries)
        bomb = total / max(path.stat().st_size, 1) > LIMITS["max_zip_ratio"] and total >= LIMITS["ratio_min_bytes"]
        if bomb or budget["bytes"] + total > LIMITS["max_total_bytes"]:
            res["notes"].append("archive too large when unpacked (possible archive bomb): not unpacked")
            return res
        if locked and not pw:
            continue  # names are readable, contents aren't: try the passwords
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir()
        r = _run(["7zz", "e", "-y", "-aou", "-bd", f"-p{pw}", f"-o{tmp}", str(path)])
        if r is None:
            res["notes"].append("archive extraction timed out")
            shutil.rmtree(tmp, ignore_errors=True)
            return res
        if BAD_PASSWORD.search(r.stdout + r.stderr):
            shutil.rmtree(tmp, ignore_errors=True)
            continue
        if r.returncode != 0:
            res["notes"].append("archive partly unreadable: " + (r.stderr.strip().splitlines() or ["error"])[-1][:160])
        res["password"] = pw or None
        res["files"] = _collect(tmp, dest, budget, res["notes"])
        return res
    shutil.rmtree(tmp, ignore_errors=True)
    return res


# ---------------------------------------------------------------- Outlook .msg (an OLE file of MAPI properties)
def is_msg(path: Path) -> bool:
    import olefile
    try:
        with olefile.OleFileIO(str(path)) as ole:
            return any(e[0].startswith("__substg1.0_") for e in ole.listdir())
    except Exception:
        return False


def _msg_part(ole, prefix: str, tag: str) -> str | bytes | None:
    """MAPI property stream: <prefix>__substg1.0_<tag>001F (UTF-16 text), 001E (8-bit text) or 0102 (binary)."""
    for kind in ("001F", "001E", "0102"):
        name = f"{prefix}__substg1.0_{tag}{kind}"
        if ole.exists(name):
            data = ole.openstream(name).read(LIMITS["max_eml_bytes"])
            if kind == "001F":
                return data.decode("utf-16-le", "replace").rstrip("\x00")
            if kind == "001E":
                return data.decode("latin-1").rstrip("\x00")
            return data
    return None


def _msg_message(ole, prefix: str = "", depth: int = 0):
    """Rebuild one message (and attached messages, recursively) as a standard email.message object."""
    import email
    from email import policy
    from email.message import EmailMessage

    headers = _msg_part(ole, prefix, "007D")  # the original internet headers, when the message came from outside
    msg = email.message_from_string(headers + "\n", policy=policy.default) if isinstance(headers, str) and \
        headers.strip() else EmailMessage(policy=policy.default)
    for h in ("Content-Type", "Content-Transfer-Encoding", "MIME-Version"):
        del msg[h]
    if "Subject" not in msg and isinstance(subj := _msg_part(ole, prefix, "0037"), str):
        msg["Subject"] = subj
    if "From" not in msg:
        name, addr = _msg_part(ole, prefix, "0C1A"), _msg_part(ole, prefix, "5D01") or _msg_part(ole, prefix, "0C1F")
        if isinstance(addr, str) and addr:
            msg["From"] = f'"{name}" <{addr}>' if isinstance(name, str) and name else addr
    body = _msg_part(ole, prefix, "1000")
    html = _msg_part(ole, prefix, "1013")
    msg.set_content(body if isinstance(body, str) else "")
    if html:
        msg.add_alternative(html.decode("utf-8", "replace") if isinstance(html, bytes) else html, subtype="html")
    seen = set()
    for entry in ole.listdir(streams=True, storages=True):
        if len(entry) <= prefix.count("/") or not entry[prefix.count("/")].startswith("__attach_version1.0_#"):
            continue
        if prefix and "/".join(entry[: prefix.count("/")]) + "/" != prefix:
            continue
        att = "/".join(entry[: prefix.count("/") + 1]) + "/"
        if att in seen:
            continue
        seen.add(att)
        name = _msg_part(ole, att, "3707") or _msg_part(ole, att, "3704") or "attachment.bin"
        if ole.exists(att + "__substg1.0_3701000D") and depth < 3:  # an attached email, stored as a sub-storage
            inner = _msg_message(ole, att + "__substg1.0_3701000D/", depth + 1)
            msg.add_attachment(inner)
            continue
        data = _msg_part(ole, att, "3701")
        if isinstance(data, bytes):
            msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=str(name))
    return msg


def msg_to_eml(path: Path, dest: Path) -> Path | None:
    """Convert an Outlook .msg to .eml so it goes through exactly the same email checks. Static: olefile only."""
    import olefile
    try:
        with olefile.OleFileIO(str(path)) as ole:
            msg = _msg_message(ole)
    except Exception:
        return None
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / "converted.eml"
    out.write_bytes(bytes(msg))
    return out


# ---------------------------------------------------------------- Windows shortcuts (.lnk)
def lnk_info(path: Path) -> dict:
    """Where a shortcut points and what it passes. 'invoice.pdf.lnk' that runs PowerShell is a classic."""
    import LnkParse3
    try:
        with open(path, "rb") as fh:
            j = LnkParse3.lnk_file(fh).get_json()
    except Exception as e:
        return {"error": f"{type(e).__name__}"}
    data = j.get("data", {}) or {}
    info = j.get("link_info", {}) or {}
    target = info.get("local_base_path") or info.get("common_path_suffix") or data.get("relative_path") or ""
    return {"target": str(target), "arguments": str(data.get("command_line_arguments") or ""),
            "workingDir": str(data.get("working_directory") or ""), "icon": str(data.get("icon_location") or ""),
            "description": str(data.get("description") or ""),
            "machine": str(((j.get("extra") or {}).get("DISTRIBUTED_LINK_TRACKER_BLOCK") or {}).get("machine_identifier") or "")}


LNK_RISKY = re.compile(r"(?i)\b(powershell|pwsh|cmd(\.exe)?|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|"
                       r"curl|wget|msiexec|conhost|forfiles|-enc(odedcommand)?|iex|invoke-expression|downloadstring)\b")


# ---------------------------------------------------------------- OneNote (.one)
ONENOTE_FILE_GUID = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")  # FileDataStoreObject header


def onenote_files(path: Path) -> list[tuple[str, bytes]]:
    """Files embedded in a OneNote section (2023 malware favourite: a fake 'double-click to view' button)."""
    raw = path.read_bytes()[: LIMITS["max_total_bytes"]]
    out, i = [], raw.find(ONENOTE_FILE_GUID)
    while i != -1 and len(out) < LIMITS["max_files"]:
        size = int.from_bytes(raw[i + 16:i + 24], "little")
        data = raw[i + 36:i + 36 + size]
        if 0 < size == len(data):
            out.append((f"onenote-embedded-{len(out) + 1}{_guess_ext(data)}", data))
        i = raw.find(ONENOTE_FILE_GUID, i + 16)
    return out


def _guess_ext(data: bytes) -> str:
    head = data[:512].lower()
    if data[:2] == b"MZ":
        return ".exe"
    if b"hta:application" in head or (b"<script" in head and b"<html" in head):
        return ".hta"
    if head.startswith((b"@echo", b"echo ", b"rem ")) or b"cmd /c" in head:
        return ".bat"
    if b"wscript" in head or b"createobject(" in head:
        return ".vbs"
    if b"%pdf" in head[:8]:
        return ".pdf"
    return ".bin"


# ---------------------------------------------------------------- Office: embedded files, DDE
def ole_packages(path: Path) -> list[tuple[str, bytes]]:
    """Files embedded in Office documents as 'packages' (the icon you double-click): OOXML embeddings/*.bin,
    legacy .doc/.xls ObjectPool, and RTF \\objdata. Extracted, never opened."""
    import olefile
    from oletools.oleobj import OleNativeStream

    def from_ole(data: bytes) -> list[tuple[str, bytes]]:
        found = []
        try:
            with olefile.OleFileIO(data) as ole:
                for e in ole.listdir():
                    if e[-1] == "\x01Ole10Native":
                        n = OleNativeStream(ole.openstream(e).read(), package=False)
                        if n.data:
                            found.append((n.filename or n.src_path or "embedded.bin", bytes(n.data)))
        except Exception:
            pass
        return found

    out = []
    raw = path.read_bytes()
    if raw[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(path) as z:
                for n in z.namelist():
                    if "/embeddings/" in n and z.getinfo(n).file_size < LIMITS["max_total_bytes"]:
                        data = z.read(n)
                        pk = from_ole(data) if data[:4] == b"\xd0\xcf\x11\xe0" else []
                        out += pk or ([(n.rsplit("/", 1)[-1], data)] if not n.endswith(".bin") else [])
        except zipfile.BadZipFile:
            pass
    elif raw[:4] == b"\xd0\xcf\x11\xe0":
        out += from_ole(raw)
    elif raw[:5] == b"{\\rtf":
        try:
            from oletools.rtfobj import RtfObjParser
            rp = RtfObjParser(raw)
            rp.parse()
            for o in rp.objects:
                if o.is_package and o.olepkgdata:
                    out.append((o.filename or "embedded.bin", bytes(o.olepkgdata)))
        except Exception:
            pass
    return out[: LIMITS["max_files"]]


def dde_fields(path: Path) -> str:
    """DDE/DDEAUTO fields: Word/Excel formulas that start a program (e.g. cmd.exe) when the file is opened."""
    try:
        from oletools import msodde
        import logging
        logging.getLogger("msodde").setLevel(logging.CRITICAL)
        return (msodde.process_file(str(path)) or "").strip()
    except Exception:
        return ""


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
    if getattr(vp, "type", None) == "Text":
        # olevba reads ANY plain-text file as possible VBA source: a 14-byte "ATT08537.docx" holding only an email
        # address came back as "1 VBA macro module" (real sample, 2026-11-18). Text files don't carry macros.
        vp.close()
        return None
    try:
        try:
            xlm = bool(vp.detect_xlm_macros())  # Excel 4.0 macro sheets: old, but still abused (no VBA project at all)
        except Exception:
            xlm = False
        if not vp.detect_vba_macros() and not xlm:
            return None
        modules, budget = [], LIMITS["max_macro_chars"]
        for _f, _s, name, code in vp.extract_macros():
            code = code if isinstance(code, str) else code.decode("utf-8", "replace")
            modules.append({"name": str(name), "code": code[:budget]})
            budget = max(budget - len(code), 0)
        findings = [{"type": t, "keyword": k, "description": d} for t, k, d in vp.analyze_macros()
                    if t in ("AutoExec", "Suspicious", "IOC")]
        return {"modules": modules, "findings": findings, "xlm": xlm}
    finally:
        vp.close()


LO_PROFILE_XCU = """<?xml version="1.0" encoding="UTF-8"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="MacroSecurityLevel" oor:op="fuse"><value>3</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="DisableMacrosExecution" oor:op="fuse"><value>true</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Misc"><prop oor:name="UseLocking" oor:op="fuse"><value>false</value></prop></item>
</oor:items>
"""


def office_to_pdf(path: Path, workdir: Path, html: bool = False) -> tuple[Path | None, str | None]:
    """Convert with LibreOffice in a throwaway profile that has macro execution disabled.
    html: open as a Writer document. LibreOffice's default (Writer/Web) exports blank pages; this draws tables and
    cell colours, so a QR code built from table cells shows up. LibreOffice never runs the page's scripts."""
    profile = workdir / "lo-profile"
    (profile / "user").mkdir(parents=True, exist_ok=True)
    (profile / "user" / "registrymodifications.xcu").write_text(LO_PROFILE_XCU)
    outdir = workdir / "converted"
    outdir.mkdir(exist_ok=True)
    env = {"HOME": str(workdir), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
    cmd = ["soffice", f"-env:UserInstallation=file://{profile}", "--headless", "--norestore", "--nologo",
           "--nolockcheck", *(["--infilter=HTML (StarWriter)"] if html else []), "--convert-to", "pdf",
           "--outdir", str(outdir), str(path)]
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
        self.text, self.hrefs, self.anchors, self._skip, self._a = [], [], [], 0, None

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag in ("p", "div", "br", "tr", "li", "h1", "h2", "h3", "table"):
            self.text.append("\n")
        for k, v in attrs:
            if k in ("href", "src", "action", "formaction", "data") and v:
                self.hrefs.append(v.strip())
                if tag == "a" and k == "href":
                    self._a = [v.strip(), []]

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._a:
            self.anchors.append((self._a[0], " ".join("".join(self._a[1]).split())[:300]))
            self._a = None

    def handle_data(self, data):
        if not self._skip:
            self.text.append(data)
            if self._a:
                self._a[1].append(data)


def html_text(txt: str) -> tuple[str, list[str], list[tuple[str, str]]]:
    """Visible text, every href/src/action, and (href, visible anchor text) pairs for <a> links."""
    p = _HtmlText()
    try:
        p.feed(txt)
    except Exception:
        pass
    return re.sub(r"[ \t]*\n\s*", "\n", "".join(p.text)).strip(), p.hrefs, p.anchors


_PAIRED = re.compile(r"(?is)<(script|iframe|object|applet|frameset|noembed|svg)\b[^>]*>.*?</\1\s*>")
_EMBED = re.compile(r"(?is)<(?:script|iframe|frame|frameset|object|embed|applet|link|base|meta|svg|import)\b[^>]*>")
_RES_ATTR = re.compile(r"""(?is)\s(?:src|srcset|lowsrc|dynsrc|background|poster|data|longdesc|xlink:href|href)\s*=\s*"""
                       r"""("[^"]*"|'[^']*'|[^\s>]+)""")
_CSS_URL = re.compile(r"(?is)url\(\s*(['\"]?)(?!data:image/)[^)]*\)")


def html_for_render(txt: str) -> tuple[str, int]:
    """A copy of untrusted HTML that is safe to DRAW: no scripts or frames, and nothing that loads another file.
    A page can point <img src="file:///..."> at files inside the renderer (proved 2026-11-18: LibreOffice drew a
    local image into the picture), or at the internet where a network exists. Only inline data: images survive.
    <a href> links are kept as text targets: drawing a page never follows them, but LibreOffice keeps them clickable
    in the PDF, so they are dropped too and the links list (from the original) stays the source of truth."""
    n = 0

    def drop(_m):
        nonlocal n
        n += 1
        return ""

    def attr(m):
        nonlocal n
        v = m.group(1).strip("'\"").strip().lower()
        if v.startswith("data:image/"):
            return m.group(0)
        n += 1
        return ""

    def css(m):
        nonlocal n
        n += 1
        return "url()"

    txt = _PAIRED.sub(drop, txt)
    txt = _EMBED.sub(drop, txt)
    txt = _RES_ATTR.sub(attr, txt)
    txt = _CSS_URL.sub(css, txt)
    return txt, n


def read_text(path: Path, is_html: bool) -> tuple[str, list[str], list[tuple[str, str]], dict]:
    raw = path.read_bytes()[: LIMITS["max_text_bytes"]]
    txt = raw.decode("utf-8", "replace")
    if not is_html:
        return txt, [], [], {}
    text, hrefs, anchors = html_text(txt)
    signals = {
        "script tags": len(re.findall(r"(?i)<script\b", txt)),
        "forms": len(re.findall(r"(?i)<form\b", txt)),
        "password fields": len(re.findall(r"(?i)type\s*=\s*['\"]?password", txt)),
        # Inline images and fonts (data:image/...;base64,...) are normal in saved web pages; smuggled payloads aren't images.
        "base64 blobs (HTML smuggling)": len(re.findall(r"[A-Za-z0-9+/]{2000,}={0,2}",
                                                        re.sub(r"data:(?:image|font|application/(?:x-)?font-[\w-]+)/?[\w.+-]*;base64,[A-Za-z0-9+/=\s]+", "", txt))),
        "atob/Blob/msSaveOrOpenBlob": len(re.findall(r"\b(atob|new Blob|msSaveOrOpenBlob|createObjectURL)\b", txt)),
    }
    return text, hrefs, anchors, {k: v for k, v in signals.items() if v}


# ---------------------------------------------------------------- email (.eml)
EMAIL_HEADERS = ("From", "Reply-To", "Return-Path", "To", "Cc", "Subject", "Date", "Message-ID",
                 "Authentication-Results")


def looks_like_email(path: Path) -> bool:
    head = path.read_bytes()[:4096]
    return bool(re.match(rb"(?i)(received|return-path|from|delivered-to|x-[\w-]+|message-id|mime-version|date|to|subject):",
                         head)) and b"\n\n" in head.replace(b"\r\n", b"\n") and re.search(rb"(?im)^from:", head) is not None


def _leaves(part):
    """Walk MIME parts, but stop at attached emails (message/rfc822): those become child files."""
    if part.get_content_type() == "message/rfc822" or not part.is_multipart():
        yield part
        return
    for p in part.get_payload():
        yield from _leaves(p)


def parse_eml(path: Path, dest: Path, budget: dict) -> dict:
    """Headers, visible body text, links with their anchor text, and every attachment/inline part saved as a file.
    Static parse with the stdlib: nothing is fetched, nothing is executed."""
    import mimetypes
    from email import policy
    from email.parser import BytesParser

    msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes()[: LIMITS["max_eml_bytes"]])
    out = {"headers": {}, "text": [], "plain": [], "hrefs": [], "anchors": [], "files": [], "notes": []}
    for k in EMAIL_HEADERS:
        try:
            v = msg.get(k)
        except Exception:  # malformed header: keep going, note it
            out["notes"].append(f"unreadable {k} header")
            v = None
        if v:
            out["headers"][k] = " ".join(str(v).split())[:1000]
    dest.mkdir(parents=True, exist_ok=True)
    for part in _leaves(msg):
        ctype = part.get_content_type()
        name = part.get_filename()
        is_body = ctype in ("text/plain", "text/html") and not name and part.get_content_disposition() != "attachment"
        if is_body:
            try:
                body = part.get_content()
            except Exception:
                body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            body = body[: LIMITS["max_text_bytes"]]
            if ctype == "text/html":
                text, hrefs, anchors = html_text(body)
                out["text"].append(text)
                out["hrefs"] += hrefs
                out["anchors"] += anchors
            else:
                out["plain"].append(body)
            continue
        if ctype == "message/rfc822":
            inner = part.get_payload()
            data = (inner[0] if isinstance(inner, list) else inner).as_bytes()
            name = name or "attached-message.eml"
        else:
            data = part.get_payload(decode=True) or b""
            name = name or ("inline-part" + (mimetypes.guess_extension(ctype) or ".bin"))
        if budget["files"] >= LIMITS["max_files"] or budget["bytes"] + len(data) > LIMITS["max_total_bytes"]:
            out["notes"].append(f"skipped {safe_name(name)}: file/size limit")
            continue
        p = dest / f"{len(out['files']) + 1:02d}-{safe_name(name)}"
        p.write_bytes(data)
        budget["files"] += 1
        budget["bytes"] += len(data)
        out["files"].append((p, name))
    join = lambda parts: "\n\n".join(t.strip() for t in parts if t.strip())  # noqa: E731
    # Show the HTML body when there is one (what Outlook displays); the plain copy is still scanned for links.
    out["scan"] = join(out["text"] + out["plain"])
    out["text"] = join(out["text"]) or join(out["plain"])
    return out


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
