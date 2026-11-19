# hal-id: #HAL-20261118-0001-PK-D1
"""Depth: what hides below the first layer of a file. Static only: nothing here runs attacker code.

pdf_inspect   walks EVERY object of a PDF after decompression (object streams included), so active content that a
              raw-bytes keyword search can't see is still found. Returns keywords, JavaScript source, every URL an
              action can open (URI, SubmitForm, Launch, ImportData, GoToR, XFA) and the embedded files themselves.
deobfuscate   peels encodings off script/HTML text layer by layer (string concatenation, \\x/\\u/%u escapes,
              String.fromCharCode, reversed strings, base64/atob, hex) and keeps going on whatever comes out, so a
              URL that is only assembled at run time is still found. Decoded binary blobs are returned as files
              (HTML smuggling payloads) so the pipeline can process them like any attachment.

Pure functions over bytes/text; unit-tested directly (tests/test_deep.py).
"""

from __future__ import annotations

import base64
import binascii
import html
import re
from urllib.parse import unquote

import pypdf
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject, StreamObject

from . import extract as X

# Same names the raw scan looks for (pipeline.PDF_KEYWORDS), plus action types that open something elsewhere.
PDF_NAMES = {"/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/XFA", "/RichMedia",
             "/SubmitForm", "/ImportData", "/GoToR", "/GoToE", "/URI"}
LIMITS = {
    "pdf_objects": 200_000,  # objects walked per PDF
    "pdf_depth": 12,  # nesting inside one object
    "pdf_embedded_bytes": 50 * 1024 * 1024,
    "pdf_js_chars": 500_000,
    "layers": 25,  # decode passes; the character budget below is what really bounds the work
    "deobf_chars": 4 * 1024 * 1024,  # total decoded text kept per call
    "blob_min": 64,  # smallest decoded binary worth calling a file
}


# ---------------------------------------------------------------- PDF
def _resolve(v):
    for _ in range(8):
        if not isinstance(v, IndirectObject):
            return v
        try:
            v = v.get_object()
        except Exception:
            return None
    return None


def _text(v, cap: int = 1_000_000) -> str:
    """A PDF string, stream or file spec as text."""
    v = _resolve(v)
    if v is None:
        return ""
    if isinstance(v, StreamObject):
        try:
            return v.get_data()[:cap].decode("utf-8", "replace")
        except Exception:
            return ""
    if isinstance(v, DictionaryObject):  # file specification
        return _text(v.get("/UF") or v.get("/F") or v.get("/DOS") or v.get("/Unix"), cap)
    if isinstance(v, bytes):
        return v[:cap].decode("latin-1")
    return str(v)[:cap]


def _object_ids(reader: pypdf.PdfReader):
    seen = set()
    for gen, table in getattr(reader, "xref", {}).items():
        for num in table:
            if num not in seen:
                seen.add(num)
                yield num, gen
    for num in getattr(reader, "xref_objStm", {}):  # objects stored inside compressed object streams
        if num not in seen:
            seen.add(num)
            yield num, 0


def pdf_inspect(path) -> dict:
    out = {"keywords": {}, "js": [], "uris": [], "launch": [], "submit": [], "remote": [], "xfa": [], "files": [],
           "notes": []}
    try:
        reader = pypdf.PdfReader(str(path), strict=False)
        if reader.is_encrypted and not reader.decrypt(""):
            out["notes"].append("password-protected PDF: objects can't be inspected")
            return out
    except Exception as e:
        out["notes"].append(f"deep PDF parse failed: {type(e).__name__}")
        return out
    js_chars, file_bytes, seen_files = 0, 0, set()

    def count(name: str) -> None:
        if name in PDF_NAMES:
            out["keywords"][name] = out["keywords"].get(name, 0) + 1

    def action(d: DictionaryObject) -> None:
        nonlocal js_chars
        s = d.get("/S")
        if "/JS" in d:
            code = _text(d["/JS"], LIMITS["pdf_js_chars"])
            if code and js_chars < LIMITS["pdf_js_chars"]:
                out["js"].append(code[: LIMITS["pdf_js_chars"] - js_chars])
                js_chars += len(code)
        if s == "/URI" and "/URI" in d:
            out["uris"].append(_text(d["/URI"]))
        elif s == "/Launch":
            target = _text(d.get("/F")) or _text(_resolve(d.get("/Win") or {}).get("/F") if d.get("/Win") else None)
            out["launch"].append(target or "(unnamed)")
        elif s in ("/SubmitForm", "/ImportData") and "/F" in d:
            out["submit"].append(_text(d["/F"]))
        elif s in ("/GoToR", "/GoToE") and "/F" in d:
            out["remote"].append(_text(d["/F"]))

    def embedded(d: DictionaryObject) -> None:
        nonlocal file_bytes
        ef = _resolve(d.get("/EF"))
        if not isinstance(ef, DictionaryObject):
            return
        stream = _resolve(ef.get("/UF") or ef.get("/F"))
        if not isinstance(stream, StreamObject):
            return
        try:
            data = stream.get_data()
        except Exception:
            out["notes"].append("embedded file could not be decoded")
            return
        key = (len(data), hash(data))
        if key in seen_files:
            return
        seen_files.add(key)
        if file_bytes + len(data) > LIMITS["pdf_embedded_bytes"]:
            out["notes"].append("embedded files over the size limit were skipped")
            return
        file_bytes += len(data)
        out["files"].append((_text(d.get("/UF") or d.get("/F")) or "embedded-file.bin", data))

    def walk(o, depth: int) -> None:
        if depth > LIMITS["pdf_depth"] or isinstance(o, IndirectObject):
            return  # every indirect object is visited once at top level; don't chase references
        if isinstance(o, DictionaryObject):
            for k, v in o.items():
                count(str(k))
                if isinstance(v, NameObject):
                    count(str(v))
                if k == "/XFA":
                    xv = _resolve(v)
                    parts = [_resolve(x) for x in xv] if isinstance(xv, ArrayObject) else [xv]
                    out["xfa"] += [_text(p) for p in parts if isinstance(p, StreamObject)]
                walk(v, depth + 1)
            if "/S" in o or "/JS" in o:
                action(o)
            if "/EF" in o:
                embedded(o)
        elif isinstance(o, ArrayObject):
            for v in o:
                walk(v, depth + 1)

    n = 0
    for num, gen in _object_ids(reader):
        n += 1
        if n > LIMITS["pdf_objects"]:
            out["notes"].append("object limit reached: rest of the PDF not inspected")
            break
        try:
            obj = reader.get_object(IndirectObject(num, gen, reader))
        except Exception:
            continue
        walk(obj, 0)
    if not out["files"]:  # name-tree attachments pypdf knows about but no /EF dict was reachable
        try:
            for name, blobs in (reader.attachments or {}).items():
                for data in blobs:
                    out["files"].append((name, data))
        except Exception:
            pass
    for k in ("uris", "launch", "submit", "remote"):
        out[k] = list(dict.fromkeys(u.strip() for u in out[k] if u and u.strip()))
    return out


# ---------------------------------------------------------------- deobfuscation
JOIN = re.compile(r"""(["'])\s*\+\s*\1""")  # "ht" + "tps"  ->  "https"
HEX_ESC = re.compile(r"\\x([0-9A-Fa-f]{2})")
U_ESC = re.compile(r"\\u([0-9A-Fa-f]{4})|%u([0-9A-Fa-f]{4})")
PCT = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")
CHARCODE = re.compile(r"fromCharCode\s*\(\s*((?:0x[0-9A-Fa-f]+|\d+)(?:\s*,\s*(?:0x[0-9A-Fa-f]+|\d+))*)\s*\)")
REVERSED = re.compile(r"""(["'])((?:(?!\1).){4,}?)\1\s*\.split\(\s*(["'])\3\s*\)\s*\.reverse\(\)\s*\.join\(""")
B64 = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,2}")
HEXRUN = re.compile(r"\b(?:[0-9A-Fa-f]{2}){24,}\b")
INLINE_MEDIA = re.compile(r"data:(?:image|font|application/(?:x-)?font-[\w-]+)/?[\w.+-]*;base64,[A-Za-z0-9+/=\s]+")
DOWNLOAD_NAME = re.compile(r"""\.?download\s*[=:]\s*["']([^"'<>]{1,120})["']""")
SMUGGLING = re.compile(r"\b(atob|new Blob|msSaveOrOpenBlob|createObjectURL|Uint8Array)\b|\bdownload\s*[=:]")
# File signatures: a decoded blob that starts like a real file is a payload, not a random token.
MAGIC = (b"PK\x03\x04", b"MZ", b"%PDF", b"7z\xbc\xaf", b"Rar!", b"\x1f\x8b", b"\xd0\xcf\x11\xe0", b"{\\rtf",
         b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"MSCF", b"L\x00\x00\x00", b"\xe4R\\{\x8c")


def _printable(b: bytes) -> bool:
    if not b:
        return False
    sample = b[:4096]
    return sum(32 <= c < 127 or c in (9, 10, 13) for c in sample) / len(sample) > 0.9


def _b64(s: str) -> bytes | None:
    s = s.strip()
    if len(s) % 4 == 1:
        return None
    try:
        return base64.b64decode(s.replace("-", "+").replace("_", "/") + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _layer(text: str, smuggling: bool) -> tuple[list[str], list[bytes]]:
    """One decode pass: every transformation that changes something yields new text; binary decodes are blobs."""
    texts, blobs = [], []
    t = JOIN.sub("", text)
    t = HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), t)
    t = U_ESC.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), t)
    t = PCT.sub(lambda m: unquote(m.group(0)), t)
    t = html.unescape(t)
    if t != text:
        texts.append(t)
    for m in CHARCODE.finditer(t):
        try:
            texts.append("".join(chr(int(x, 0)) for x in re.split(r"\s*,\s*", m.group(1))))
        except (ValueError, OverflowError):
            pass
    for m in REVERSED.finditer(t):
        texts.append(m.group(2)[::-1])
    for m in B64.finditer(t):
        raw = _b64(m.group(0))
        if raw is None or len(raw) < 16:
            continue
        if _printable(raw):
            texts.append(raw.decode("utf-8", "replace"))
        elif len(raw) >= 8 and raw[1::2].count(0) > len(raw) // 2 * 0.9 and _printable(raw[0::2]):
            texts.append(raw.decode("utf-16-le", "replace"))  # PowerShell -EncodedCommand is UTF-16 base64
        elif len(raw) >= LIMITS["blob_min"] and (raw.startswith(MAGIC) or smuggling):
            blobs.append(raw)
    for m in HEXRUN.finditer(t):
        raw = bytes.fromhex(m.group(0))
        if _printable(raw):
            texts.append(raw.decode("utf-8", "replace"))
    return texts, blobs


def deobfuscate(text: str, layers: int | None = None) -> dict:
    """{"urls": [(url, layer)], "blobs": [(name, bytes, layer)], "layers": deepest layer that produced something,
    "truncated": True when decoding was still producing new text at the layer/size limit}.
    Layer 0 = URLs already in plain sight; layer >= 1 = only visible after decoding."""
    layers = LIMITS["layers"] if layers is None else layers
    text = INLINE_MEDIA.sub("", text or "")  # inline images/fonts are normal, not smuggling
    names = DOWNLOAD_NAME.findall(text)
    smuggling = bool(SMUGGLING.search(text))
    seen_urls, urls, blobs, seen_blobs = set(), [], [], set()
    budget = LIMITS["deobf_chars"]
    frontier, seen_text, deepest, truncated = [text], {hash(text)}, 0, False

    def note_urls(t: str, layer: int) -> None:
        for u in X.find_urls(t):
            if u.lower() not in seen_urls:
                seen_urls.add(u.lower())
                urls.append((u, layer))

    note_urls(text, 0)
    note_urls(html.unescape(text), 0)  # &amp; in an href is HTML, not obfuscation
    for layer in range(1, layers + 1):
        nxt = []
        for t in frontier:
            texts, bl = _layer(t, smuggling)
            for b in bl:
                key = (len(b), hash(b))
                if key not in seen_blobs:
                    seen_blobs.add(key)
                    name = names[len(blobs)] if len(blobs) < len(names) else f"decoded-blob-{len(blobs) + 1}.bin"
                    blobs.append((name, b, layer))
                    deepest = layer
            for nt in texts:
                if hash(nt) in seen_text:
                    continue
                if budget <= 0:
                    truncated = True
                    continue
                seen_text.add(hash(nt))
                budget -= len(nt)
                before = len(urls)
                note_urls(nt, layer)
                if len(urls) > before:
                    deepest = layer
                nxt.append(nt)
        if not nxt:
            break
        frontier = nxt
    else:
        truncated = truncated or bool(frontier)
    return {"urls": urls, "blobs": blobs, "layers": deepest, "truncated": truncated}
