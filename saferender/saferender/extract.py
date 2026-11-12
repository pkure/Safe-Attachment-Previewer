# hal-id: #HAL-20261110-0003-PK-R1
"""Pure text helpers: find URLs, phone numbers and e-mail addresses in untrusted text, and defang them.

Nothing here touches the network or the file system, so it is unit-tested directly (tests/test_extract.py).
"""

from __future__ import annotations

import re

import phonenumbers

# Scheme URLs, plus bare "www." hosts. Stops at whitespace and characters that rarely end a URL in prose.
URL_RE = re.compile(r"""(?i)\b(?:(?:https?|ftp|hxxps?)://|www\.)[^\s<>"'`{}|\\^\[\]]+""")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
TRAILING = ".,;:!?)]}'\""
# OCR often reads "https://" as "https:/ /" or "https ://". Repair before matching.
OCR_SCHEME_FIX = re.compile(r"(?i)\b(h[tx]{2}ps?)\s*:\s*/\s*/\s*")


def clean_url(u: str) -> str:
    u = u.strip().rstrip(TRAILING)
    # Balance a trailing ")" only if the URL opened one (Wikipedia-style links).
    while u.endswith(")") and u.count("(") < u.count(")"):
        u = u[:-1]
    return u


def find_urls(text: str, ocr: bool = False) -> list[str]:
    if ocr:
        text = OCR_SCHEME_FIX.sub(lambda m: m.group(1) + "://", text)
    seen, out = set(), []
    for m in URL_RE.finditer(text or ""):
        u = clean_url(m.group(0))
        if len(u) > 8 and u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out


def find_emails(text: str) -> list[str]:
    return sorted({m.group(0) for m in EMAIL_RE.finditer(text or "")}, key=str.lower)


def find_phones(text: str, region: str = "US") -> list[str]:
    """Phone numbers in E.164 form. Callback phishing ("call to cancel") lives on these."""
    out = []
    for m in phonenumbers.PhoneNumberMatcher(text or "", region, leniency=phonenumbers.Leniency.VALID):
        e164 = phonenumbers.format_number(m.number, phonenumbers.PhoneNumberFormat.E164)
        if e164 not in out:
            out.append(e164)
    return out


def defang(u: str) -> str:
    """Make a URL unclickable for display: hxxps://evil[.]example/path."""
    u = re.sub(r"(?i)^http", "hxxp", u)
    u = re.sub(r"(?i)^ftp", "fxp", u)
    host_end = u.find("/", u.find("://") + 3) if "://" in u else u.find("/")
    host, rest = (u, "") if host_end == -1 else (u[:host_end], u[host_end:])
    return host.replace(".", "[.]") + rest


def host_of(u: str) -> str:
    m = re.match(r"(?i)^(?:[a-z]+://)?([^/:?#]+)", u)
    return m.group(1).lower() if m else ""
