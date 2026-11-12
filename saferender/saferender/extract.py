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


# ---------------------------------------------------------------- lookalike domains
# brand keyword -> domains that really belong to it. Add the organization's own domains with
# SAFERENDER_ORG_DOMAINS="example.org,example-mail.org" (the keyword is each domain's first label).
BRANDS = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "microsoft365.com", "office.com", "office365.com",
                  "live.com", "outlook.com", "sharepoint.com", "onmicrosoft.com", "windows.net", "azure.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "paypal": {"paypal.com"},
    "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"},
    "contoso": {"contoso.com"},  # demo organization used by the test samples
}
_HOMO = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", "|": "l"}
_ONE_AS = ("l", "i")  # "1" stands in for either


def brands() -> dict[str, set[str]]:
    import os

    b = {k: set(v) for k, v in BRANDS.items()}
    for d in filter(None, (x.strip().lower() for x in os.environ.get("SAFERENDER_ORG_DOMAINS", "").split(","))):
        b.setdefault(d.split(".")[0], set()).add(d)
    return b


def _skeletons(s: str) -> set[str]:
    base = s.lower().translate(str.maketrans(_HOMO)).replace("rn", "m").replace("vv", "w")
    return {re.sub(r"[^a-z]", "", base.replace("1", c)) for c in _ONE_AS}


def owned_by(host: str, domains: set[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def lookalike(host: str) -> str | None:
    """The brand a host imitates (micros0ft-support.example, contoso.com.evil.example), or None.
    Hosts that really belong to the brand are never flagged."""
    host = (host or "").lower().rstrip(".")
    if not host or re.fullmatch(r"[\d.:]+", host):
        return None
    all_brands = brands()
    # Really hosted on a known brand's domain (e.g. contoso.sharepoint.com): not an imitation.
    if owned_by(host, set().union(*all_brands.values())):
        return None
    sk = _skeletons(host)
    for brand, doms in all_brands.items():
        if any(brand in s for s in sk) and not owned_by(host, doms):
            return brand
    return None


def brand_named(text: str) -> str | None:
    """A brand keyword spelled out in display text (e.g. a sender name 'Microsoft 365 Security')."""
    words = set(re.findall(r"[a-z]+", (text or "").lower()))
    return next((b for b in brands() if b in words), None)
