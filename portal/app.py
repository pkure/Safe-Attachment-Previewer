# hal-id: #HAL-20261113-0009-PK-P1
"""Safe Attachment Previewer: portal (Outlook add-in backend + signed-in viewer).

  Analyst selects email(s) in Outlook -> "Preview safely" (add-in) -> POST /api/cases with the analyst's own token
  -> the portal exchanges it (on-behalf-of) for a Graph token that can read ONLY what that analyst can already read
  -> copies each email's raw bytes (never parsed here) to private storage -> starts one offline render job per email
  -> the add-in opens /case/<id>, which shows live progress and then becomes the preview.

Access = (assigned the app role in Entra) AND (the shared-mailbox permission in Exchange). The portal has no standing
mailbox access of its own. Fallback for Outlook builds without nested app auth: /start (browser sign-in, same rules).

Config (environment): TENANT_ID, CLIENT_ID, PUBLIC_URL, STORE (blob:https://<acct>.blob.core.windows.net | dir:/path),
JOB_ID (ARM id of the render job, or "local" for tests), SESSION_SECRET, AZURE_CLIENT_ID (the portal's managed
identity, used as the app's federated credential: no client secret exists), LAB_MAILBOXES (optional fallback list).
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import re
import secrets
import shutil
import threading
import time
import urllib.parse
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

import jwt
import msal
import requests
from flask import (Flask, Response, abort, jsonify, redirect, render_template_string, request, send_from_directory,
                   session, url_for)

HERE = Path(__file__).resolve().parent
VIEWER_DIR = Path(os.environ.get("VIEWER_DIR", HERE.parent / "viewer"))
ADDIN_DIR = HERE / "addin"

TENANT = os.environ.get("TENANT_ID", "")
CLIENT_ID = os.environ.get("CLIENT_ID", "")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:8000").rstrip("/")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT}"
API_SCOPE = f"api://{CLIENT_ID}/access_as_user"
APP_ROLE = "Previewer.Use"
GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPES = ["https://graph.microsoft.com/Mail.Read.Shared"]
ARM = "https://management.azure.com"
ARM_API = "2025-01-01"
MAX_ITEMS = int(os.environ.get("MAX_ITEMS", "10"))
MAX_MIME = int(os.environ.get("MAX_MIME_MB", "50")) * 1024 * 1024
RATE_PER_HOUR = int(os.environ.get("RATE_PER_HOUR", "60"))
LAB_MAILBOXES = [m.strip() for m in os.environ.get("LAB_MAILBOXES", "").split(",") if m.strip()]

CASE_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
ITEM_RE = re.compile(r"^[A-Za-z0-9_\-=+/]{20,512}$")
MAILBOX_RE = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,255}$")
RESULT_FILE_RE = re.compile(r"^(report\.json|attestation\.json|status\.json|meta\.json|pages/f\d{1,3}-p\d{3}(\.t)?\.png)$")

app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("SESSION_SECRET") or secrets.token_hex(32),
                  SESSION_COOKIE_SECURE=PUBLIC_URL.startswith("https://"), SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
                  MAX_CONTENT_LENGTH=64 * 1024)


def audit(event: str, **kw) -> None:
    """One JSON line per security-relevant action -> container logs -> Log Analytics (who, what, when, result)."""
    print(json.dumps({"audit": event, "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), **kw}),
          flush=True)


# ---------------------------------------------------------------- managed identity
_mi_cache: dict[str, tuple[str, float]] = {}


def mi_token(resource: str) -> str:
    tok, exp = _mi_cache.get(resource, ("", 0.0))
    if tok and time.time() < exp - 300:
        return tok
    q = {"resource": resource, "api-version": "2019-08-01"}
    if os.environ.get("AZURE_CLIENT_ID"):
        q["client_id"] = os.environ["AZURE_CLIENT_ID"]
    r = requests.get(f"{os.environ['IDENTITY_ENDPOINT']}?{urllib.parse.urlencode(q)}",
                     headers={"X-IDENTITY-HEADER": os.environ["IDENTITY_HEADER"]}, timeout=20)
    r.raise_for_status()
    j = r.json()
    _mi_cache[resource] = (j["access_token"], float(j.get("expires_on", time.time() + 3000)))
    return j["access_token"]


def client_credential():
    """No client secret: the app proves itself with its managed identity (federated identity credential)."""
    if os.environ.get("CLIENT_SECRET"):  # local development only
        return os.environ["CLIENT_SECRET"]
    return {"client_assertion": lambda: mi_token("api://AzureADTokenExchange")}


@functools.lru_cache(maxsize=1)
def cca() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential=client_credential())


# ---------------------------------------------------------------- storage
class BlobStore:
    VERSION = "2023-11-03"

    def __init__(self, endpoint: str):
        if not re.fullmatch(r"https://[a-z0-9]{3,24}\.blob\.core\.windows\.net", endpoint):
            raise SystemExit("unexpected blob endpoint")
        self.endpoint = endpoint

    def _h(self, extra=None):
        return {"Authorization": f"Bearer {mi_token('https://storage.azure.com/')}", "x-ms-version": self.VERSION,
                **(extra or {})}

    def put(self, container: str, name: str, data: bytes, ctype: str) -> None:
        r = requests.put(f"{self.endpoint}/{container}/{urllib.parse.quote(name)}", data=data, timeout=120,
                         headers=self._h({"x-ms-blob-type": "BlockBlob", "Content-Type": ctype}))
        r.raise_for_status()

    def get(self, container: str, name: str) -> bytes | None:
        r = requests.get(f"{self.endpoint}/{container}/{urllib.parse.quote(name)}", headers=self._h(), timeout=60)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.content

    def names(self, container: str, suffix: str, limit: int = 2000) -> list[str]:
        out, marker = [], ""
        while len(out) < limit:
            q = {"restype": "container", "comp": "list", "maxresults": "1000", **({"marker": marker} if marker else {})}
            r = requests.get(f"{self.endpoint}/{container}?{urllib.parse.urlencode(q)}", headers=self._h(), timeout=60)
            r.raise_for_status()
            root = ET.fromstring(r.content)
            out += [n for b in root.iter("Blob") if (n := b.findtext("Name") or "").endswith(suffix)]
            marker = root.findtext("NextMarker") or ""
            if not marker:
                break
        return out


class DirStore:
    def __init__(self, root: str):
        self.root = Path(root)

    def put(self, container, name, data, ctype):
        p = self.root / container / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def get(self, container, name):
        p = self.root / container / name
        return p.read_bytes() if p.is_file() else None

    def names(self, container, suffix, limit=2000):
        base = self.root / container
        return sorted(p.relative_to(base).as_posix() for p in base.rglob(f"*{suffix}"))[:limit] if base.is_dir() else []


def make_store():
    kind, _, where = os.environ.get("STORE", "").partition(":")
    return BlobStore(where) if kind == "blob" else DirStore(where or "/tmp/sap-store")


STORE = make_store()


def put_json(container: str, name: str, obj: dict) -> None:
    STORE.put(container, name, json.dumps(obj).encode(), "application/json")


# ---------------------------------------------------------------- render job
def start_job(case: str) -> str:
    """Start one execution of the render job for this case. The run's settings come from the job itself; the portal
    only adds CASE_ID (its role lets it read and start this one job, nothing else)."""
    job_id = os.environ.get("JOB_ID", "")
    if job_id == "local":
        return "local"
    h = {"Authorization": f"Bearer {mi_token(ARM + '/')}"}
    r = requests.get(f"{ARM}{job_id}?api-version={ARM_API}", headers=h, timeout=30)
    r.raise_for_status()
    c = r.json()["properties"]["template"]["containers"][0]
    env = [e for e in c.get("env", []) if e.get("name") != "CASE_ID"] + [{"name": "CASE_ID", "value": case}]
    body = {"containers": [{k: v for k, v in {**c, "env": env}.items()
                            if k in ("name", "image", "command", "args", "env", "resources")}]}
    r = requests.post(f"{ARM}{job_id}/start?api-version={ARM_API}", headers=h, json=body, timeout=30)
    r.raise_for_status()
    return (r.json() or {}).get("name", "started") if r.content else "started"


# ---------------------------------------------------------------- auth
class AuthError(Exception):
    pass


@functools.lru_cache(maxsize=1)
def jwks() -> jwt.PyJWKClient:
    return jwt.PyJWKClient(f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys", cache_keys=True)


def validate_bearer(token: str) -> dict:
    """Access token from the add-in (nested app auth): our tenant, our API, the access_as_user scope, and the
    Previewer.Use app role (Entra only issues the role to people assigned to the app)."""
    try:
        key = jwks().get_signing_key_from_jwt(token).key
        c = jwt.decode(token, key, algorithms=["RS256"], audience=[CLIENT_ID, f"api://{CLIENT_ID}"],
                       issuer=f"https://login.microsoftonline.com/{TENANT}/v2.0",
                       options={"require": ["exp", "iat", "aud", "iss", "tid", "oid"]})
    except Exception as e:
        raise AuthError(f"invalid token: {type(e).__name__}") from e
    if c.get("tid") != TENANT:
        raise AuthError("wrong tenant")
    if "access_as_user" not in str(c.get("scp", "")).split():
        raise AuthError("missing scope")
    if APP_ROLE not in (c.get("roles") or []):
        raise AuthError("not assigned to Safe Attachment Previewer")
    return c


def bearer_user() -> dict:
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        raise AuthError("no token")
    tok = h[7:]
    c = validate_bearer(tok)
    return {"oid": c["oid"], "upn": c.get("preferred_username") or c.get("upn") or c["oid"],
            "name": c.get("name", ""), "token": tok}


def session_user() -> dict | None:
    u = session.get("user")
    return u if u and u.get("exp", 0) > time.time() else None


def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not session_user():
            return redirect(url_for("login", next=request.full_path if request.query_string else request.path))
        return view(*a, **kw)
    return wrapped


def safe_next(nxt: str | None) -> str:
    return nxt if nxt and nxt.startswith("/") and not nxt.startswith("//") else "/"


@app.get("/login")
def login():
    flow = cca().initiate_auth_code_flow(["User.Read"], redirect_uri=f"{PUBLIC_URL}/auth/callback")
    session["flow"], session["next"] = flow, safe_next(request.args.get("next"))
    return redirect(flow["auth_uri"])


@app.get("/auth/callback")
def auth_callback():
    flow = session.pop("flow", None)
    if not flow:
        return redirect("/login")
    res = cca().acquire_token_by_auth_code_flow(flow, request.args.to_dict())
    claims = res.get("id_token_claims") or {}
    if "error" in res or claims.get("tid") != TENANT:
        audit("login_failed", error=res.get("error"))
        abort(401)
    if APP_ROLE not in (claims.get("roles") or []):
        audit("login_denied", upn=claims.get("preferred_username"), reason="not assigned")
        abort(403)
    session.permanent = True
    session["user"] = {"oid": claims["oid"], "upn": claims.get("preferred_username", ""), "name": claims.get("name", ""),
                       "exp": time.time() + 8 * 3600}
    audit("login", upn=session["user"]["upn"])
    pending = session.pop("pending", None)
    if pending and "access_token" in res and set(GRAPH_SCOPES) <= set(res.get("scope", "").split()):
        return finish_start(res["access_token"], session["user"], pending)
    return redirect(session.pop("next", "/"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(f"{AUTHORITY}/oauth2/v2.0/logout?post_logout_redirect_uri={urllib.parse.quote(PUBLIC_URL + '/')}")


# ---------------------------------------------------------------- cases
_rate: dict[str, deque] = defaultdict(deque)
_rate_lock = threading.Lock()


def rate_ok(oid: str, n: int) -> bool:
    now = time.time()
    with _rate_lock:
        q = _rate[oid]
        while q and q[0] < now - 3600:
            q.popleft()
        if len(q) + n > RATE_PER_HOUR:
            return False
        q.extend([now] * n)
        return True


def clean_items(raw) -> list[dict]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_ITEMS:
        raise ValueError(f"select between 1 and {MAX_ITEMS} emails")
    out = []
    for it in raw:
        iid = str((it or {}).get("id", ""))
        mbx = (it or {}).get("mailbox") or None
        if not ITEM_RE.match(iid):
            raise ValueError("bad message id")
        if mbx is not None and not MAILBOX_RE.match(str(mbx)):
            raise ValueError("bad mailbox")
        out.append({"id": iid, "mailbox": mbx})
    return out


def graph_message(gtok: str, item: dict) -> tuple[str, dict]:
    """Find the message with the ANALYST's permissions: the mailbox Outlook reported, else their own mailbox, else
    the lab's known shared mailboxes. Exchange decides; a mailbox they can't read simply isn't found."""
    h = {"Authorization": f"Bearer {gtok}"}
    tries = [item["mailbox"]] if item["mailbox"] else [None, *LAB_MAILBOXES]
    mid = urllib.parse.quote(item["id"].replace("/", "-").replace("+", "_"), safe="")
    for mbx in tries:
        base = f"{GRAPH}/users/{urllib.parse.quote(mbx)}" if mbx else f"{GRAPH}/me"
        r = requests.get(f"{base}/messages/{mid}", headers=h, timeout=30,
                         params={"$select": "subject,from,receivedDateTime,hasAttachments,internetMessageId"})
        if r.status_code == 200:
            return f"{base}/messages/{mid}", {**r.json(), "_mailbox": mbx or "own mailbox"}
        if r.status_code not in (400, 403, 404):
            r.raise_for_status()
    raise PermissionError("message not found, or you don't have access to that mailbox")


def fetch_mime(gtok: str, url: str) -> bytes:
    """Raw MIME, streamed with a size cap. Bytes only: nothing here parses or opens the email."""
    with requests.get(f"{url}/$value", headers={"Authorization": f"Bearer {gtok}"}, stream=True, timeout=120) as r:
        r.raise_for_status()
        buf = bytearray()
        for chunk in r.iter_content(1024 * 1024):
            buf += chunk
            if len(buf) > MAX_MIME:
                raise ValueError(f"email is larger than {MAX_MIME // 1048576} MB")
        return bytes(buf)


def new_case_id() -> str:
    return f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{secrets.token_hex(3)}"


def create_cases(gtok: str, user: dict, items: list[dict], via: str) -> list[dict]:
    out = []
    for item in items:
        mid_hash = hashlib.sha256(item["id"].encode()).hexdigest()[:16]
        try:
            url, meta = graph_message(gtok, item)
        except PermissionError as e:
            audit("case_denied", upn=user["upn"], mailbox=item["mailbox"], message=mid_hash, via=via)
            out.append({"error": str(e)})
            continue
        try:
            mime = fetch_mime(gtok, url)
        except ValueError as e:
            audit("case_rejected", upn=user["upn"], message=mid_hash, reason=str(e), via=via)
            out.append({"error": str(e)})
            continue
        case = new_case_id()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        frm = ((meta.get("from") or {}).get("emailAddress") or {})
        put_json("results", f"{case}/meta.json", {
            "schema": 1, "caseId": case, "requestedBy": user["upn"], "requestedUtc": now, "via": via,
            "mailbox": meta["_mailbox"], "subject": str(meta.get("subject") or "")[:300],
            "from": str(frm.get("address") or "")[:200], "received": meta.get("receivedDateTime"),
            "hasAttachments": bool(meta.get("hasAttachments")), "sizeBytes": len(mime),
            "sha256": hashlib.sha256(mime).hexdigest()})
        put_json("results", f"{case}/status.json", {"schema": 1, "caseId": case, "stage": "queued",
                                                     "steps": [{"stage": "queued", "note": None, "utc": now}]})
        STORE.put("cases", f"{case}/message.eml", mime, "message/rfc822")
        try:
            run = start_job(case)
        except Exception as e:
            put_json("results", f"{case}/status.json", {"schema": 1, "caseId": case, "stage": "failed", "steps": [
                {"stage": "failed", "note": "the render job could not be started", "utc": now}]})
            audit("case_job_failed", upn=user["upn"], case=case, error=type(e).__name__)
            out.append({"id": case, "url": f"{PUBLIC_URL}/case/{case}", "error": "render job could not start"})
            continue
        audit("case_created", upn=user["upn"], oid=user["oid"], case=case, mailbox=meta["_mailbox"],
              message=mid_hash, bytes=len(mime), run=run, via=via)
        out.append({"id": case, "url": f"{PUBLIC_URL}/case/{case}"})
    return out


def landing_url(cases: list[dict]) -> str:
    ids = [c["id"] for c in cases if "id" in c]
    if len(ids) == 1:
        return f"{PUBLIC_URL}/case/{ids[0]}"
    return f"{PUBLIC_URL}/?cases={','.join(ids)}" if ids else f"{PUBLIC_URL}/"


@app.post("/api/cases")
def api_create():
    try:
        user = bearer_user()
    except AuthError as e:
        audit("api_denied", reason=str(e))
        return jsonify(error=str(e)), 401
    try:
        items = clean_items((request.get_json(silent=True) or {}).get("items"))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    if not rate_ok(user["oid"], len(items)):
        return jsonify(error="too many previews this hour"), 429
    res = cca().acquire_token_on_behalf_of(user["token"], GRAPH_SCOPES)
    if "access_token" not in res:
        audit("obo_failed", upn=user["upn"], error=res.get("error"))
        return jsonify(error="could not get mailbox access on your behalf", detail=res.get("error")), 403
    cases = create_cases(res["access_token"], user, items, via="addin")
    code = 201 if any("id" in c for c in cases) else 403
    return jsonify(cases=cases, open=landing_url(cases)), code


@app.get("/start")
def start():
    """Fallback when the add-in can't sign in by itself: the browser signs in (same rules) and creates the cases."""
    try:
        items = clean_items(json.loads(base64.urlsafe_b64decode(request.args.get("items", "") + "==")))
    except Exception:
        abort(400)
    session["pending"] = items
    flow = cca().initiate_auth_code_flow(GRAPH_SCOPES, redirect_uri=f"{PUBLIC_URL}/auth/callback")
    session["flow"], session["next"] = flow, "/"
    return redirect(flow["auth_uri"])


def finish_start(gtok: str, user: dict, items: list[dict]):
    if not rate_ok(user["oid"], len(items)):
        abort(429)
    return redirect(landing_url(create_cases(gtok, user, items, via="browser")))


def read_result(case: str, name: str) -> bytes | None:
    if not CASE_RE.match(case) or not RESULT_FILE_RE.match(name):
        abort(404)
    return STORE.get("results", f"{case}/{name}")


@app.get("/api/cases/<case>/status")
def api_status(case):
    if not session_user():
        try:
            bearer_user()
        except AuthError:
            return jsonify(error="sign in"), 401
    raw = read_result(case, "status.json")
    if raw is None:
        return jsonify(error="no such case"), 404
    st = json.loads(raw)
    meta = json.loads(read_result(case, "meta.json") or b"{}")
    return jsonify(status=st, subject=meta.get("subject"), mailbox=meta.get("mailbox"))


@app.get("/case/<case>")
@login_required
def case_page(case):
    if not CASE_RE.match(case):
        abort(404)
    return redirect(f"/v/?case={case}")


@app.get("/v/")
@login_required
def viewer_index():
    return send_from_directory(VIEWER_DIR, "index.html")


@app.get("/v/<path:name>")
@login_required
def viewer_files(name):
    m = re.match(r"^cases/([^/]+)/(.+)$", name)
    if not m:
        if name not in ("app.js", "style.css"):
            abort(404)
        return send_from_directory(VIEWER_DIR, name)
    case, rel = m.groups()
    data = read_result(case, rel)
    if data is None:
        abort(404)
    if rel == "report.json":
        audit("case_viewed", upn=session_user()["upn"], case=case)
    return Response(data, mimetype="image/png" if rel.endswith(".png") else "application/json",
                    headers={"Cache-Control": "private, max-age=300" if rel.endswith(".png") else "no-store"})


HOME = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Safe Attachment Previewer</title><link rel="stylesheet" href="/static/portal.css"></head><body>
<header><h1>Safe Attachment Previewer</h1><span class="who">{{ user.name or user.upn }} · <a href="/logout">Sign out</a></span></header>
<main>
{% if only %}<p class="hint">Showing the {{ rows|length }} email(s) you just sent. <a href="/">All recent cases</a></p>{% endif %}
<p class="hint">Select emails in Outlook and choose <b>Preview safely</b>. Previews are deleted automatically after {{ days }} days.</p>
<table><thead><tr><th>Status</th><th>Subject</th><th>From</th><th>Requested</th><th>By</th></tr></thead><tbody>
{% for r in rows %}<tr data-case="{{ r.caseId }}"><td class="st">{{ r.stage }}</td>
<td><a href="/case/{{ r.caseId }}">{{ r.subject or "(no subject)" }}</a></td><td>{{ r.from }}</td>
<td>{{ r.requestedUtc }}</td><td>{{ r.requestedBy }}</td></tr>
{% else %}<tr><td colspan="5">No cases yet.</td></tr>{% endfor %}
</tbody></table></main><script src="/static/portal.js"></script></body></html>"""


@app.get("/")
@login_required
def home():
    only = [c for c in request.args.get("cases", "").split(",") if CASE_RE.match(c)]
    ids = only or sorted({n.split("/")[0] for n in STORE.names("results", "/meta.json")}, reverse=True)[:50]
    rows = []
    for c in ids:
        meta = json.loads(read_result(c, "meta.json") or b"{}")
        st = json.loads(read_result(c, "status.json") or b"{}")
        if meta:
            rows.append({**meta, "stage": st.get("stage", "?")})
    return render_template_string(HOME, rows=rows, user=session_user(), only=bool(only),
                                  days=os.environ.get("RETENTION_DAYS", "7"))


# ---------------------------------------------------------------- add-in
@app.get("/addin/manifest.xml")
def manifest():
    xml = (ADDIN_DIR / "manifest.template.xml").read_text()
    for k, v in {"{{ADDIN_ID}}": os.environ.get("ADDIN_ID", str(uuid.uuid5(uuid.NAMESPACE_URL, PUBLIC_URL))),
                 "{{PUBLIC_URL}}": PUBLIC_URL, "{{PUBLIC_HOST}}": urllib.parse.urlparse(PUBLIC_URL).netloc}.items():
        xml = xml.replace(k, v)
    return Response(xml, mimetype="application/xml")


@app.get("/addin/config.json")
def addin_config():
    return jsonify(clientId=CLIENT_ID, tenantId=TENANT, apiScope=API_SCOPE, portal=PUBLIC_URL, maxItems=MAX_ITEMS)


@app.get("/addin/<path:name>")
def addin_files(name):
    if not re.fullmatch(r"(taskpane\.(html|js|css)|msal-browser\.min\.js|icon-(16|32|64|80|128)\.png)", name):
        abort(404)
    return send_from_directory(ADDIN_DIR, name)


@app.get("/healthz")
def healthz():
    return "ok"


OFFICE_FRAMES = ("https://outlook.office.com https://outlook.office365.com https://outlook.cloud.microsoft "
                 "https://*.outlook.com https://*.office.com https://*.office365.com https://*.officeapps.live.com")


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if PUBLIC_URL.startswith("https://"):
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.path.startswith("/addin/"):
        # Runs inside Outlook (a webview, or an iframe in Outlook on the web). Office.js comes from Microsoft's CDN.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://appsforoffice.microsoft.com; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self' https://login.microsoftonline.com; object-src 'none'; "
            f"base-uri 'none'; frame-ancestors {OFFICE_FRAMES}")
    else:
        # Viewer/portal: report content is attacker-influenced, so nothing inline and nothing from elsewhere.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; object-src 'none'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        resp.headers["X-Frame-Options"] = "DENY"
    return resp


app.add_url_rule("/static/<path:name>", "static_files",
                 lambda name: send_from_directory(HERE / "static", name) if re.fullmatch(r"portal\.(css|js)", name)
                 else abort(404))
