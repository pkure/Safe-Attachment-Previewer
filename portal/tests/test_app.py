# hal-id: #HAL-20261113-0017-PK-T5
"""Portal tests: token rules, access decisions, case creation, file serving and headers. Offline: Entra, Graph and
Azure are stood in for, the store is a local folder and the render job is "local"."""

import base64
import json
import os
import sys
import time
import xml.dom.minidom
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture()
def mod(tmp_path, monkeypatch):
    monkeypatch.setenv("TENANT_ID", TENANT)
    monkeypatch.setenv("CLIENT_ID", CLIENT)
    monkeypatch.setenv("PUBLIC_URL", "https://sap.example.test")
    monkeypatch.setenv("STORE", f"dir:{tmp_path}")
    monkeypatch.setenv("JOB_ID", "local")
    monkeypatch.setenv("LAB_MAILBOXES", "secops-triage@example.test")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    sys.modules.pop("app", None)
    import app as m
    m.app.config["TESTING"] = True
    yield m
    sys.path.pop(0)


KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(**over):
    now = int(time.time())
    claims = {"aud": CLIENT, "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "tid": TENANT,
              "oid": "oid-analyst1", "preferred_username": "analyst1@example.test", "name": "Analyst One",
              "scp": "access_as_user", "roles": ["Previewer.Use"], "iat": now, "nbf": now, "exp": now + 600}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "k1"})


class FakeJwks:
    def get_signing_key_from_jwt(self, _):
        return type("K", (), {"key": KEY.public_key()})()


class FakeCca:
    def __init__(self, ok=True):
        self.ok = ok

    def acquire_token_on_behalf_of(self, assertion, scopes):
        return {"access_token": "graph-token"} if self.ok else {"error": "consent_required"}


@pytest.fixture()
def api(mod, monkeypatch):
    monkeypatch.setattr(mod, "jwks", lambda: FakeJwks())
    monkeypatch.setattr(mod, "cca", lambda: FakeCca())
    return mod


REST_ID = "AAMkAGI2THVSAAA=" + "x" * 40


# ---------------------------------------------------------------- token rules
def test_valid_token_accepted(api):
    assert api.validate_bearer(token())["oid"] == "oid-analyst1"


@pytest.mark.parametrize("over,why", [
    ({"roles": None}, "not assigned"),                     # signed in, but not assigned to the app
    ({"scp": "User.Read"}, "missing scope"),
    ({"aud": "api://someone-else"}, "invalid token"),
    ({"tid": "99999999-0000-0000-0000-000000000000"}, "wrong tenant"),
    ({"exp": int(time.time()) - 60}, "invalid token"),
    ({"iss": "https://login.microsoftonline.com/common/v2.0"}, "invalid token"),
])
def test_bad_tokens_refused(api, over, why):
    with pytest.raises(api.AuthError, match=why):
        api.validate_bearer(token(**over))


def test_api_requires_token(api):
    r = api.app.test_client().post("/api/cases", json={"items": [{"id": REST_ID}]})
    assert r.status_code == 401


# ---------------------------------------------------------------- case creation
def stub_graph(api, monkeypatch, allowed=("secops-triage@example.test",)):
    seen = []

    def graph_message(gtok, item):
        assert gtok == "graph-token"  # the ANALYST's delegated token, never an app-wide one
        seen.append(item)
        if item["mailbox"] and item["mailbox"] not in allowed:
            raise PermissionError("message not found, or you don't have access to that mailbox")
        return "https://graph/msg", {"subject": "Invoice <script>", "from": {"emailAddress": {"address": "a@b.test"}},
                                     "receivedDateTime": "2026-11-13T10:00:00Z", "hasAttachments": True,
                                     "_mailbox": item["mailbox"] or "secops-triage@example.test"}
    monkeypatch.setattr(api, "graph_message", graph_message)
    monkeypatch.setattr(api, "fetch_mime", lambda gtok, url: b"From: a@b.test\r\nSubject: hi\r\n\r\nbody")
    return seen


def test_case_created_end_to_end(api, monkeypatch, tmp_path, capsys):
    stub_graph(api, monkeypatch)
    r = api.app.test_client().post("/api/cases", headers={"Authorization": f"Bearer {token()}"},
                                   json={"items": [{"id": REST_ID, "mailbox": "secops-triage@example.test"}]})
    assert r.status_code == 201, r.get_json()
    case = r.get_json()["cases"][0]["id"]
    assert api.CASE_RE.match(case)
    assert r.get_json()["open"] == f"https://sap.example.test/case/{case}"
    assert (tmp_path / "cases" / case / "message.eml").read_bytes().startswith(b"From:")
    meta = json.loads((tmp_path / "results" / case / "meta.json").read_text())
    assert meta["requestedBy"] == "analyst1@example.test" and meta["via"] == "addin"
    assert json.loads((tmp_path / "results" / case / "status.json").read_text())["stage"] == "queued"
    log = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
    assert any(e.get("audit") == "case_created" and e["case"] == case for e in log)


def test_mailbox_without_access_is_denied(api, monkeypatch, capsys):
    stub_graph(api, monkeypatch)
    r = api.app.test_client().post("/api/cases", headers={"Authorization": f"Bearer {token()}"},
                                   json={"items": [{"id": REST_ID, "mailbox": "ceo@example.test"}]})
    assert r.status_code == 403
    assert "access" in r.get_json()["cases"][0]["error"]
    assert '"audit": "case_denied"' in capsys.readouterr().out


def test_obo_failure_is_refused(api, monkeypatch):
    monkeypatch.setattr(api, "cca", lambda: FakeCca(ok=False))
    r = api.app.test_client().post("/api/cases", headers={"Authorization": f"Bearer {token()}"},
                                   json={"items": [{"id": REST_ID}]})
    assert r.status_code == 403


@pytest.mark.parametrize("items", [
    [], [{"id": REST_ID}] * 11, [{"id": "short"}], [{"id": REST_ID, "mailbox": "not an email"}],
    [{"id": "../../etc/passwd" + "a" * 30}], "not a list",
])
def test_bad_requests_rejected(api, items):
    r = api.app.test_client().post("/api/cases", headers={"Authorization": f"Bearer {token()}"}, json={"items": items})
    assert r.status_code == 400


def test_graph_lookup_order_uses_only_the_analysts_access(mod, monkeypatch):
    calls = []

    class R:
        def __init__(self, code):
            self.status_code = code

        def json(self):
            return {"subject": "s"}

    def fake_get(url, headers, timeout, params):
        calls.append(url)
        assert headers["Authorization"] == "Bearer analyst-token"
        return R(200 if "/users/secops-triage" in url else 404)
    monkeypatch.setattr(mod.requests, "get", fake_get)
    url, meta = mod.graph_message("analyst-token", {"id": REST_ID, "mailbox": None})
    assert [c.split("/messages/")[0].rsplit("/", 1)[-1] for c in calls] == ["me", "secops-triage%40example.test"]
    assert meta["_mailbox"] == "secops-triage@example.test"


def test_rate_limit(api, monkeypatch):
    monkeypatch.setattr(api, "RATE_PER_HOUR", 2)
    stub_graph(api, monkeypatch)
    c = api.app.test_client()
    h = {"Authorization": f"Bearer {token()}"}
    assert c.post("/api/cases", headers=h, json={"items": [{"id": REST_ID}, {"id": REST_ID}]}).status_code == 201
    assert c.post("/api/cases", headers=h, json={"items": [{"id": REST_ID}]}).status_code == 429


# ---------------------------------------------------------------- viewer + pages
def login(client):
    with client.session_transaction() as s:
        s["user"] = {"oid": "o", "upn": "analyst1@example.test", "name": "A", "exp": time.time() + 600}


def test_viewer_needs_sign_in(mod):
    r = mod.app.test_client().get("/v/?case=20261113-101010-abcdef")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_viewer_serves_only_expected_result_files(mod, tmp_path):
    case = "20261113-101010-abcdef"
    (tmp_path / "results" / case / "pages").mkdir(parents=True)
    (tmp_path / "results" / case / "report.json").write_text("{}")
    (tmp_path / "results" / case / "pages" / "f1-p001.png").write_bytes(b"\x89PNG\r\n\x1a\nx")
    (tmp_path / "cases" / case).mkdir(parents=True)
    (tmp_path / "cases" / case / "message.eml").write_text("the original")
    c = mod.app.test_client()
    login(c)
    assert c.get(f"/v/cases/{case}/report.json").status_code == 200
    assert c.get(f"/v/cases/{case}/pages/f1-p001.png").mimetype == "image/png"
    for bad in [f"/v/cases/{case}/../../cases/{case}/message.eml", f"/v/cases/{case}/message.eml",
                "/v/cases/../x/report.json", f"/v/cases/{case}/pages/evil.svg", "/v/app.py"]:
        assert c.get(bad).status_code == 404, bad


def test_case_list_escapes_subjects(mod, tmp_path):
    case = "20261113-101010-abcdef"
    (tmp_path / "results" / case).mkdir(parents=True)
    (tmp_path / "results" / case / "meta.json").write_text(json.dumps(
        {"caseId": case, "subject": "<img src=x onerror=alert(1)>", "from": "a@b", "requestedUtc": "t",
         "requestedBy": "u"}))
    (tmp_path / "results" / case / "status.json").write_text('{"stage": "done"}')
    c = mod.app.test_client()
    login(c)
    html = c.get("/").get_data(as_text=True)
    assert "<img src=x" not in html and "&lt;img src=x" in html


def test_security_headers(mod):
    c = mod.app.test_client()
    v = c.get("/healthz").headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in v and "script-src 'self';" in v
    a = c.get("/addin/taskpane.html").headers["Content-Security-Policy"]
    assert "https://outlook.office.com" in a and "appsforoffice.microsoft.com" in a


def test_manifest_is_valid_and_points_at_portal(mod):
    r = mod.app.test_client().get("/addin/manifest.xml")
    body = r.get_data(as_text=True)
    xml.dom.minidom.parseString(body)
    assert "{{" not in body and "https://sap.example.test/addin/taskpane.html" in body
    assert "<SupportsSharedFolders>true</SupportsSharedFolders>" in body
    assert "<SupportsMultiSelect>true</SupportsMultiSelect>" in body


def test_addin_static_is_allowlisted(mod):
    c = mod.app.test_client()
    assert c.get("/addin/taskpane.js").status_code == 200
    assert c.get("/addin/manifest.template.xml").status_code == 404
    assert c.get("/addin/../app.py").status_code == 404


def test_browser_fallback_rejects_bad_items(mod, monkeypatch):
    c = mod.app.test_client()
    bad = base64.urlsafe_b64encode(json.dumps([{"id": "x"}]).encode()).decode()
    assert c.get(f"/start?items={bad}").status_code == 400


def test_login_next_cannot_redirect_off_site(mod):
    assert mod.safe_next("//evil.test/x") == "/"
    assert mod.safe_next("https://evil.test") == "/"
    assert mod.safe_next("/case/1") == "/case/1"
