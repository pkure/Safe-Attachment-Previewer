# hal-id: #HAL-20261111-0002-PK-R7
"""Cloud entry point: move one case in and out, around a network-locked renderer.

  python -m saferender.fetcher --case <id>

  1. DOWNLOAD the case's attachment bytes into private scratch space. The fetcher never opens or parses them.
  2. PROVE the network lock works on this host (lockdown.verify()).
  3. RENDER: start the renderer under the lock (no sockets except local AF_UNIX), with an empty environment:
     no managed-identity endpoint, no storage name, no credentials. Even fully compromised, it has nothing to
     connect to and nothing to connect with.
  4. CHECK the output: only report.json and page/thumbnail PNGs with expected names, sizes and PNG signatures.
     Anything else is dropped and recorded.
  5. UPLOAD the checked output plus attestation.json (hashes, lock proof, timings, image version).

Throughout, it writes results/<id>/status.json (stage, current file and page) so the viewer can show live progress.
The case id comes from --case or the CASE_ID environment variable (set per run by the portal).

Storage is chosen by SAFERENDER_STORE:
  dir:/path                               local folders /path/cases/<id>/ and /path/results/<id>/ (tests, demos)
  blob:https://<acct>.blob.core.windows.net  Azure Blob via the job's managed identity (stdlib only, no SDK)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from . import lockdown
from .formats import LIMITS, safe_name

CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
OUT_NAME_RE = re.compile(r"^(report\.json|pages/f\d{1,3}-p\d{3}(\.t)?\.png)$")
PNG_SIG = b"\x89PNG\r\n\x1a\n"
MAX_OUT_FILE = 25 * 1024 * 1024
MAX_OUT_TOTAL = 400 * 1024 * 1024
RENDER_TIMEOUT_S = 900
# Settings the renderer may see. Everything else (identity endpoint, storage name, credentials) is withheld.
RENDERER_ENV_ALLOW = ("SAFERENDER_ORG_DOMAINS", "SAFERENDER_SIMPLE", "SAFERENDER_AV")
STATUS_EVERY_S = 1.0
CASES, RESULTS = os.environ.get("CASES_CONTAINER", "cases"), os.environ.get("RESULTS_CONTAINER", "results")


# ---------------------------------------------------------------- storage
class DirStore:
    def __init__(self, root: str):
        self.root = Path(root)

    def list(self, container: str, prefix: str) -> list[tuple[str, int]]:
        base = self.root / container / prefix
        return [(f"{prefix}{p.name}", p.stat().st_size) for p in sorted(base.iterdir()) if p.is_file()] \
            if base.is_dir() else []

    def get(self, container: str, name: str, dest: Path) -> None:
        shutil.copyfile(self.root / container / name, dest)

    def put(self, container: str, name: str, src: Path, ctype: str) -> None:
        dst = self.root / container / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)


class BlobStore:
    """Azure Blob REST with a managed-identity token. API calls only; no SDK, no shared keys."""
    VERSION = "2023-11-03"

    def __init__(self, endpoint: str):
        self.endpoint = endpoint.rstrip("/")
        if not re.fullmatch(r"https://[a-z0-9]{3,24}\.blob\.core\.windows\.net", self.endpoint):
            raise SystemExit("unexpected blob endpoint")
        self._token, self._exp = None, 0.0

    def _auth(self) -> str:
        if not self._token or time.time() > self._exp - 300:
            q = {"resource": "https://storage.azure.com/", "api-version": "2019-08-01"}
            if os.environ.get("AZURE_CLIENT_ID"):
                q["client_id"] = os.environ["AZURE_CLIENT_ID"]
            req = urllib.request.Request(f"{os.environ['IDENTITY_ENDPOINT']}?{urllib.parse.urlencode(q)}",
                                         headers={"X-IDENTITY-HEADER": os.environ["IDENTITY_HEADER"]})
            with urllib.request.urlopen(req, timeout=30) as r:
                tok = json.load(r)
            self._token, self._exp = tok["access_token"], float(tok.get("expires_on", time.time() + 3000))
        return self._token

    def _req(self, method: str, url: str, data=None, headers=None):
        h = {"Authorization": f"Bearer {self._auth()}", "x-ms-version": self.VERSION, **(headers or {})}
        return urllib.request.urlopen(urllib.request.Request(url, data=data, method=method, headers=h), timeout=120)

    def _url(self, container: str, name: str = "") -> str:
        return f"{self.endpoint}/{container}/{urllib.parse.quote(name)}" if name else f"{self.endpoint}/{container}"

    def list(self, container: str, prefix: str) -> list[tuple[str, int]]:
        q = urllib.parse.urlencode({"restype": "container", "comp": "list", "prefix": prefix})
        with self._req("GET", f"{self._url(container)}?{q}") as r:
            root = ET.fromstring(r.read())
        return [(b.findtext("Name"), int(b.findtext("Properties/Content-Length") or 0))
                for b in root.iter("Blob")]

    def get(self, container: str, name: str, dest: Path) -> None:
        with self._req("GET", self._url(container, name)) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f, 1024 * 1024)

    def put(self, container: str, name: str, src: Path, ctype: str) -> None:
        self._req("PUT", self._url(container, name), data=src.read_bytes(),
                  headers={"x-ms-blob-type": "BlockBlob", "Content-Type": ctype}).close()


def store_from_env():
    spec = os.environ.get("SAFERENDER_STORE", "")
    kind, _, where = spec.partition(":")
    if kind == "dir":
        return DirStore(where)
    if kind == "blob":
        return BlobStore(where)
    raise SystemExit("set SAFERENDER_STORE=dir:/path or blob:https://<account>.blob.core.windows.net")


# ---------------------------------------------------------------- steps
def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class Status:
    """results/<case>/status.json, rewritten as the case moves along (throttled). Never blocks the case on failure."""

    def __init__(self, store, case: str, work: Path):
        self.store, self.case, self.path, self.last = store, case, work / "status.json", 0.0
        self.data = {"schema": 1, "caseId": case, "stage": "starting", "steps": [], "file": None, "page": None,
                     "pages": None, "filesSeen": 0}

    def step(self, stage: str, note: str | None = None, force: bool = True, **kw) -> None:
        if stage != self.data["stage"] or note:
            self.data["steps"].append({"stage": stage, "note": note,
                                       "utc": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        self.data.update(stage=stage, **kw)
        self.flush(force)

    def flush(self, force: bool = False) -> None:
        if not force and time.monotonic() - self.last < STATUS_EVERY_S:
            return
        self.last = time.monotonic()
        self.data["updatedUtc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            self.path.write_text(json.dumps(self.data))
            self.store.put(RESULTS, f"{self.case}/status.json", self.path, "application/json")
        except Exception as e:  # status is best effort; the case itself must not fail because of it
            print(f"status write failed: {e}", file=sys.stderr)


def download(store, case: str, dest: Path) -> tuple[list[dict], list[str]]:
    inputs, notes, total = [], [], 0
    for name, size in store.list(CASES, f"{case}/"):
        base = safe_name(name[len(case) + 1:])
        if len(inputs) >= LIMITS["max_files"] or total + size > LIMITS["max_total_bytes"]:
            notes.append(f"input limit reached; skipped {base}")
            continue
        p = dest / base
        store.get(CASES, name, p)
        total += p.stat().st_size
        inputs.append({"name": name[len(case) + 1:], "stored": base, "size": p.stat().st_size, "sha256": sha256(p)})
    return inputs, notes


def render(case: str, inp: Path, out: Path, status: Status | None = None) -> dict:
    """The renderer gets: the input folder, an output folder, a few non-secret settings, and NOTHING else.
    No credentials in its environment. Its "@@progress" stdout lines become live status."""
    env = {"PATH": "/opt/venv/bin:/usr/bin:/bin", "HOME": str(out.parent), "TMPDIR": str(out.parent / "tmp"),
           "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
           **{k: os.environ[k] for k in RENDERER_ENV_ALLOW if k in os.environ}}
    Path(env["TMPDIR"]).mkdir(exist_ok=True)
    t0 = time.monotonic()
    tail: list[str] = []
    p = subprocess.Popen([sys.executable, "-m", "saferender.pipeline", "--in", str(inp), "--out", str(out),
                          "--case", case], env=env, preexec_fn=lockdown.apply, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, errors="replace",
                         cwd="/app" if Path("/app").is_dir() else None)
    killer = threading.Timer(RENDER_TIMEOUT_S, p.kill)
    killer.start()
    try:
        for line in p.stdout:
            if line.startswith("@@progress ") and status:
                try:
                    ev = json.loads(line[11:])
                except ValueError:
                    continue
                if not isinstance(ev, dict):
                    continue
                if ev.get("stage") == "file":
                    status.data["filesSeen"] = int(ev.get("n") or 0)
                    status.data.update(file=str(ev.get("file", ""))[:120], page=None, pages=None)
                elif ev.get("stage") == "render":
                    status.data.update(file=str(ev.get("file", ""))[:120], page=ev.get("page"), pages=ev.get("pages"))
                elif ev.get("stage") == "scan":
                    status.step("scanning", force=False)
                status.flush()
            else:
                tail.append(line)
                del tail[:-40]
        code = p.wait()
    finally:
        killer.cancel()
    if code == -9 and time.monotonic() - t0 >= RENDER_TIMEOUT_S:
        code = "timeout"
    return {"exit": code, "seconds": round(time.monotonic() - t0, 2), "log": "".join(tail)[-1500:]}


def check_output(out: Path) -> tuple[list[Path], list[str]]:
    keep, dropped, total = [], [], 0
    for p in sorted(x for x in out.rglob("*") if x.is_file() or x.is_symlink()):
        rel = p.relative_to(out).as_posix()
        size = p.lstat().st_size
        ok = not p.is_symlink() and OUT_NAME_RE.match(rel) and size <= MAX_OUT_FILE and total + size <= MAX_OUT_TOTAL
        if ok and rel.endswith(".png"):
            with open(p, "rb") as f:
                ok = f.read(8) == PNG_SIG
        if ok and rel == "report.json":
            try:
                ok = isinstance(json.loads(p.read_text()), dict)
            except (ValueError, UnicodeDecodeError):
                ok = False
        if ok:
            keep.append(p)
            total += size
        else:
            dropped.append(rel[:200])
    return keep, dropped


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default=os.environ.get("CASE_ID", ""))
    a = ap.parse_args()
    if not CASE_RE.match(a.case):
        raise SystemExit("invalid case id")
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    store = store_from_env()
    work = Path(tempfile.mkdtemp(prefix="case-"))
    inp, out = work / "in", work / "out"
    inp.mkdir()
    out.mkdir()
    status = Status(store, a.case, work)
    status.step("fetching")
    inputs, notes = download(store, a.case, inp)
    lock = lockdown.verify()
    if not lock["verified"]:
        # Fail closed: never render on a host where the network lock can't be proven.
        rendered = {"exit": "not run: network lock not verified", "seconds": 0, "log": ""}
        status.step("failed", "network lock could not be verified, so nothing was opened")
    else:
        status.step("locked", f"network lock verified; {len(inputs)} file(s) received")
        status.step("rendering")
        rendered = render(a.case, inp, out, status)
    status.step("checking")
    keep, dropped = check_output(out)
    att = {"schema": 1, "caseId": a.case, "startedUtc": started,
           "finishedUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "image": os.environ.get("IMAGE_TAG", "local"), "networkLock": lock, "renderer": rendered,
           "inputs": inputs, "notes": notes, "outputsKept": len(keep), "outputsDropped": dropped}
    (work / "attestation.json").write_text(json.dumps(att, indent=1))
    for p in keep:
        rel = p.relative_to(out).as_posix()
        store.put(RESULTS, f"{a.case}/{rel}", p, "image/png" if rel.endswith(".png") else "application/json")
    store.put(RESULTS, f"{a.case}/attestation.json", work / "attestation.json", "application/json")
    ok = lock["verified"] and rendered["exit"] == 0
    if ok:
        status.step("done")
    elif status.data["stage"] != "failed":
        status.step("failed", "the preview could not be completed; escalate manually per your process")
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({"case": a.case, "lockVerified": lock["verified"], "renderExit": rendered["exit"],
                      "kept": len(keep), "dropped": len(dropped), "renderSeconds": rendered["seconds"]}))
    if not lock["verified"] or rendered["exit"] != 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
