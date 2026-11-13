# hal-id: #HAL-20261111-0004-PK-T4
"""Fetcher end to end with the local folder store: download, lock proof, locked render, output check, upload."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from saferender import fetcher

SAMPLES = Path(os.environ.get("SAMPLES", "/samples"))


def run_fetcher(store: Path, case: str, **extra_env) -> subprocess.CompletedProcess:
    env = {**os.environ, "SAFERENDER_STORE": f"dir:{store}", **extra_env}
    args = ["--case", case] if case else []
    return subprocess.run([sys.executable, "-m", "saferender.fetcher", *args], env=env,
                          capture_output=True, text=True, timeout=600)


def test_fetcher_end_to_end(tmp_path):
    src = SAMPLES / "fwd-account-alert.eml"
    if not src.exists():
        pytest.skip("samples not built")
    (tmp_path / "cases" / "c1").mkdir(parents=True)
    shutil.copy(src, tmp_path / "cases" / "c1" / "fwd-account-alert.eml")
    r = run_fetcher(tmp_path, "c1")
    assert r.returncode == 0, r.stdout + r.stderr[-2000:]
    res = tmp_path / "results" / "c1"
    att = json.loads((res / "attestation.json").read_text())
    rep = json.loads((res / "report.json").read_text())
    assert att["networkLock"]["verified"] is True
    assert att["renderer"]["exit"] == 0
    assert att["inputs"][0]["sha256"] == fetcher.sha256(src)
    assert att["outputsDropped"] == []
    assert rep["isolation"] == {"internetReached": False, "dnsResolved": False}
    assert rep["verdict"] == "SUSPICIOUS"
    # Only report + PNGs ever leave. Never the original.
    leaving = {p.relative_to(res).as_posix() for p in res.rglob("*") if p.is_file()}
    assert all(x in ("report.json", "attestation.json", "status.json") or x.endswith(".png") for x in leaving), leaving
    # Live status: ends "done", passed through the lock check, and saw the renderer's page progress.
    st = json.loads((res / "status.json").read_text())
    assert st["stage"] == "done"
    assert [x["stage"] for x in st["steps"]][:3] == ["fetching", "locked", "rendering"]
    assert st["filesSeen"] >= 1 and st["page"]


def test_output_check_drops_unexpected_files(tmp_path):
    out = tmp_path / "out"
    (out / "pages").mkdir(parents=True)
    (out / "report.json").write_text("{}")
    (out / "pages" / "f1-p001.png").write_bytes(fetcher.PNG_SIG + b"x")
    (out / "pages" / "f1-p002.png").write_bytes(b"MZ not a png")          # wrong signature
    (out / "payload.exe").write_bytes(b"MZ")                               # not an allowed name
    (out / "pages" / "f1-p003.png").symlink_to("/etc/passwd")              # symlink trick
    keep, dropped = fetcher.check_output(out)
    assert sorted(p.name for p in keep) == ["f1-p001.png", "report.json"]
    assert set(dropped) == {"pages/f1-p002.png", "payload.exe", "pages/f1-p003.png"}


def test_bad_case_id_rejected(tmp_path):
    r = run_fetcher(tmp_path, "../../etc")
    assert r.returncode != 0 and "invalid case id" in r.stderr


def test_simple_mode_and_case_id_from_env(tmp_path):
    """The portal starts runs with CASE_ID set. Simple mode reaches the locked renderer (allowlisted setting) and
    switches heuristic findings off; the original still never leaves."""
    src = SAMPLES / "fwd-account-alert.eml"
    if not src.exists():
        pytest.skip("samples not built")
    (tmp_path / "cases" / "c2").mkdir(parents=True)
    shutil.copy(src, tmp_path / "cases" / "c2" / "message.eml")
    r = run_fetcher(tmp_path, "", CASE_ID="c2", SAFERENDER_SIMPLE="1")
    assert r.returncode == 0, r.stdout + r.stderr[-2000:]
    rep = json.loads((tmp_path / "results" / "c2" / "report.json").read_text())
    assert rep["mode"] == "simple"
    assert all(f["flags"] == [] for f in rep["files"])
    assert rep["summary"]["links"] > 0          # links are still extracted
    assert rep["verdict"] in ("NO AV DETECTIONS", "SUSPICIOUS")
